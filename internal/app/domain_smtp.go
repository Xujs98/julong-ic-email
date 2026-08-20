package app

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	domainSMTPReadTimeout  = 2 * time.Minute
	domainSMTPWriteTimeout = 30 * time.Second
)

// DomainSMTPService accepts inbound mail for managed domain mailboxes. It is
// intentionally receive-only: domain mailbox records are the recipient allow
// list, and every accepted message is persisted in the existing mailbox store.
type DomainSMTPService struct {
	listener  net.Listener
	store     *FileStore
	logger    *slog.Logger
	maxBytes  int64
	tlsConfig *tls.Config
	done      chan struct{}
	once      sync.Once
}

func StartDomainSMTP(cfg Config, store *FileStore, logger *slog.Logger) (*DomainSMTPService, error) {
	if store == nil {
		return nil, fmt.Errorf("domain SMTP requires a file store")
	}
	host := strings.TrimSpace(cfg.DomainSMTPHost)
	if host == "" {
		host = "0.0.0.0"
	}
	port := cfg.DomainSMTPPort
	if port < 0 {
		port = 2525
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	maxBytes := cfg.DomainSMTPMaxMessageBytes
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	var tlsConfig *tls.Config
	certFile := strings.TrimSpace(cfg.DomainSMTPCertFile)
	keyFile := strings.TrimSpace(cfg.DomainSMTPKeyFile)
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			_ = listener.Close()
			return nil, fmt.Errorf("domain SMTP TLS requires both certificate and key files")
		}
		if _, err := os.Stat(certFile); err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("domain SMTP certificate: %w", err)
		}
		if _, err := os.Stat(keyFile); err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("domain SMTP key: %w", err)
		}
		certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			_ = listener.Close()
			return nil, fmt.Errorf("load domain SMTP TLS certificate: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	}
	service := &DomainSMTPService{listener: listener, store: store, logger: logger, maxBytes: maxBytes, tlsConfig: tlsConfig, done: make(chan struct{})}
	go service.serve()
	if logger != nil {
		logger.Info("domain SMTP started", "addr", listener.Addr().String(), "max_message_bytes", maxBytes, "starttls", tlsConfig != nil)
	}
	return service, nil
}

func (s *DomainSMTPService) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *DomainSMTPService) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.once.Do(func() {
		close(s.done)
		if s.listener != nil {
			err = s.listener.Close()
		}
	})
	return err
}

func (s *DomainSMTPService) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				if s.logger != nil {
					s.logger.Warn("domain SMTP accept failed", "err", err)
				}
				continue
			}
		}
		go s.handleConn(conn)
	}
}

func (s *DomainSMTPService) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(domainSMTPReadTimeout))
	reader := bufio.NewReaderSize(conn, 64*1024)
	writer := bufio.NewWriterSize(conn, 8*1024)
	defer func() { _ = writer.Flush() }()
	writeSMTPReply(writer, 220, "julong-mail ESMTP domain receiver ready")

	var sender string
	mailFromSet := false
	var recipients []Mailbox
	tlsActive := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		_ = conn.SetDeadline(time.Now().Add(domainSMTPReadTimeout))
		line = strings.TrimRight(line, "\r\n")
		command, argument := smtpCommand(line)
		switch command {
		case "EHLO", "HELO":
			capabilities := []string{"julong-mail", "SIZE " + fmt.Sprintf("%d", s.maxBytes), "8BITMIME"}
			if s.tlsConfig != nil && !tlsActive {
				capabilities = append(capabilities, "STARTTLS")
			}
			writeSMTPMultiline(writer, 250, capabilities)
		case "STARTTLS":
			if s.tlsConfig == nil || tlsActive {
				writeSMTPReply(writer, 502, "command not supported")
				continue
			}
			writeSMTPReply(writer, 220, "ready to start TLS")
			tlsConn := tls.Server(conn, s.tlsConfig.Clone())
			if err := tlsConn.Handshake(); err != nil {
				if s.logger != nil {
					s.logger.Warn("domain SMTP TLS handshake failed", "err", err)
				}
				return
			}
			conn = tlsConn
			_ = conn.SetDeadline(time.Now().Add(domainSMTPReadTimeout))
			reader = bufio.NewReaderSize(conn, 64*1024)
			writer = bufio.NewWriterSize(conn, 8*1024)
			tlsActive = true
			sender = ""
			mailFromSet = false
			recipients = nil
		case "NOOP":
			writeSMTPReply(writer, 250, "OK")
		case "RSET":
			sender = ""
			mailFromSet = false
			recipients = nil
			writeSMTPReply(writer, 250, "reset")
		case "QUIT":
			writeSMTPReply(writer, 221, "bye")
			return
		case "VRFY", "EXPN":
			writeSMTPReply(writer, 252, "cannot verify user")
		case "AUTH":
			writeSMTPReply(writer, 502, "command not supported")
		case "MAIL":
			address, ok := smtpPathArgument(argument, "FROM:")
			if !ok {
				writeSMTPReply(writer, 501, "MAIL FROM syntax error")
				continue
			}
			sender = address
			mailFromSet = true
			recipients = nil
			writeSMTPReply(writer, 250, "sender accepted")
		case "RCPT":
			if !mailFromSet {
				writeSMTPReply(writer, 503, "send MAIL FROM first")
				continue
			}
			address, ok := smtpPathArgument(argument, "TO:")
			if !ok {
				writeSMTPReply(writer, 501, "RCPT TO syntax error")
				continue
			}
			mailbox, code, message := s.acceptRecipient(address)
			if code != 0 {
				writeSMTPReply(writer, code, message)
				continue
			}
			duplicate := false
			for _, recipient := range recipients {
				if recipient.ID == mailbox.ID {
					duplicate = true
					break
				}
			}
			if !duplicate {
				recipients = append(recipients, mailbox)
			}
			writeSMTPReply(writer, 250, "recipient accepted")
		case "DATA":
			if len(recipients) == 0 {
				writeSMTPReply(writer, 503, "send RCPT TO first")
				continue
			}
			writeSMTPReply(writer, 354, "end data with <CR><LF>.<CR><LF>")
			raw, tooLarge, err := readSMTPData(reader, s.maxBytes)
			if err != nil {
				return
			}
			if tooLarge {
				writeSMTPReply(writer, 552, "message exceeds configured size")
				sender = ""
				mailFromSet = false
				recipients = nil
				continue
			}
			if err := s.storeMessage(raw, sender, recipients); err != nil {
				if s.logger != nil {
					s.logger.Warn("domain SMTP store failed", "sender", sender, "err", err)
				}
				writeSMTPReply(writer, 451, "temporary local processing failure")
			} else {
				writeSMTPReply(writer, 250, "message accepted")
			}
			sender = ""
			mailFromSet = false
			recipients = nil
		default:
			writeSMTPReply(writer, 500, "command unrecognized")
		}
	}
}

func smtpCommand(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	parts := strings.SplitN(line, " ", 2)
	command := strings.ToUpper(strings.TrimSpace(parts[0]))
	argument := ""
	if len(parts) == 2 {
		argument = strings.TrimSpace(parts[1])
	}
	return command, argument
}

func smtpPathArgument(argument, prefix string) (string, bool) {
	if !strings.HasPrefix(strings.ToUpper(argument), prefix) {
		return "", false
	}
	value := strings.TrimSpace(argument[len(prefix):])
	if value == "<>" {
		return "", strings.EqualFold(prefix, "FROM:")
	}
	if !strings.HasPrefix(value, "<") || !strings.Contains(value, ">") {
		return "", false
	}
	value = value[1:strings.Index(value, ">")]
	address, err := mail.ParseAddress(value)
	if err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(address.Address)), true
}

func writeSMTPReply(writer *bufio.Writer, code int, message string) {
	_, _ = fmt.Fprintf(writer, "%d %s\r\n", code, message)
	_ = writer.Flush()
}

func writeSMTPMultiline(writer *bufio.Writer, code int, lines []string) {
	for i, line := range lines {
		separator := "-"
		if i == len(lines)-1 {
			separator = " "
		}
		_, _ = fmt.Fprintf(writer, "%d%s%s\r\n", code, separator, line)
	}
	_ = writer.Flush()
}

func readSMTPData(reader *bufio.Reader, maxBytes int64) ([]byte, bool, error) {
	var data bytes.Buffer
	tooLarge := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, false, err
		}
		if line == ".\r\n" || line == ".\n" {
			return data.Bytes(), tooLarge, nil
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		if int64(data.Len()+len(line)) > maxBytes {
			tooLarge = true
			continue
		}
		if !tooLarge {
			_, _ = data.WriteString(line)
		}
	}
}

func (s *DomainSMTPService) acceptRecipient(address string) (Mailbox, int, string) {
	address = strings.ToLower(strings.TrimSpace(address))
	at := strings.LastIndex(address, "@")
	if at <= 0 || at == len(address)-1 {
		return Mailbox{}, 550, "invalid recipient"
	}
	if _, ok := s.store.FindEnabledDomainByName(address[at+1:]); !ok {
		return Mailbox{}, 550, "recipient domain is not configured"
	}
	mailbox, ok := s.store.FindMailboxByEmail(address)
	if !ok || mailbox.ProviderKind() != MailboxProviderDomain || !mailbox.APIActive || !mailbox.ICloudActive || mailbox.Status == StatusDisabled {
		return Mailbox{}, 550, "mailbox is not active"
	}
	return mailbox, 0, ""
}

func (s *DomainSMTPService) storeMessage(raw []byte, envelopeFrom string, recipients []Mailbox) error {
	parsed, err := parseDomainSMTPMessage(raw, envelopeFrom)
	if err != nil {
		return err
	}
	for _, mailbox := range recipients {
		remoteID := parsed.remoteID + ":" + strings.ToLower(mailbox.Email)
		if _, _, err := s.store.UpsertMessageContent(mailbox.ID, remoteID, "domain_smtp", parsed.subject, parsed.from, parsed.body, parsed.htmlBody, parsed.receivedAt); err != nil {
			return err
		}
	}
	return nil
}

type domainSMTPMessage struct {
	remoteID   string
	subject    string
	from       string
	body       string
	htmlBody   string
	receivedAt time.Time
}

func parseDomainSMTPMessage(raw []byte, envelopeFrom string) (domainSMTPMessage, error) {
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return domainSMTPMessage{}, err
	}
	decoder := new(mime.WordDecoder)
	decodeHeader := func(value string) string {
		decoded, err := decoder.DecodeHeader(value)
		if err != nil {
			return strings.TrimSpace(value)
		}
		return strings.TrimSpace(decoded)
	}
	subject := decodeHeader(message.Header.Get("Subject"))
	if subject == "" {
		subject = "(无主题邮件)"
	}
	from := decodeHeader(message.Header.Get("From"))
	if parsed, err := mail.ParseAddress(from); err == nil {
		from = parsed.Address
	}
	if from == "" {
		from = strings.TrimSpace(envelopeFrom)
	}
	if from == "" {
		from = "unknown"
	}
	plain, htmlBody, err := decodeSMTPBody(message.Header, message.Body)
	if err != nil {
		return domainSMTPMessage{}, err
	}
	if plain == "" && htmlBody != "" {
		plain = normalizeMailBody(htmlBody)
	}
	if plain == "" {
		plain = "邮件正文为空"
	}
	receivedAt := time.Now()
	if date, err := mail.ParseDate(message.Header.Get("Date")); err == nil {
		receivedAt = date
	}
	messageID := strings.TrimSpace(message.Header.Get("Message-ID"))
	if messageID == "" {
		digest := sha256.Sum256(raw)
		messageID = fmt.Sprintf("smtp-%x", digest[:])
	}
	return domainSMTPMessage{remoteID: messageID, subject: subject, from: from, body: plain, htmlBody: htmlBody, receivedAt: receivedAt}, nil
}

func decodeSMTPBody(header mail.Header, body io.Reader) (string, string, error) {
	contentType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		contentType = "text/plain"
	}
	if strings.HasPrefix(strings.ToLower(contentType), "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return "", "", fmt.Errorf("multipart message missing boundary")
		}
		return decodeSMTPMultipart(multipart.NewReader(body, boundary))
	}
	content, err := readSMTPContent(header, body)
	if err != nil {
		return "", "", err
	}
	if strings.EqualFold(contentType, "text/html") {
		return "", content, nil
	}
	return content, "", nil
}

func decodeSMTPMultipart(reader *multipart.Reader) (string, string, error) {
	var plain, htmlBody string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", err
		}
		contentType, params, parseErr := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if parseErr != nil {
			contentType = "text/plain"
		}
		if strings.HasPrefix(strings.ToLower(contentType), "multipart/") {
			boundary := params["boundary"]
			if boundary == "" {
				continue
			}
			childPlain, childHTML, err := decodeSMTPMultipart(multipart.NewReader(part, boundary))
			if err != nil {
				return "", "", err
			}
			if plain == "" {
				plain = childPlain
			}
			if htmlBody == "" {
				htmlBody = childHTML
			}
			continue
		}
		if !strings.HasPrefix(strings.ToLower(contentType), "text/") {
			continue
		}
		content, err := readSMTPContent(part.Header, part)
		if err != nil {
			return "", "", err
		}
		switch strings.ToLower(contentType) {
		case "text/plain":
			if plain == "" {
				plain = content
			}
		case "text/html":
			if htmlBody == "" {
				htmlBody = content
			}
		}
	}
	return plain, htmlBody, nil
}

func readSMTPContent(header interface{ Get(string) string }, body io.Reader) (string, error) {
	var reader io.Reader = body
	switch strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding"))) {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, body)
	case "quoted-printable":
		reader = quotedprintable.NewReader(body)
	}
	data, err := io.ReadAll(io.LimitReader(reader, 2*1024*1024))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
