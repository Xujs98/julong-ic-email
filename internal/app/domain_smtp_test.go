package app

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDomainSMTPStoresInboundMailAndServesCode(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomainForOwner("", "测试域名", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	mailboxes, err := store.AddDomainMailboxesForOwner("", domain.ID, "测试批次", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	mailbox := mailboxes[0]
	service, err := StartDomainSMTP(Config{DomainSMTPHost: "127.0.0.1", DomainSMTPPort: 0, DomainSMTPMaxMessageBytes: 1 << 20}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	client, err := smtp.Dial(service.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Quit()
	if err := client.Mail("sender@external.test"); err != nil {
		t.Fatal(err)
	}
	if err := client.Rcpt(mailbox.Email); err != nil {
		t.Fatal(err)
	}
	writer, err := client.Data()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(writer, "Message-ID: <smtp-domain-test@example.test>\r\nFrom: Sender <sender@external.test>\r\nSubject: Your verification code 654321\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nVerification code: 654321\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	messages := store.MessagesForMailbox(mailbox.ID)
	if len(messages) != 1 {
		t.Fatalf("stored messages = %d, want 1", len(messages))
	}
	if messages[0].Source != "domain_smtp" || !strings.Contains(messages[0].Body, "654321") {
		t.Fatalf("stored message = %#v", messages[0])
	}

	panel := httptest.NewServer(NewServer(Config{}, store, slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer panel.Close()
	requestURL := panel.URL + "/api/v1/mailboxes/" + url.PathEscape(mailbox.Email) + "/code?key=" + url.QueryEscape(mailbox.APIToken) + "&keyword=verification&peek=1"
	response, err := http.Get(requestURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"code":"654321"`)) {
		t.Fatalf("code response status=%d body=%s", response.StatusCode, body)
	}
}

func TestDomainSMTPSTARTTLS(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomainForOwner("", "", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	mailboxes, err := store.AddDomainMailboxesForOwner("", domain.ID, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := writeTestSMTPCertificate(t)
	service, err := StartDomainSMTP(Config{
		DomainSMTPHost:            "127.0.0.1",
		DomainSMTPPort:            0,
		DomainSMTPMaxMessageBytes: 1 << 20,
		DomainSMTPCertFile:        certFile,
		DomainSMTPKeyFile:         keyFile,
	}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	conn, err := net.Dial("tcp", service.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	readReply := func() string {
		t.Helper()
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		return line
	}
	if got := readReply(); !strings.HasPrefix(got, "220 ") {
		t.Fatalf("greeting = %q", got)
	}
	if _, err := io.WriteString(conn, "EHLO test.example\r\n"); err != nil {
		t.Fatal(err)
	}
	seenSTARTTLS := false
	for {
		line := readReply()
		if strings.Contains(line, "STARTTLS") {
			seenSTARTTLS = true
		}
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	if !seenSTARTTLS {
		t.Fatal("EHLO did not advertise STARTTLS")
	}
	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		t.Fatal(err)
	}
	if got := readReply(); !strings.HasPrefix(got, "220 ") {
		t.Fatalf("STARTTLS reply = %q", got)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "mail.example.test"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	reader = bufio.NewReader(tlsConn)
	if _, err := io.WriteString(tlsConn, "EHLO test.example\r\nMAIL FROM:<sender@example.test>\r\nRCPT TO:<"+mailboxes[0].Email+">\r\nDATA\r\nMessage-ID: <tls-test@example.test>\r\nSubject: TLS code\r\n\r\n654321\r\n.\r\nQUIT\r\n"); err != nil {
		t.Fatal(err)
	}
	var responses []string
	for len(responses) < 12 {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			break
		}
		responses = append(responses, line)
		if strings.HasPrefix(line, "221 ") {
			break
		}
	}
	if !strings.Contains(strings.Join(responses, ""), "250 message accepted") {
		t.Fatalf("TLS SMTP responses = %q", responses)
	}
	if messages := store.MessagesForMailbox(mailboxes[0].ID); len(messages) != 1 || !strings.Contains(messages[0].Body, "654321") {
		t.Fatalf("TLS messages = %#v", messages)
	}
}

func writeTestSMTPCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mail.example.test"},
		DNSNames:              []string{"mail.example.test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatal(err)
	}
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestDomainMailboxLifecycleGuards(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddDomainForOwner("", "", "invalid_domain"); err == nil {
		t.Fatal("invalid domain accepted")
	}
	domain, err := store.AddDomainForOwner("", "", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddDomainForOwner("", "", "example.test"); err == nil {
		t.Fatal("duplicate domain accepted")
	}
	if _, err := store.AddDomainMailboxesForOwner("", domain.ID, "", "", 2); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteDomain(domain.ID); err == nil || !isCodedError(err, "domain_has_mailboxes") {
		t.Fatalf("delete domain error = %v, want domain_has_mailboxes", err)
	}
	if _, err := store.SetDomainEnabled(domain.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddDomainMailboxesForOwner("", domain.ID, "", "", 1); err == nil || !isCodedError(err, "domain_disabled") {
		t.Fatalf("disabled domain create error = %v, want domain_disabled", err)
	}
}

func TestDomainProviderSelectionAndDNSInstructions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "domain-provider-user", "domain-password")
	call := func(method, path, payload string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		return rr
	}

	for _, item := range []struct {
		name     string
		provider string
		wantDNS  string
	}{
		{name: "cf.test", provider: DomainProviderCloudflare, wantDNS: "Cloudflare Email Routing"},
		{name: "smtp.test", provider: DomainProviderSMTP, wantDNS: "服务器公网 IP"},
		{name: "remail.test", provider: DomainProviderRemail, wantDNS: "Remail 控制台"},
	} {
		rr := call(http.MethodPost, "/api/domains", fmt.Sprintf(`{"name":%q,"provider":%q}`, item.name, item.provider))
		if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), fmt.Sprintf(`"provider":%q`, item.provider)) {
			t.Fatalf("create %s provider = %d body=%s", item.provider, rr.Code, rr.Body.String())
		}
		var response struct {
			Domain struct {
				ID string `json:"id"`
			} `json:"domain"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		dns := call(http.MethodGet, "/api/domains/"+response.Domain.ID+"/dns", "")
		if dns.Code != http.StatusOK || !strings.Contains(dns.Body.String(), item.wantDNS) {
			t.Fatalf("dns %s = %d body=%s", item.provider, dns.Code, dns.Body.String())
		}
	}
}

func TestDomainManagementAPIsAndCommercialWorkbench(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{DomainSMTPEnabled: true, DomainSMTPHost: "0.0.0.0", DomainSMTPPort: 2525}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "domain-admin", "domain-password")

	call := func(method, path, payload string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		return rr
	}

	rr := call(http.MethodPost, "/api/domains", `{"name":"example.test","label":"业务域名"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create domain = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(http.MethodGet, "/api/domains", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"name":"example.test"`) || !strings.Contains(rr.Body.String(), `"enabled":true`) {
		t.Fatalf("list domains = %d body=%s", rr.Code, rr.Body.String())
	}
	all := store.Snapshot()
	if len(all.Domains) != 1 {
		t.Fatalf("domain state = %+v", all.Domains)
	}
	domainID := all.Domains[0].ID

	rr = call(http.MethodPost, "/api/domain-mailboxes", `{"domain_id":"`+domainID+`","count":2,"label":"商业批次"}`)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), `"provider":"domain"`) {
		t.Fatalf("create domain mailboxes = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(http.MethodGet, "/api/mailboxes?provider=domain", "")
	if rr.Code != http.StatusOK || strings.Count(rr.Body.String(), `"provider":"domain"`) != 2 {
		t.Fatalf("list domain mailboxes = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(http.MethodGet, "/api/domains/"+domainID+"/dns", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"type":"MX"`) {
		t.Fatalf("domain DNS = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(http.MethodDelete, "/api/domains/"+domainID, "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("delete non-empty domain = %d body=%s", rr.Code, rr.Body.String())
	}

	for _, mailbox := range store.Snapshot().Mailboxes {
		rr = call(http.MethodDelete, "/api/mailboxes/"+url.PathEscape(mailbox.ID), "")
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"provider":"domain"`) {
			t.Fatalf("delete domain mailbox = %d body=%s", rr.Code, rr.Body.String())
		}
	}
	rr = call(http.MethodDelete, "/api/domains/"+domainID, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("delete empty domain = %d body=%s", rr.Code, rr.Body.String())
	}

	ui, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`data-view="domains"`, `id="domainRows"`, `id="domainRandomMode"`, `class="domain-picker-menu"`, `random_domain: randomDomain`, `class="domain-operation-grid"`, `function createDomainMailboxes()`, `function showDomainDNS(id)`, `域名邮箱`} {
		if !strings.Contains(string(ui), want) {
			t.Fatalf("commercial domain workbench missing %q", want)
		}
	}
}

func TestRandomDomainMailboxAPI(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "random-domain-user", "domain-password")

	call := func(payload string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/domains", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		return rr
	}
	for _, payload := range []string{`{"name":"one.test","label":"主域名"}`, `{"name":"two.test","label":"备用域名"}`} {
		if rr := call(payload); rr.Code != http.StatusCreated {
			t.Fatalf("create domain = %d body=%s", rr.Code, rr.Body.String())
		}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/domain-mailboxes", strings.NewReader(`{"random_domain":true,"count":24,"label":"随机批次"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || !strings.Contains(rr.Body.String(), `"random_domain":true`) {
		t.Fatalf("random create = %d body=%s", rr.Code, rr.Body.String())
	}
	snapshot := store.Snapshot()
	if len(snapshot.Mailboxes) != 24 || len(snapshot.DomainMailboxHistory) != 24 {
		t.Fatalf("mailboxes=%d history=%d, want 24", len(snapshot.Mailboxes), len(snapshot.DomainMailboxHistory))
	}
	validDomains := map[string]bool{}
	for _, domain := range snapshot.Domains {
		validDomains[domain.ID] = true
	}
	seen := map[string]bool{}
	for _, mailbox := range snapshot.Mailboxes {
		if !validDomains[mailbox.DomainID] {
			t.Fatalf("mailbox used unknown domain: %#v", mailbox)
		}
		if seen[mailbox.Email] {
			t.Fatalf("duplicate random mailbox: %s", mailbox.Email)
		}
		seen[mailbox.Email] = true
	}
}

func TestLoadConfigDomainSMTPEnvironmentOverridesDockerDefaults(t *testing.T) {
	t.Setenv("IPM_DOMAIN_SMTP_ENABLED", "true")
	t.Setenv("IPM_DOMAIN_SMTP_HOST", "127.0.0.1")
	t.Setenv("IPM_DOMAIN_SMTP_PORT", "2526")
	t.Setenv("IPM_DOMAIN_SMTP_MAX_MESSAGE_BYTES", "2097152")
	t.Setenv("IPM_DOMAIN_SMTP_CERT_FILE", "/tmp/fullchain.pem")
	t.Setenv("IPM_DOMAIN_SMTP_KEY_FILE", "/tmp/privkey.pem")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"domain_smtp_enabled":false,"domain_smtp_host":"0.0.0.0","domain_smtp_port":2525,"domain_smtp_max_message_bytes":10485760}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DomainSMTPEnabled || cfg.DomainSMTPHost != "127.0.0.1" || cfg.DomainSMTPPort != 2526 || cfg.DomainSMTPMaxMessageBytes != 2097152 || cfg.DomainSMTPCertFile != "/tmp/fullchain.pem" || cfg.DomainSMTPKeyFile != "/tmp/privkey.pem" {
		t.Fatalf("domain smtp config = %+v", cfg)
	}
}

func TestDeleteUserRemovesOwnedDomainAssets(t *testing.T) {
	store := newTestStore(t)
	admin, err := store.CreateUser("admin", "password")
	if err != nil || !admin.IsAdmin {
		t.Fatalf("create admin = %+v err=%v", admin, err)
	}
	user, err := store.CreateUser("domain-user", "password")
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomainForOwner(user.ID, "", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddDomainMailboxesForOwner(user.ID, domain.ID, "", "", 1); err != nil {
		t.Fatal(err)
	}
	result, err := store.DeleteUser(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domains != 1 || result.Mailboxes != 1 || len(store.Snapshot().Domains) != 0 {
		t.Fatalf("delete result=%+v state=%+v", result, store.Snapshot())
	}
}
