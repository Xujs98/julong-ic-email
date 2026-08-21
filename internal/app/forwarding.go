package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	forwardingMaxBodyBytes = 24 << 20
	forwardingClockSkew    = 10 * time.Minute
)

type forwardingInboundPayload struct {
	From      string `json:"from"`
	To        string `json:"to"`
	MessageID string `json:"message_id,omitempty"`
	RawBase64 string `json:"raw_base64"`
}

func (s *Server) handleForwardingSettings(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusUnauthorized, errCode("admin_required", "需要管理员账号", false))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"settings": s.forwardingSettingsResponse(r),
	})
}

func (s *Server) handleSaveForwardingSettings(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusUnauthorized, errCode("admin_required", "需要管理员账号", false))
		return
	}
	var payload struct {
		Enabled     *bool   `json:"enabled"`
		Domain      *string `json:"domain"`
		WorkerURL   *string `json:"worker_url"`
		TargetEmail *string `json:"target_email"`
		Secret      *string `json:"secret"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	current := s.store.SystemSettings()
	if payload.Enabled != nil {
		current.ForwardingEnabled = *payload.Enabled
	}
	if payload.Domain != nil {
		current.ForwardingDomain = strings.ToLower(strings.TrimSpace(*payload.Domain))
	}
	if payload.WorkerURL != nil {
		current.ForwardingWorkerURL = strings.TrimRight(strings.TrimSpace(*payload.WorkerURL), "/")
	}
	if payload.TargetEmail != nil {
		current.ForwardingTargetEmail = strings.TrimSpace(*payload.TargetEmail)
	}
	if payload.Secret != nil && strings.TrimSpace(*payload.Secret) != "" {
		current.ForwardingSecret = strings.TrimSpace(*payload.Secret)
	}
	if err := validateForwardingSettings(current); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	saved, err := s.store.SaveSystemSettings(current)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "settings": s.forwardingSettingsResponseWith(saved, r)})
}

func (s *Server) handleRotateForwardingSecret(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusUnauthorized, errCode("admin_required", "需要管理员账号", false))
		return
	}
	secret, err := randomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	settings := s.store.SystemSettings()
	settings.ForwardingSecret = secret
	saved, err := s.store.SaveSystemSettings(settings)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"secret":   saved.ForwardingSecret,
		"settings": s.forwardingSettingsResponseWith(saved, r),
	})
}

func (s *Server) handleTestForwarding(w http.ResponseWriter, r *http.Request) {
	if !s.isAdminRequest(r) {
		writeError(w, http.StatusUnauthorized, errCode("admin_required", "需要管理员账号", false))
		return
	}
	settings := s.store.SystemSettings()
	if err := validateForwardingSettings(settings); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	state := s.store.Snapshot()
	domainMailboxes := 0
	for _, mailbox := range state.Mailboxes {
		if mailbox.ProviderKind() == MailboxProviderDomain && mailbox.APIActive && mailbox.ICloudActive && mailbox.Status != StatusDisabled {
			domainMailboxes++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"ready":   settings.ForwardingEnabled && domainMailboxes > 0,
		"message": fmt.Sprintf("配置有效，当前有 %d 个可收件域名邮箱；发送测试邮件后会自动显示在邮箱列表。", domainMailboxes),
	})
}

func (s *Server) handleForwardingInbound(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"success": false, "message": "仅支持 POST"})
		return
	}
	settings := s.store.SystemSettings()
	if !settings.ForwardingEnabled {
		writeError(w, http.StatusServiceUnavailable, errCode("forwarding_disabled", "转发收件服务未启用", true))
		return
	}
	timestamp := strings.TrimSpace(r.Header.Get("X-Julong-Forwarding-Timestamp"))
	if timestamp == "" {
		writeError(w, http.StatusUnauthorized, errCode("forwarding_timestamp_missing", "缺少转发签名时间戳", false))
		return
	}
	unixSeconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Since(time.Unix(unixSeconds, 0)) > forwardingClockSkew || time.Until(time.Unix(unixSeconds, 0)) > forwardingClockSkew {
		writeError(w, http.StatusUnauthorized, errCode("forwarding_timestamp_invalid", "转发签名已过期，请重试", true))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, forwardingMaxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, errCode("forwarding_body_read_failed", "读取转发邮件失败", true))
		return
	}
	if int64(len(body)) > forwardingMaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, errCode("forwarding_body_too_large", "转发邮件请求超过大小限制", false))
		return
	}
	if !validForwardingSignature(settings.ForwardingSecret, timestamp, body, r.Header.Get("X-Julong-Forwarding-Signature")) {
		writeError(w, http.StatusUnauthorized, errCode("forwarding_signature_invalid", "转发签名校验失败", false))
		return
	}
	var payload forwardingInboundPayload
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, errCode("forwarding_payload_invalid", "转发请求格式非法："+err.Error(), false))
		return
	}
	payload.To = strings.ToLower(strings.TrimSpace(payload.To))
	if payload.To == "" || strings.TrimSpace(payload.RawBase64) == "" {
		writeError(w, http.StatusBadRequest, errCode("forwarding_payload_incomplete", "转发请求缺少收件地址或原始邮件", false))
		return
	}
	raw, err := base64.StdEncoding.DecodeString(payload.RawBase64)
	if err != nil || len(raw) == 0 || int64(len(raw)) > settings.DomainSMTPMaxMessageBytes {
		writeError(w, http.StatusRequestEntityTooLarge, errCode("forwarding_raw_invalid", "原始邮件内容非法或超过邮件大小限制", false))
		return
	}
	if !strings.Contains(payload.To, "@") {
		writeError(w, http.StatusBadRequest, errCode("forwarding_recipient_invalid", "收件地址非法", false))
		return
	}
	domain := strings.ToLower(strings.TrimSpace(payload.To[strings.LastIndex(payload.To, "@")+1:]))
	if _, ok := s.store.FindEnabledDomainByName(domain); !ok {
		writeError(w, http.StatusNotFound, errCode("forwarding_domain_not_found", "收件域名未接入矩龙邮箱", false))
		return
	}
	mailbox, ok := s.store.FindMailboxByEmail(payload.To)
	if !ok || mailbox.ProviderKind() != MailboxProviderDomain || !mailbox.APIActive || !mailbox.ICloudActive || mailbox.Status == StatusDisabled {
		writeError(w, http.StatusNotFound, errCode("forwarding_mailbox_not_found", "收件邮箱不存在或已停用", false))
		return
	}
	parsed, err := parseDomainSMTPMessage(raw, payload.From)
	if err != nil {
		writeError(w, http.StatusBadRequest, errCode("forwarding_mime_invalid", "原始邮件解析失败："+err.Error(), false))
		return
	}
	remoteID := strings.TrimSpace(payload.MessageID)
	if remoteID == "" {
		remoteID = parsed.remoteID
	}
	remoteID += ":" + strings.ToLower(mailbox.Email)
	_, created, err := s.store.UpsertMessageContent(mailbox.ID, remoteID, "cloudflare_forwarding", parsed.subject, parsed.from, parsed.body, parsed.htmlBody, parsed.receivedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if created {
		if _, err := s.store.RecordForwardingReceived(parsed.receivedAt); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if s.logger != nil {
		s.logger.Info("cloudflare forwarding inbound stored", "from", parsed.from, "to", mailbox.Email, "message_id", parsed.remoteID, "duplicate", !created)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "stored": true, "duplicate": !created, "mailbox_id": mailbox.ID})
}

func validateForwardingSettings(settings SystemSettings) error {
	if strings.TrimSpace(settings.ForwardingSecret) == "" {
		return errCode("forwarding_secret_missing", "请先生成转发签名密钥", false)
	}
	if settings.ForwardingEnabled && strings.TrimSpace(settings.ForwardingDomain) == "" {
		return errCode("forwarding_domain_missing", "启用转发收件前请填写接收域名", false)
	}
	if domain := strings.TrimSpace(settings.ForwardingDomain); domain != "" && !managedDomainPattern.MatchString(strings.ToLower(domain)) {
		return errCode("forwarding_domain_invalid", "接收域名格式不正确", false)
	}
	if target := strings.TrimSpace(settings.ForwardingTargetEmail); target != "" {
		parsed, err := mail.ParseAddress(target)
		if err != nil || !strings.Contains(parsed.Address, "@") {
			return errCode("forwarding_target_invalid", "默认转发目标邮箱格式不正确", false)
		}
	}
	if worker := strings.TrimSpace(settings.ForwardingWorkerURL); worker != "" {
		u, err := url.Parse(worker)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errCode("forwarding_worker_url_invalid", "Worker URL 必须是 HTTPS 地址", false)
		}
	}
	return nil
}

func validForwardingSignature(secret, timestamp string, body []byte, header string) bool {
	secret = strings.TrimSpace(secret)
	header = strings.TrimSpace(header)
	if secret == "" || header == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(header), "sha256=") {
		header = strings.TrimSpace(header[len("sha256="):])
	}
	provided, err := hex.DecodeString(header)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "\n"))
	_, _ = mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

func (s *Server) forwardingSettingsResponse(r *http.Request) map[string]any {
	return s.forwardingSettingsResponseWith(s.store.SystemSettings(), r)
}

func (s *Server) forwardingSettingsResponseWith(settings SystemSettings, r *http.Request) map[string]any {
	mailboxes := make([]map[string]any, 0)
	state := s.store.Snapshot()
	domains := make([]string, 0)
	for _, domain := range state.Domains {
		if domain.Enabled {
			domains = append(domains, domain.Name)
		}
	}
	sort.Strings(domains)
	for _, mailbox := range state.Mailboxes {
		if mailbox.ProviderKind() != MailboxProviderDomain {
			continue
		}
		row := map[string]any{
			"id":            mailbox.ID,
			"email":         mailbox.Email,
			"status":        mailbox.Status,
			"active":        mailbox.APIActive && mailbox.ICloudActive && mailbox.Status != StatusDisabled,
			"receive_count": mailbox.ReceiveCount,
			"updated_at":    formatTime(mailbox.UpdatedAt),
		}
		if link, ok := s.store.MailboxHTMLLinkForMailbox(mailbox.ID); ok {
			row["html_url"] = s.mailboxHTMLURL(r, link.Token)
		}
		mailboxes = append(mailboxes, row)
	}
	endpoint := strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/")
	if endpoint == "" {
		endpoint = forwardedRequestBaseURL(r)
	}
	endpoint += "/api/v1/forwarding/inbound"
	return map[string]any{
		"enabled":                settings.ForwardingEnabled,
		"domain":                 settings.ForwardingDomain,
		"domains":                domains,
		"worker_url":             settings.ForwardingWorkerURL,
		"target_email":           settings.ForwardingTargetEmail,
		"endpoint_url":           endpoint,
		"secret":                 settings.ForwardingSecret,
		"secret_masked":          maskSecret(settings.ForwardingSecret, 6),
		"secret_configured":      strings.TrimSpace(settings.ForwardingSecret) != "",
		"received_count":         settings.ForwardingReceivedCount,
		"last_received_at":       formatTime(settings.ForwardingLastReceivedAt),
		"mailboxes":              mailboxes,
		"cloudflare_setup_ready": settings.ForwardingEnabled && settings.ForwardingDomain != "" && len(domains) > 0 && len(mailboxes) > 0,
	}
}

func forwardedRequestBaseURL(r *http.Request) string {
	if r == nil {
		return "http://127.0.0.1"
	}
	scheme := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if scheme != "http" && scheme != "https" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return scheme + "://" + host
}
