package app

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	for _, want := range []string{`data-view="domains"`, `id="domainRows"`, `function createDomainMailboxes()`, `function showDomainDNS(id)`, `域名邮箱`} {
		if !strings.Contains(string(ui), want) {
			t.Fatalf("commercial domain workbench missing %q", want)
		}
	}
}

func TestLoadConfigDomainSMTPEnvironmentOverridesDockerDefaults(t *testing.T) {
	t.Setenv("IPM_DOMAIN_SMTP_ENABLED", "true")
	t.Setenv("IPM_DOMAIN_SMTP_HOST", "127.0.0.1")
	t.Setenv("IPM_DOMAIN_SMTP_PORT", "2526")
	t.Setenv("IPM_DOMAIN_SMTP_MAX_MESSAGE_BYTES", "2097152")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"domain_smtp_enabled":false,"domain_smtp_host":"0.0.0.0","domain_smtp_port":2525,"domain_smtp_max_message_bytes":10485760}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DomainSMTPEnabled || cfg.DomainSMTPHost != "127.0.0.1" || cfg.DomainSMTPPort != 2526 || cfg.DomainSMTPMaxMessageBytes != 2097152 {
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
