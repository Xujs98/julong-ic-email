package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMailAliasCreatesHTMLAndAPIInbox(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger()).(*Server)
	server.mailAliasDomains = func(_ context.Context, _ MailAccount) ([]string, error) {
		return []string{"email.com", "mail.com"}, nil
	}
	server.createMailAlias = func(_ context.Context, _ MailAccount, address string) (string, error) {
		return strings.ToLower(address), nil
	}
	server.syncMailAliases = func(_ context.Context, _ MailAccount, mailboxes []Mailbox, _ time.Time, _ string, _ int) (map[string][]ICloudSyncedMessage, string, error) {
		return map[string][]ICloudSyncedMessage{mailboxes[0].ID: {{RemoteID: "mail:101", UID: "101", Subject: "Your OpenAI code is 246810", From: "verify@example.com", Body: "Use 246810 to continue.", ReceivedAt: time.Now()}}}, "101", nil
	}
	server.deleteMailAlias = func(_ context.Context, _ MailAccount, _ string) error { return nil }

	cookie, _ := registerTestUser(t, server, "mail-alias-user", "mail-alias-password")
	call := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(cookie)
		server.ServeHTTP(rr, req)
		return rr
	}

	rr := call(http.MethodPost, "/api/mail/accounts", `{"label":"Main MAIL","email":"owner@mail.com","password":"secret"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create mail account status=%d body=%s", rr.Code, rr.Body.String())
	}
	var accountResponse struct {
		Account publicMailAccount `json:"account"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &accountResponse); err != nil {
		t.Fatal(err)
	}
	if accountResponse.Account.ID == "" || accountResponse.Account.Email != "owner@mail.com" || strings.Contains(rr.Body.String(), "secret") {
		t.Fatalf("unsafe or incomplete mail account response: %s", rr.Body.String())
	}

	rr = call(http.MethodPost, "/api/mail/aliases", `{"account_id":"`+accountResponse.Account.ID+`","local":"codebox","domain":"mail.com","label":"MAIL test"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create mail alias status=%d body=%s", rr.Code, rr.Body.String())
	}
	var aliasResponse struct {
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &aliasResponse); err != nil {
		t.Fatal(err)
	}
	mailbox := aliasResponse.Mailbox
	if mailbox.Provider != MailboxProviderMail || mailbox.Email != "codebox@mail.com" || !strings.HasPrefix(mailbox.HTMLLinkURL, "https://mail.example/mailbox/") || !strings.Contains(mailbox.APIURL, "/api/v1/mailboxes/codebox@mail.com/code?key=") {
		t.Fatalf("mail alias output=%+v", mailbox)
	}

	stored, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mail alias was not stored")
	}
	rr = call(http.MethodGet, "/api/v1/mailboxes/codebox%40mail.com/code?key="+stored.APIToken, "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"code":"246810"`) {
		t.Fatalf("mail alias API code status=%d body=%s", rr.Code, rr.Body.String())
	}

	htmlPath := strings.TrimPrefix(mailbox.HTMLLinkURL, "https://mail.example") + "/data"
	rr = httptest.NewRecorder()
	server.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, htmlPath, nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"email":"codebox@mail.com"`) || !strings.Contains(rr.Body.String(), `"code":"246810"`) {
		t.Fatalf("mail alias HTML data status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMailAliasTemplateAndProviderNormalization(t *testing.T) {
	for _, input := range []string{"mail", "mailcom", "mail.com"} {
		if got := normalizeMailboxProvider(input); got != MailboxProviderMail {
			t.Fatalf("normalizeMailboxProvider(%q)=%q", input, got)
		}
	}
	if _, _, address, err := normalizeMailAliasAddress("Demo.Box@mail.com"); err != nil || address != "demo.box@mail.com" {
		t.Fatalf("normalize mail alias address=%q err=%v", address, err)
	}
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{"MAIL别名生成", `data-view="mail"`, "/api/mail/accounts", "/api/mail/aliases", "/api/mail/mailboxes/sync", "HTML + API"} {
		if !strings.Contains(source, want) {
			t.Fatalf("MAIL alias UI missing %q", want)
		}
	}
}

func TestMailAliasRoutesAllowUserSession(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	server.mailAliasDomains = func(_ context.Context, _ MailAccount) ([]string, error) { return []string{"mail.com"}, nil }
	adminCookie, _ := registerTestUser(t, server, "mail-route-admin", "password-admin")
	_ = adminCookie
	userCookie, _ := registerTestUser(t, server, "mail-route-user", "password-user")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/mail/accounts", nil)
	req.AddCookie(userCookie)
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"success":true`) {
		t.Fatalf("ordinary user mail account route status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMailAliasRemoteRollbackWhenMailboxPersistenceFails(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	server.createMailAlias = func(_ context.Context, _ MailAccount, address string) (string, error) { return address, nil }
	var deleted string
	server.deleteMailAlias = func(_ context.Context, _ MailAccount, address string) error { deleted = address; return nil }
	cookie, user := registerTestUser(t, server, "mail-rollback-user", "password-rollback")
	account, err := store.AddMailAccountForOwner(user.ID, "rollback", "owner@mail.com", "secret")
	if err != nil {
		t.Fatal(err)
	}
	// Make the next save fail while allowing the in-memory mutation to occur.
	store.path = t.TempDir()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mail/aliases", strings.NewReader(`{"account_id":"`+account.ID+`","local":"rollback","domain":"mail.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("rollback status=%d body=%s", rr.Code, rr.Body.String())
	}
	if deleted != "rollback@mail.com" {
		t.Fatalf("remote alias rollback address=%q", deleted)
	}
	if _, ok := store.FindMailboxByEmail("rollback@mail.com"); ok {
		t.Fatal("mailbox remained after persistence failure rollback")
	}
}
