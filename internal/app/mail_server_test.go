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
	server.checkMailInbox = func(_ context.Context, _ MailAccount) error { return nil }
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
	if !strings.Contains(rr.Body.String(), `"web_alias":true`) || !strings.Contains(rr.Body.String(), `"mobile_api":true`) {
		t.Fatalf("mail account verification missing: %s", rr.Body.String())
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

func TestMailAccountBindingRequiresWebAndMobileAPIValidation(t *testing.T) {
	for _, test := range []struct {
		name        string
		webError    error
		mobileError error
		wantCode    string
	}{
		{name: "web", webError: errCode("mail_invalid_credentials", "bad web login", false), wantCode: "mail_invalid_credentials"},
		{name: "mobile", mobileError: errCode("mail_mobile_login_failed", "bad mobile login", false), wantCode: "mail_mobile_login_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newTestStore(t)
			server := NewServer(Config{}, store, discardLogger()).(*Server)
			server.mailAliasDomains = func(_ context.Context, _ MailAccount) ([]string, error) {
				return []string{"mail.com"}, test.webError
			}
			server.checkMailInbox = func(_ context.Context, _ MailAccount) error { return test.mobileError }
			cookie, _ := registerTestUser(t, server, "binding-"+test.name, "password-123")
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/mail/accounts", strings.NewReader(`{"email":"owner@mail.com","password":"secret"}`))
			req.AddCookie(cookie)
			server.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), `"code":"`+test.wantCode+`"`) {
				t.Fatalf("binding status=%d body=%s", rr.Code, rr.Body.String())
			}
			if len(store.Snapshot().MailAccounts) != 0 {
				t.Fatal("invalid MAIL account was persisted")
			}
		})
	}
}

func TestMailAliasBatchRandomTemplateAndOwnerIsolation(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	cookie, owner := registerTestUser(t, server, "batch-owner", "password-owner")
	_, other := registerTestUser(t, server, "batch-other", "password-other")
	ownerAccount, _ := store.AddMailAccountForOwner(owner.ID, "owner", "owner@mail.com", "secret")
	_, _ = store.AddMailAccountForOwner(other.ID, "other", "other@mail.com", "secret")
	seen := map[string]bool{}
	server.createMailAlias = func(_ context.Context, account MailAccount, address string) (string, error) {
		if account.OwnerID != owner.ID || account.ID != ownerAccount.ID {
			t.Fatalf("random account crossed owner boundary: %+v", account)
		}
		if seen[address] {
			t.Fatalf("duplicate generated address: %s", address)
		}
		seen[address] = true
		return address, nil
	}
	server.deleteMailAlias = func(_ context.Context, _ MailAccount, _ string) error { return nil }

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mail/aliases", strings.NewReader(`{"random_account":true,"local":"[随机]-mail","domain":"mail.com","count":3}`))
	req.AddCookie(cookie)
	server.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated || len(seen) != 3 || !strings.Contains(rr.Body.String(), `"created":3`) {
		t.Fatalf("batch status=%d seen=%d body=%s", rr.Code, len(seen), rr.Body.String())
	}
	for address := range seen {
		if !strings.HasSuffix(address, "-mail@mail.com") || len(strings.Split(address, "-")[0]) != 8 {
			t.Fatalf("unexpected random template address: %s", address)
		}
	}
}

func TestDeleteMailAccountRequiresNoLinkedAliasesAndOwnerAccess(t *testing.T) {
	store := newTestStore(t)
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	_, _ = registerTestUser(t, server, "delete-admin", "password-admin")
	cookie, owner := registerTestUser(t, server, "delete-owner", "password-owner")
	otherCookie, other := registerTestUser(t, server, "delete-other", "password-other")
	account, _ := store.AddMailAccountForOwner(owner.ID, "owner", "owner@mail.com", "secret")
	linked, _ := store.AddMailAccountForOwner(owner.ID, "linked", "linked@mail.com", "secret")
	_, _ = store.AddMailboxForOwnerProvider(owner.ID, linked.ID, MailboxProviderMail, "linked", "alias@mail.com", "")

	call := func(id string, auth *http.Cookie) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/mail/accounts/"+id, nil)
		req.AddCookie(auth)
		server.ServeHTTP(rr, req)
		return rr
	}
	if rr := call(account.ID, otherCookie); rr.Code != http.StatusNotFound {
		t.Fatalf("cross-owner delete status=%d body=%s other=%s", rr.Code, rr.Body.String(), other.ID)
	}
	if rr := call(linked.ID, cookie); rr.Code != http.StatusConflict {
		t.Fatalf("linked delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := call(account.ID, cookie); rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := store.FindMailAccountByID(account.ID); ok {
		t.Fatal("MAIL account remained after delete")
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
