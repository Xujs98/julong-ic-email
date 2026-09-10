package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMailMobileLoginValidatesUserDataAndCachesSession(t *testing.T) {
	client := NewMailClient()
	var state string
	var tokenRequests atomic.Int32
	client.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.URL.Host == "oauth2.mail.com" && request.URL.Path == "/authorize":
			state = request.URL.Query().Get("state")
			if request.URL.Query().Get("code_challenge") == "" || request.URL.Query().Get("code_challenge_method") != "S256" {
				t.Fatalf("authorize query missing PKCE: %s", request.URL.RawQuery)
			}
			return mailMobileTestResponse(http.StatusFound, "", map[string]string{"Location": "https://auth.mail.com/loginapp/oauth2?authcode-context=context-1"}), nil
		case request.URL.Host == "auth.mail.com" && request.URL.Path == "/loginapp/oauth2":
			return mailMobileTestResponse(http.StatusOK, "login", nil), nil
		case request.URL.Host == "login.mail.com" && request.URL.Path == "/login":
			if err := request.ParseForm(); err != nil || request.Form.Get("username") != "owner@mail.com" || request.Form.Get("password") == "" {
				t.Fatalf("unexpected login form: %v %v", request.Form, err)
			}
			return mailMobileTestResponse(http.StatusFound, "", map[string]string{"Location": "https://oauth2.mail.com/authcode?authcode-context=context-1"}), nil
		case request.URL.Host == "oauth2.mail.com" && request.URL.Path == "/authcode":
			location := mailMobileRedirectURI + "?" + url.Values{"code": {"code-1"}, "state": {state}}.Encode()
			return mailMobileTestResponse(http.StatusFound, "", map[string]string{"Location": location}), nil
		case request.URL.Host == "oauth2.mail.com" && request.URL.Path == "/token":
			tokenRequests.Add(1)
			if request.Header.Get("Authorization") != mailMobileOAuthAuth {
				t.Fatal("mobile token authorization header missing")
			}
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if request.Form.Get("grant_type") == "authorization_code" {
				return mailMobileTestResponse(http.StatusOK, `{"access_token":"initial","refresh_token":"refresh-1","expires_in":3600}`, nil), nil
			}
			return mailMobileTestResponse(http.StatusOK, `{"access_token":"active","refresh_token":"refresh-2","expires_in":3600}`, nil), nil
		case request.URL.Host == "mobsi.mail.com" && request.URL.Path == "/rest/MobSI/UserData":
			if request.Method != http.MethodHead || request.Header.Get("Authorization") != "Bearer active" {
				t.Fatalf("unexpected UserData validation: %s %s", request.Method, request.Header.Get("Authorization"))
			}
			return mailMobileTestResponse(http.StatusOK, "", nil), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
			return nil, nil
		}
	})

	account := MailAccount{Email: "owner@mail.com", Password: "secret"}
	if err := client.CheckMobileAPI(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	if err := client.CheckMobileAPI(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	if tokenRequests.Load() != 2 {
		t.Fatalf("token requests = %d, want one login exchange and one refresh", tokenRequests.Load())
	}
}

func TestMailMobileSyncRoutesAliasMessagesAndPreservesHTML(t *testing.T) {
	client := NewMailClient()
	client.mobileSessions["owner@mail.com"] = mailMobileSession{AccessToken: "active", RefreshToken: "refresh", ExpiresAt: time.Now().Add(time.Hour)}
	now := time.Now().UTC().Truncate(time.Second)
	date := now.UnixMilli()
	newerDate := now.Add(time.Minute).UnixMilli()
	client.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer active" {
			t.Fatalf("missing mobile bearer token for %s", request.URL)
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/folders"):
			return mailMobileTestResponse(http.StatusOK, `{"folders":[{"folderIdentifier":"inbox","attribute":{"folderType":"INBOX"},"folders":[{"folderIdentifier":"custom","attribute":{"folderType":"USER_DEFINED"}}]},{"folderIdentifier":"trash","attribute":{"folderType":"TRASH"}}]}`, nil), nil
		case strings.Contains(request.URL.Path, "/Folder/inbox/Mail"):
			body := `{"mail":[{"mailURI":"../../Mail/ignored","attribute":{"mailIdentifier":"ignored"},"mailHeader":{"from":"other@example.test","to":"owner@mail.com","subject":"Account notice","date":` + fmt.Sprint(newerDate) + `}},{"mailURI":"../../Mail/101","attribute":{"mailIdentifier":"101"},"mailHeader":{"from":"Verify <verify@example.test>","to":["codebox@mail.com"],"subject":"Your verification code","date":` + fmt.Sprint(date) + `}}]}`
			return mailMobileTestResponse(http.StatusOK, body, nil), nil
		case strings.Contains(request.URL.Path, "/Folder/custom/Mail"):
			return mailMobileTestResponse(http.StatusOK, `{"mail":[]}`, nil), nil
		case strings.Contains(request.URL.Path, "/Mail/101/Body"):
			return mailMobileTestResponse(http.StatusOK, `<html><body><strong>Code 246810</strong></body></html>`, nil), nil
		default:
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
			return nil, nil
		}
	})

	mailboxes := []Mailbox{{ID: "box-1", Email: "codebox@mail.com"}, {ID: "box-2", Email: "other@mail.com"}}
	messages, lastID, err := client.SyncAliases(context.Background(), MailAccount{Email: "owner@mail.com"}, mailboxes, now.Add(-time.Hour), allMailboxMessagesKeyword, 1)
	if err != nil {
		t.Fatal(err)
	}
	if lastID != "101" || len(messages["box-1"]) != 1 || len(messages["box-2"]) != 0 {
		t.Fatalf("unexpected routed messages: last=%q messages=%+v", lastID, messages)
	}
	message := messages["box-1"][0]
	if message.RemoteID != "mail:101" || message.UID != "101" || !message.ReceivedAt.Equal(now) {
		t.Fatalf("unexpected message identity: %+v", message)
	}
	if !strings.Contains(message.Body, "246810") || !strings.Contains(message.HTMLBody, "<strong>") {
		t.Fatalf("message body was not preserved: %+v", message)
	}
}

func TestMailMobileStringListAcceptsSingleAddress(t *testing.T) {
	var header mailMobileHeader
	if err := json.Unmarshal([]byte(`{"to":"alias@mail.com"}`), &header); err != nil {
		t.Fatal(err)
	}
	if len(header.To) != 1 || header.To[0] != "alias@mail.com" {
		t.Fatalf("single address decoded as %#v", header.To)
	}
}

func mailMobileTestResponse(status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}
