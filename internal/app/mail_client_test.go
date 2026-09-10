package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMailRedirectHandlesHTMLAndCredentialPage(t *testing.T) {
	redirect := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`<meta http-equiv="refresh" content="0; url=/next">`)), Header: make(http.Header)}
	got, err := redirectURL(redirect, "https://login.mail.com/start")
	if err != nil || got != "https://login.mail.com/next" {
		t.Fatalf("HTML redirect=%q err=%v", got, err)
	}

	login := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`<form><input type="password" name="password"></form>`)), Header: make(http.Header)}
	_, err = redirectURL(login, "https://login.mail.com/login")
	var coded codedError
	if err == nil || !strings.Contains(err.Error(), "未必错误") || !errors.As(err, &coded) || coded.code != "mail_web_login_rejected" || !coded.retryable {
		t.Fatalf("credential page error=%v", err)
	}
	credential := mailLoginPageError(`<p>Incorrect password</p>`)
	if !errors.As(credential, &coded) || coded.code != "mail_invalid_credentials" || coded.retryable {
		t.Fatalf("explicit credential error=%v", credential)
	}
}

func TestMailSettingsSessionCachesTokenAndRefreshesAfterUnauthorized(t *testing.T) {
	for _, test := range []struct {
		name             string
		unauthorizedOnce bool
		wantLogins       int32
	}{
		{name: "reuse", wantLogins: 1},
		{name: "refresh", unauthorizedOnce: true, wantLogins: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := NewMailClient()
			var state string
			var logins atomic.Int32
			var settingsRequests atomic.Int32
			client.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				switch {
				case request.URL.Host == "oauth2.mail.com" && request.URL.Path == "/authorize":
					state = request.URL.Query().Get("state")
					logins.Add(1)
					location := "https://mlogin.mail.com/oauth2/?authcode-context=context&login_hint=owner%40mail.com"
					return mailMobileTestResponse(http.StatusSeeOther, "", map[string]string{"Location": location}), nil
				case request.URL.Host == "mlogin.mail.com" && request.URL.Path == "/oauth2/":
					return mailMobileTestResponse(http.StatusOK, `<input name="service" value="oauth2">`, nil), nil
				case request.URL.Host == "login.mail.com" && request.URL.Path == "/login":
					if err := request.ParseForm(); err != nil || request.Form.Get("username") != "owner@mail.com" || request.Form.Get("password") != "secret" {
						t.Fatalf("unexpected login form: %v err=%v", request.Form, err)
					}
					return mailMobileTestResponse(http.StatusFound, "", map[string]string{"Location": "https://oauth2.mail.com/authcode?authcode-context=context"}), nil
				case request.URL.Host == "oauth2.mail.com" && request.URL.Path == "/authcode":
					callback := mailWebRedirectURI + "?" + url.Values{"code": {"web-code"}, "state": {state}}.Encode()
					return mailMobileTestResponse(http.StatusFound, "", map[string]string{"Location": callback}), nil
				case request.URL.Host == "oauth2.mail.com" && request.URL.Path == "/token":
					return mailMobileTestResponse(http.StatusOK, `{"access_token":"web-access"}`, nil), nil
				case request.URL.Host == "login.mail.com" && request.URL.Path == "/oauth2login":
					return mailMobileTestResponse(http.StatusFound, "", map[string]string{"Location": "https://navigator-lxa.mail.com/login?sid=navigator"}), nil
				case request.URL.Host == "navigator-lxa.mail.com" && request.URL.Path == "/login":
					return mailMobileTestResponse(http.StatusOK, "navigator", nil), nil
				case request.URL.Host == "navigator-lxa.mail.com" && request.URL.Path == "/halogin":
					return mailMobileTestResponse(http.StatusFound, "", map[string]string{"Location": "https://navigator-lxa.mail.com/?sid=navigator"}), nil
				case request.URL.Host == "navigator-lxa.mail.com" && request.URL.Path == "/":
					return mailMobileTestResponse(http.StatusOK, "root", nil), nil
				case request.URL.Host == "oauthbridge.navigator-lxa.mail.com":
					token := "settings-" + string(rune('0'+logins.Load()))
					return mailMobileTestResponse(http.StatusOK, `{"access_token":"`+token+`","expires_in":3600}`, nil), nil
				case request.URL.Host == "settings-cats.mail.com":
					call := settingsRequests.Add(1)
					if test.unauthorizedOnce && call == 1 {
						return mailMobileTestResponse(http.StatusUnauthorized, "", nil), nil
					}
					return mailMobileTestResponse(http.StatusOK, `{"domains":[{"domain":"mail.com","state":"ACTIVE"}]}`, nil), nil
				default:
					t.Fatalf("unexpected request: %s %s", request.Method, request.URL)
					return nil, nil
				}
			})

			account := MailAccount{Email: "owner@mail.com", Password: "secret"}
			for call := 0; call < 2; call++ {
				domains, err := client.AvailableAliasDomains(context.Background(), account)
				if err != nil || len(domains) != 1 || domains[0] != "mail.com" {
					t.Fatalf("available domains call %d = %v err=%v", call+1, domains, err)
				}
			}
			if logins.Load() != test.wantLogins {
				t.Fatalf("web logins = %d, want %d", logins.Load(), test.wantLogins)
			}
		})
	}
}

func TestMailLoginChallengeRequiresInteractiveControl(t *testing.T) {
	if err := mailLoginPageError(`<script>window.loginChallenge = {captcha: false, markup: "data-sitekey login failed"};</script><p>Continue to mailbox</p>`); err != nil {
		t.Fatalf("script vocabulary was classified as a challenge: %v", err)
	}
	for _, source := range []string{
		`<form action="/login/challenge"><input name="verificationCode"></form>`,
		`<div class="g-recaptcha" data-sitekey="site-key"></div>`,
	} {
		var coded codedError
		err := mailLoginPageError(source)
		if err == nil || !errors.As(err, &coded) || coded.code != "mail_login_challenge" {
			t.Fatalf("interactive challenge was not detected: %v", err)
		}
	}
}

func TestMailNavigatorSIDSupportsURLFragmentAndCookie(t *testing.T) {
	if got := mailNavigatorSID("https://navigator-lxa.mail.com/#sid=fragment-sid", nil); got != "fragment-sid" {
		t.Fatalf("fragment sid=%q", got)
	}
	jar, _ := cookiejar.New(nil)
	endpoint, _ := url.Parse("https://navigator-lxa.mail.com/")
	jar.SetCookies(endpoint, []*http.Cookie{{Name: "sid", Value: "cookie-sid", Path: "/"}})
	if got := mailNavigatorSID(endpoint.String(), jar); got != "cookie-sid" {
		t.Fatalf("cookie sid=%q", got)
	}
}
