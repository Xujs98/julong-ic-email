package app

import (
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
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
	if err == nil || !strings.Contains(err.Error(), "账号密码") || !errors.As(err, &coded) || coded.code != "mail_invalid_credentials" {
		t.Fatalf("credential page error=%v", err)
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
