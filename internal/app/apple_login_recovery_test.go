package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppleLoginCarriesPortalAndTokenCookiesIntoAuth(t *testing.T) {
	oldBase := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBase }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/account/manage/section/privacy":
			http.SetCookie(w, &http.Cookie{Name: "portal", Value: "start", Path: "/"})
			_, _ = w.Write([]byte(`<html></html>`))
		case "/bootstrap/portal":
			if !strings.Contains(r.Header.Get("Cookie"), "portal=start") {
				t.Error("bootstrap lost portal cookie")
			}
			http.SetCookie(w, &http.Cookie{Name: "bootstrap", Value: "ready", Path: "/"})
			_, _ = w.Write([]byte(`{}`))
		case "/account/manage/gs/ws/token":
			if !strings.Contains(r.Header.Get("Cookie"), "bootstrap=ready") || r.Header.Get("scnt") != "" {
				t.Error("pre-login token request lost bootstrap state or sent auth scnt")
			}
			http.SetCookie(w, &http.Cookie{Name: "challenge", Value: "retained", Path: "/"})
			w.Header().Set("scnt", "manage-challenge")
			w.WriteHeader(http.StatusUnauthorized)
		case "/auth":
			for _, want := range []string{"portal=start", "bootstrap=ready", "challenge=retained"} {
				if !strings.Contains(r.Header.Get("Cookie"), want) {
					t.Errorf("authentication lost %s", want)
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL
	session := &appleAuthSession{Endpoints: appleAccountManageAuthEndpoints()}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.primeAppleAccountManageState(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if session.ManageScnt != "manage-challenge" || session.Scnt != "" {
		t.Fatal("management and authentication challenges were not kept separate")
	}
	if _, _, err := client.do(t.Context(), session, http.MethodGet, ts.URL+"/auth", nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
}

func TestAppleLoginKeepsRedirectCookies(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/begin" {
			http.SetCookie(w, &http.Cookie{Name: "redirect-session", Value: "kept", Path: "/"})
			w.Header().Set("scnt", "redirect-scnt")
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		if !strings.Contains(r.Header.Get("Cookie"), "redirect-session=kept") {
			t.Error("redirect response cookie was dropped")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	session := &appleAuthSession{}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if _, _, err := client.do(t.Context(), session, http.MethodGet, ts.URL+"/begin", nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if session.Scnt != "redirect-scnt" || len(session.Cookies) != 1 {
		t.Fatal("redirect session not retained")
	}
}

func TestAppleLoginCompletionRetryDoesNotReplayAcceptedOTP(t *testing.T) {
	for _, method := range []string{appleTwoFactorMethodTrustedDevice, appleTwoFactorMethodPhone} {
		t.Run(method, func(t *testing.T) {
			oldBase := appleAccountManageBaseURL
			defer func() { appleAccountManageBaseURL = oldBase }()
			otpCalls, trustCalls, tokenCalls := 0, 0, 0
			allowToken := false
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/verify/trusteddevice/securitycode", "/verify/phone/securitycode":
					otpCalls++
					w.Header().Set("scnt", "verified")
					w.WriteHeader(http.StatusNoContent)
				case "/2sv/trust":
					trustCalls++
					w.Header().Set("scnt", "trusted")
					w.WriteHeader(http.StatusNoContent)
				case "/account/manage/section/privacy", "/bootstrap/portal":
					_, _ = w.Write([]byte(`{}`))
				case "/account/manage/gs/ws/token":
					tokenCalls++
					if !allowToken {
						http.SetCookie(w, &http.Cookie{Name: "rotated", Value: "retained", Path: "/"})
						w.Header().Set("scnt", "rotated-scnt")
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if !strings.Contains(r.Header.Get("Cookie"), "rotated=retained") || r.Header.Get("scnt") != "rotated-scnt" {
						t.Error("completion retry lost rotated cookies or scnt")
					}
					w.Header().Set("scnt", "ready")
					_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
				case "/account/manage":
					_, _ = w.Write([]byte(`{"apiKey":"test-key"}`))
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer ts.Close()
			appleAccountManageBaseURL = ts.URL
			client := &AppleAuthClient{httpClient: ts.Client()}
			session := &appleAuthSession{Endpoints: appleAuthEndpoints{Home: "https://account.apple.com", Auth: ts.URL}, AppleID: "test@example.test", Scnt: "before", TwoFactorMethod: method}
			pending := appleAuthPending{Session: session}
			result, err := client.SubmitAppleAccountManage2FA(context.Background(), pending, "123456", nil)
			if err == nil || !strings.Contains(err.Error(), "验证码已通过") || len(result.LoginStates) != 0 {
				t.Fatalf("incomplete login was not reported accurately: %v", err)
			}
			response := httptest.NewRecorder()
			writeError(response, http.StatusBadGateway, err)
			if !strings.Contains(response.Body.String(), "验证码已通过") || !strings.Contains(response.Body.String(), "apple_account_login_incomplete") {
				t.Fatal("HTTP error hid verified-OTP recovery instructions")
			}
			if session.ManageLoginState == nil || !session.TwoFactorVerified {
				t.Fatal("verified pending login was lost")
			}
			allowToken = true
			result, err = client.SubmitAppleAccountManage2FA(context.Background(), pending, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if otpCalls != 1 || trustCalls != 1 || tokenCalls < 2 || len(result.LoginStates) != 1 || result.LoginStates[0].APIKey != "test-key" {
				t.Fatalf("completion did not resume correctly: otp=%d trust=%d token=%d", otpCalls, trustCalls, tokenCalls)
			}
		})
	}
}

func TestAppleLoginRejectedOTPIsNotMarkedVerified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/securitycode") {
			t.Error("rejected OTP advanced to session completion")
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()
	client := &AppleAuthClient{httpClient: ts.Client()}
	session := &appleAuthSession{Endpoints: appleAuthEndpoints{Auth: ts.URL}}
	_, err := client.SubmitAppleAccountManage2FA(t.Context(), appleAuthPending{Session: session}, "123456", nil)
	if err == nil || session.TwoFactorVerified || session.ManageLoginState != nil {
		t.Fatalf("rejected OTP marked verified: %v", err)
	}
}
