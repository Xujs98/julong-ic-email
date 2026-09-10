package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	mailOAuthBaseURL        = "https://oauth2.mail.com"
	mailSettingsBaseURL     = "https://settings-cats.mail.com"
	mailBridgeURL           = "https://oauthbridge.navigator-lxa.mail.com/navigator/oauth2/token"
	mailWebClientID         = "mailcom_mailcheck_chrome"
	mailWebRedirectURI      = "https://lpebgcnlaohcgdfhbffjajlnpifdkllg.chromiumapp.org/"
	mailAliasLimit          = 10
	mailWebUserAgent        = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	mailWebOAuthBasicAuth   = "Basic bWFpbGNvbV9tYWlsY2hlY2tfY2hyb21lOnRJWkNZWjFZOFFhNUt0MjJMVXJXSDJTc29td1VhV1F5dGszWWdNem4="
	mailSettingsBasicAuth   = "Basic bWFpbGNvbV9tYWlsc2V0X3Jvb3RfbGl2ZToqKioqKioq"
	mailSettingsPartnerData = "eyJ1c2VjYXNlIjoiaW5ib3hfdW5yZWFkIiwiYXJncyI6W10sImlkIjoyLCJjYWxsZXJfYXBwIjoidG9vbGJhciIsImNhbGxlcl92ZXJzaW9uIjoiQ2hyb21lLzguMC41LjAifQ=="
)

var mailAliasLocalPattern = regexp.MustCompile(`^[a-z0-9._-]{3,62}$`)

type MailClient struct {
	client           *http.Client
	settingsMu       sync.Mutex
	settingsSessions map[string]mailSettingsSession
	mobileMu         sync.Mutex
	mobileSessions   map[string]mailMobileSession
}

type mailSettingsSession struct {
	AccessToken string
	Password    string
	ExpiresAt   time.Time
}

type mailAlias struct {
	Address   string `json:"address"`
	Deletable *bool  `json:"deletable,omitempty"`
}

type mailAliasList struct {
	Addresses []mailAlias `json:"mailaddresslist"`
}
type mailDomainList struct {
	Domains []struct{ Domain, State string } `json:"domains"`
}

func NewMailClient() *MailClient {
	jar, _ := cookiejar.New(nil)
	return &MailClient{
		client:           newMailHTTPClient(jar, nil),
		settingsSessions: make(map[string]mailSettingsSession),
		mobileSessions:   make(map[string]mailMobileSession),
	}
}

func newMailHTTPClient(jar http.CookieJar, transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
		Jar:       jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (c *MailClient) AvailableAliasDomains(ctx context.Context, account MailAccount) ([]string, error) {
	var response mailDomainList
	if err := c.settingsJSONForAccount(ctx, account, http.MethodGet, "/domains?absoluteURI=false&q.state.eq=ACTIVE&q.legacySupport.eq=true", nil, &response); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(response.Domains))
	for _, item := range response.Domains {
		domain := strings.ToLower(strings.TrimSpace(item.Domain))
		if domain != "" && (item.State == "" || strings.EqualFold(item.State, "ACTIVE")) {
			out = append(out, domain)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *MailClient) CreateAlias(ctx context.Context, account MailAccount, requested string) (string, error) {
	local, domain, address, err := normalizeMailAliasAddress(requested)
	if err != nil {
		return "", err
	}
	aliases, err := c.aliases(ctx, account)
	if err != nil {
		return "", err
	}
	if len(aliases) >= mailAliasLimit {
		return "", errCode("mail_alias_limit", "mail.com 别名数量已达到上限 10 个", false)
	}
	for _, alias := range aliases {
		if strings.EqualFold(alias.Address, address) {
			return "", errCode("mail_alias_exists", "mail.com 别名已存在", false)
		}
	}
	domains, err := c.availableAliasDomainsForAccount(ctx, account)
	if err != nil {
		return "", err
	}
	if !containsStringFold(domains, domain) {
		return "", errCode("mail_alias_domain_unavailable", "所选 mail.com 别名域名当前不可用", true)
	}
	validation := map[string]any{}
	if err := c.settingsJSONForAccount(ctx, account, http.MethodPost, "/mailaccount/emailAddressValidations?absoluteURI=false", []string{address}, &validation); err != nil {
		return "", err
	}
	if len(validation) > 0 {
		return "", errCode("mail_alias_unavailable", "mail.com 别名已被占用", false)
	}
	payload := map[string]any{"address": local + "@" + domain, "deletable": true, "pgpEnabled": false, "defaultSenderAddress": false, "defaultReceiverAddress": false, "state": "ACTIVE"}
	if err := c.settingsJSONForAccount(ctx, account, http.MethodPost, "/mailaccount/primary/emailAddresses?absoluteURI=false", payload, nil); err != nil {
		return "", err
	}
	for attempt := 0; attempt < 4; attempt++ {
		aliases, listErr := c.aliases(ctx, account)
		if listErr == nil {
			for _, alias := range aliases {
				if strings.EqualFold(alias.Address, address) {
					return address, nil
				}
			}
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
			}
		}
	}
	return "", errCode("mail_alias_create_unconfirmed", "mail.com 别名创建后未确认成功，请稍后同步", true)
}

func (c *MailClient) DeleteAlias(ctx context.Context, account MailAccount, address string) error {
	_, _, normalized, err := normalizeMailAliasAddress(address)
	if err != nil {
		return err
	}
	aliases, err := c.aliases(ctx, account)
	if err != nil {
		return err
	}
	deletable := false
	for _, alias := range aliases {
		if strings.EqualFold(alias.Address, normalized) {
			deletable = alias.Deletable == nil || *alias.Deletable
			break
		}
	}
	if !deletable {
		return errCode("mail_alias_not_deletable", "该 mail.com 地址不是可删除别名", false)
	}
	path := "/mailaccount/primary/emailAddressesRemovals/" + url.PathEscape(normalized) + "/removals?absoluteURI=false"
	return c.settingsJSONForAccount(ctx, account, http.MethodPost, path, nil, nil)
}

func (c *MailClient) SyncAliases(ctx context.Context, account MailAccount, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, string, error) {
	return c.SyncAliasesMobile(ctx, account, mailboxes, after, keyword, maxMessages)
}

func normalizeMailAliasAddress(input string) (string, string, string, error) {
	input = strings.ToLower(strings.TrimSpace(input))
	parts := strings.Split(input, "@")
	if len(parts) != 2 || !mailAliasLocalPattern.MatchString(parts[0]) || strings.TrimSpace(parts[1]) == "" {
		return "", "", "", errCode("invalid_mail_alias", "别名需为 3-62 位字母、数字、点、横线或下划线，并选择有效域名", false)
	}
	return parts[0], parts[1], parts[0] + "@" + parts[1], nil
}

func (c *MailClient) aliases(ctx context.Context, account MailAccount) ([]mailAlias, error) {
	var response mailAliasList
	err := c.settingsJSONForAccount(ctx, account, http.MethodGet, "/mailaccount/primary/emailAddresses?absoluteURI=false&q.state.in=ACTIVE&q.type.in=MANAGED%2CDOMAIN_HOSTING", nil, &response)
	return response.Addresses, err
}

func (c *MailClient) availableAliasDomainsForAccount(ctx context.Context, account MailAccount) ([]string, error) {
	var response mailDomainList
	if err := c.settingsJSONForAccount(ctx, account, http.MethodGet, "/domains?absoluteURI=false&q.state.eq=ACTIVE&q.legacySupport.eq=true", nil, &response); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(response.Domains))
	for _, item := range response.Domains {
		if strings.TrimSpace(item.Domain) != "" {
			out = append(out, strings.ToLower(strings.TrimSpace(item.Domain)))
		}
	}
	return out, nil
}

func (c *MailClient) settingsJSONForAccount(ctx context.Context, account MailAccount, method, path string, payload, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.settingsToken(ctx, account)
		if err != nil {
			return err
		}
		err = c.settingsJSON(ctx, token, method, path, payload, out)
		if !isCodedError(err, "mail_settings_unauthorized") || attempt > 0 {
			return err
		}
		c.invalidateSettingsSession(account.Email, token)
	}
	return errCode("mail_settings_oauth_failed", "mail.com 设置接口登录失效，请稍后重试", true)
}

func (c *MailClient) settingsJSON(ctx context.Context, token, method, path string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, _ := http.NewRequestWithContext(ctx, method, mailSettingsBaseURL+path, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://mailset-root.mail.com")
	req.Header.Set("Referer", "https://mailset-root.mail.com/")
	req.Header.Set("X-UI-App", "mailcom.mailset-compose/1.0.5-build.322")
	req.Header.Set("X-Request-ID", randomHex(16))
	req.Header.Set("User-Agent", mailWebUserAgent)
	switch {
	case strings.Contains(path, "emailAddressesRemovals"):
		req.Header.Set("Accept", "text/plain;charset=UTF-8")
		req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	case strings.Contains(path, "emailAddressValidations"):
		req.Header.Set("Accept", "application/vnd.ui.trinity.email-address-validation-response+json")
		req.Header.Set("Content-Type", "application/vnd.ui.trinity.email-address-validation-request+json")
	case strings.Contains(path, "emailAddresses") && method == http.MethodPost:
		req.Header.Set("Accept", "application/vnd.ui.trinity.minimalmailaddress-v3+json")
		req.Header.Set("Content-Type", "application/vnd.ui.trinity.minimalmailaddress-v3+json")
	case strings.Contains(path, "emailAddresses"):
		req.Header.Set("Accept", "application/vnd.ui.trinity.mailaddress.list-v5+json")
		req.Header.Set("Content-Type", "application/vnd.ui.trinity.mailaddress.list-v5+json")
	default:
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	response, err := c.client.Do(req)
	if err != nil {
		return errCode("mail_request_failed", "mail.com 请求失败："+err.Error(), true)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == http.StatusUnauthorized {
			return errCode("mail_settings_unauthorized", "mail.com 设置会话已过期", true)
		}
		data, _ := io.ReadAll(io.LimitReader(response.Body, 1000))
		return errCode("mail_request_rejected", fmt.Sprintf("mail.com 请求返回 %d：%s", response.StatusCode, strings.TrimSpace(string(data))), response.StatusCode >= 500)
	}
	if out != nil && response.StatusCode != http.StatusNoContent {
		return json.NewDecoder(response.Body).Decode(out)
	}
	return nil
}

func (c *MailClient) settingsToken(ctx context.Context, account MailAccount) (string, error) {
	email := normalizeICloudIMAPEmail(account.Email)
	if email == "" || strings.TrimSpace(account.Password) == "" {
		return "", errCode("mail_credentials_missing", "mail.com Web 登录缺少账号或密码", false)
	}
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	if session := c.settingsSessions[email]; session.AccessToken != "" && session.Password == account.Password && time.Until(session.ExpiresAt) > time.Minute {
		return session.AccessToken, nil
	}
	flow := c.newSettingsAuthFlow()
	token, expiresAt, err := flow.openSettingsSession(ctx, account)
	if err != nil {
		return "", err
	}
	c.settingsSessions[email] = mailSettingsSession{AccessToken: token, Password: account.Password, ExpiresAt: expiresAt}
	return token, nil
}

func (c *MailClient) openSettingsSession(ctx context.Context, account MailAccount) (string, time.Time, error) {
	state := randomHex(12)
	authorize, _ := url.Parse(mailOAuthBaseURL + "/authorize")
	q := authorize.Query()
	q.Set("client_id", mailWebClientID)
	q.Set("redirect_uri", mailWebRedirectURI)
	q.Set("scope", "mailbox_user_status_access mailbox_user_full_access login")
	q.Set("response_type", "code")
	q.Set("hl", "en-US")
	q.Set("state", state)
	q.Set("login_hint", account.Email)
	authorize.RawQuery = q.Encode()
	response, err := c.webRequest(ctx, authorize.String(), http.MethodGet, "", "", mailWebUserAgent)
	if err != nil {
		return "", time.Time{}, err
	}
	location, err := redirectURL(response, authorize.String())
	if err != nil {
		return "", time.Time{}, err
	}
	loginPage, err := c.webRequest(ctx, location, http.MethodGet, "", "", mailWebUserAgent)
	if err != nil {
		return "", time.Time{}, err
	}
	loginHTML, _ := io.ReadAll(loginPage.Body)
	loginPage.Body.Close()
	params, err := mailLoginFormParams(string(loginHTML), location)
	if err != nil {
		return "", time.Time{}, err
	}
	params.Set("username", account.Email)
	params.Set("password", account.Password)
	loginResponse, err := c.webRequestWithReferer(ctx, "https://login.mail.com/login", http.MethodPost, params.Encode(), "https://mlogin.mail.com", location, mailWebUserAgent)
	if err != nil {
		return "", time.Time{}, err
	}
	authURL, err := redirectURL(loginResponse, "https://login.mail.com/")
	if err != nil {
		return "", time.Time{}, err
	}
	authResponse, err := c.webRequest(ctx, authURL, http.MethodGet, "", "", mailWebUserAgent)
	if err != nil {
		return "", time.Time{}, err
	}
	callbackURL, err := redirectURL(authResponse, authURL)
	if err != nil {
		return "", time.Time{}, err
	}
	callback, _ := url.Parse(callbackURL)
	code := callback.Query().Get("code")
	if code == "" || callback.Query().Get("state") != state {
		return "", time.Time{}, errCode("mail_oauth_failed", "mail.com OAuth 未返回有效授权码", true)
	}
	token, err := c.oauthToken(ctx, code, mailWebRedirectURI, mailWebClientID, "", mailWebOAuthBasicAuth)
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{"service": {"mailint"}, "origin": {"toolbar"}, "access_token": {token}, "successURL": {"https://navigator-lxa.mail.com/login"}, "loginFailedURL": {"http://www.mail.com/?status=nologin"}, "loginErrorURL": {"http://www.mail.com/?status=nologin"}, "statistics": {}, "partnerdata": {mailSettingsPartnerData}}
	navResponse, err := c.webRequest(ctx, "https://login.mail.com/oauth2login", http.MethodPost, form.Encode(), "", mailWebUserAgent)
	if err != nil {
		return "", time.Time{}, err
	}
	navURL, err := redirectURL(navResponse, "https://login.mail.com/")
	if err != nil {
		return "", time.Time{}, err
	}
	navigatorPage, err := c.webRequest(ctx, navURL, http.MethodGet, "", "", mailWebUserAgent)
	if err != nil {
		return "", time.Time{}, err
	}
	navigatorPage.Body.Close()
	parsed, _ := url.Parse(navURL)
	parsed.Path = "/halogin"
	parsedQuery := parsed.Query()
	parsedQuery.Set("tz", "5.5")
	parsed.RawQuery = parsedQuery.Encode()
	halogin, err := c.webRequest(ctx, parsed.String(), http.MethodGet, "", "", mailWebUserAgent)
	if err != nil {
		return "", time.Time{}, err
	}
	rootURL, err := redirectURL(halogin, parsed.String())
	if err != nil {
		return "", time.Time{}, err
	}
	sid := mailNavigatorSID(rootURL, c.client.Jar)
	if sid == "" {
		return "", time.Time{}, errCode("mail_navigator_failed", "mail.com Web 登录已完成，但未取得 navigator 会话 SID；请稍后重试或检查账号是否触发安全验证", true)
	}
	if rootPage, rootErr := c.webRequest(ctx, rootURL, http.MethodGet, "", "", mailWebUserAgent); rootErr == nil {
		rootPage.Body.Close()
	}
	bridge, _ := url.Parse(mailBridgeURL)
	query := bridge.Query()
	query.Set("sid", sid)
	bridge.RawQuery = query.Encode()
	bridgeForm := url.Values{"grant_type": {"urn:mam:oauth:grant-type:spa"}, "scope": {"mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, bridge.String(), strings.NewReader(bridgeForm.Encode()))
	req.Header.Set("Authorization", mailSettingsBasicAuth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://mailset-root.mail.com")
	req.Header.Set("Referer", "https://mailset-root.mail.com/")
	response, err = c.client.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", time.Time{}, errCode("mail_settings_oauth_failed", fmt.Sprintf("mail.com 设置接口授权失败：HTTP %d", response.StatusCode), response.StatusCode >= 500)
	}
	var settings struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&settings); err != nil || settings.AccessToken == "" {
		return "", time.Time{}, errCode("mail_settings_oauth_failed", "mail.com 设置接口登录失败", true)
	}
	// The bridge does not consistently expose expires_in. Keep the token until
	// a 401 forces one clean refresh instead of repeating password login flows.
	return settings.AccessToken, time.Now().Add(12 * time.Hour), nil
}

func (c *MailClient) newSettingsAuthFlow() *MailClient {
	jar, _ := cookiejar.New(nil)
	return &MailClient{client: newMailHTTPClient(jar, c.client.Transport)}
}

func (c *MailClient) invalidateSettingsSession(email, accessToken string) {
	email = normalizeICloudIMAPEmail(email)
	c.settingsMu.Lock()
	if session := c.settingsSessions[email]; accessToken == "" || session.AccessToken == accessToken {
		delete(c.settingsSessions, email)
	}
	c.settingsMu.Unlock()
}

func (c *MailClient) oauthToken(ctx context.Context, code, redirectURI, clientID, verifier, auth string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "client_id": {clientID}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, mailOAuthBaseURL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	response, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var token struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil || token.AccessToken == "" {
		return "", errCode("mail_oauth_failed", firstNonEmpty(token.Error, "mail.com OAuth 登录失败"), false)
	}
	return token.AccessToken, nil
}

func (c *MailClient) webRequest(ctx context.Context, endpoint, method, encoded, origin, userAgent string) (*http.Response, error) {
	return c.webRequestWithReferer(ctx, endpoint, method, encoded, origin, "", userAgent)
}

func (c *MailClient) webRequestWithReferer(ctx context.Context, endpoint, method, encoded, origin, referer, userAgent string) (*http.Response, error) {
	var body io.Reader
	if encoded != "" {
		body = strings.NewReader(encoded)
	}
	req, _ := http.NewRequestWithContext(ctx, method, endpoint, body)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if encoded != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, errCode("mail_login_failed", "mail.com 登录请求失败："+err.Error(), true)
	}
	return response, nil
}

func redirectURL(response *http.Response, base string) (string, error) {
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if response.StatusCode >= 300 && response.StatusCode < 400 && location != "" {
		return resolveMailURL(base, location)
	}
	data, _ := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	source := string(data)
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if next := mailHTMLRedirectURL(source, base); next != "" {
			return next, nil
		}
		if loginErr := mailLoginPageError(source); loginErr != nil {
			return "", loginErr
		}
	}
	return "", errCode("mail_redirect_failed", fmt.Sprintf("mail.com Web 登录流程未返回预期跳转（HTTP %d）", response.StatusCode), response.StatusCode >= 500)
}

func resolveMailURL(base, location string) (string, error) {
	ref, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	next, err := ref.Parse(html.UnescapeString(strings.TrimSpace(location)))
	if err != nil {
		return "", err
	}
	return next.String(), nil
}

func mailHTMLRedirectURL(source, base string) string {
	for _, tag := range regexp.MustCompile(`(?is)<meta\b[^>]*>`).FindAllString(source, -1) {
		if !strings.EqualFold(strings.TrimSpace(htmlAttribute(tag, "http-equiv")), "refresh") {
			continue
		}
		match := regexp.MustCompile(`(?is)\burl\s*=\s*["']?([^"';\s>]+)`).FindStringSubmatch(htmlAttribute(tag, "content"))
		if len(match) == 2 {
			if next, err := resolveMailURL(base, match[1]); err == nil {
				return next
			}
		}
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?is)(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?is)(?:window\.)?location\.replace\(\s*["']([^"']+)["']\s*\)`),
	}
	for _, pattern := range patterns {
		if match := pattern.FindStringSubmatch(source); len(match) == 2 {
			if next, err := resolveMailURL(base, match[1]); err == nil {
				return next
			}
		}
	}
	return ""
}

func mailLoginPageError(source string) error {
	markup := regexp.MustCompile(`(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>|<!--.*?-->`).ReplaceAllString(source, " ")
	lower := strings.ToLower(markup)
	// Login pages often ship scripts containing generic words such as
	// "challenge" or "captcha". Only classify an actual challenge when the
	// returned document contains an interactive verification control.
	challengeControls := []*regexp.Regexp{
		regexp.MustCompile(`(?is)<(?:input|textarea)\b[^>]*(?:name|id)\s*=\s*["'][^"']*(?:captcha|otp|security.?code|verification.?code|challenge)[^"']*["']`),
		regexp.MustCompile(`(?is)<form\b[^>]*action\s*=\s*["'][^"']*(?:captcha|challenge|two.?factor|verify)[^"']*["']`),
		regexp.MustCompile(`(?is)\b(?:data-sitekey|g-recaptcha|h-captcha|cf-turnstile)\b`),
	}
	for _, pattern := range challengeControls {
		if pattern.MatchString(lower) {
			return errCode("mail_login_challenge", "mail.com 登录页要求交互式安全验证，请在官网登录完成后重试", false)
		}
	}
	credentialMarkers := []string{"invalid password", "incorrect password", "wrong password", "authentication failed"}
	for _, marker := range credentialMarkers {
		if strings.Contains(lower, marker) {
			return errCode("mail_invalid_credentials", "mail.com Web 登录失败，请检查账号和密码", false)
		}
	}
	for _, marker := range []string{"login failed", "status=login-failed", "status=login_failed"} {
		if strings.Contains(lower, marker) {
			return errCode("mail_web_login_rejected", "mail.com 拒绝本次 Web 自动登录；账号密码未必错误，可能是短时频繁登录或站点风控，请稍后重试", true)
		}
	}
	if regexp.MustCompile(`(?is)<input\b[^>]*type\s*=\s*["']password["']`).MatchString(markup) {
		return errCode("mail_web_login_rejected", "mail.com 将本次请求退回登录页；账号密码未必错误，可能是短时频繁登录或站点风控，请稍后重试", true)
	}
	return nil
}

func mailNavigatorSID(rawURL string, jar http.CookieJar) string {
	parsed, _ := url.Parse(rawURL)
	if parsed != nil {
		if sid := strings.TrimSpace(parsed.Query().Get("sid")); sid != "" {
			return sid
		}
		if fragment, err := url.ParseQuery(parsed.Fragment); err == nil {
			if sid := strings.TrimSpace(fragment.Get("sid")); sid != "" {
				return sid
			}
		}
	}
	if decoded, err := url.QueryUnescape(rawURL); err == nil {
		if match := regexp.MustCompile(`(?i)(?:[?&#]|\b)sid=([^&#\s]+)`).FindStringSubmatch(decoded); len(match) == 2 {
			return strings.TrimSpace(match[1])
		}
	}
	if jar != nil {
		for _, endpoint := range []string{"https://navigator-lxa.mail.com/", "https://mail.com/"} {
			cookieURL, _ := url.Parse(endpoint)
			for _, cookie := range jar.Cookies(cookieURL) {
				if strings.EqualFold(cookie.Name, "sid") && strings.TrimSpace(cookie.Value) != "" {
					return strings.TrimSpace(cookie.Value)
				}
			}
		}
	}
	return ""
}
func mailLoginFormParams(source, pageURL string) (url.Values, error) {
	values := url.Values{}
	re := regexp.MustCompile(`(?is)<input\b[^>]*>`)
	for _, tag := range re.FindAllString(source, -1) {
		name := htmlAttribute(tag, "name")
		if name != "" {
			values.Set(name, html.UnescapeString(htmlAttribute(tag, "value")))
		}
	}
	if values.Get("service") == "" {
		values.Set("service", "oauth2")
	}
	if values.Get("successURL") == "" {
		parsed, _ := url.Parse(pageURL)
		ctx := parsed.Query().Get("authcode-context")
		if ctx == "" {
			return nil, errors.New("mail.com login page missing authcode-context")
		}
		values.Set("successURL", mailOAuthBaseURL+"/authcode?authcode-context="+url.QueryEscape(ctx))
		values.Set("loginFailedURL", "https://mlogin.mail.com/oauth2/?status=login-failed&authcode-context="+url.QueryEscape(ctx))
		values.Set("loginErrorURL", "https://mlogin.mail.com/loginapplication/error/loginerror")
	}
	return values, nil
}
func htmlAttribute(tag, name string) string {
	re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(name) + `\s*=\s*["']([^"']*)["']`)
	match := re.FindStringSubmatch(tag)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}
func randomHex(size int) string {
	data := make([]byte, size)
	_, _ = rand.Read(data)
	return hex.EncodeToString(data)
}
func containsStringFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
