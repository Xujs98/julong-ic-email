package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	mailMobileOAuthClientID = "mailcom_mailapp_android"
	mailMobileRedirectURI   = "com.mail.androidmail.redirect://authorization_code_grant"
	mailMobileOAuthAuth     = "Basic bWFpbGNvbV9tYWlsYXBwX2FuZHJvaWQ6a2luMmxTU2tVUXRRQ0NsWG9YZklOaEp1bUc2SmQwM0taNVdMN05KOQ=="
	mailMobileScope         = "mailbox_user_full_access mailbox_user_status_access hsp_user_full_access onlinestorage_user_meta_read onlinestorage_user_meta_write foo bar"
	mailMobileUserAgent     = "mailcom.android.androidmail/9.8.0 Dalvik/2.1.0 (Linux; U; Android 13; SM-S908E Build/TQ2B.230505.005.A1)"
	mailMobileWebUserAgent  = "Mozilla/5.0 (Linux; Android 13; SM-S908E Build/TQ2B.230505.005.A1; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Mobile Safari/537.36 [APPNME/mailcom.android.androidmail;APPVS/9.8.0;APPTNME/andall]"
	mailMobileMIMEFolders   = "application/vnd.ui.trinity.folders-v5+json"
	mailMobileMIMEMessages  = "application/vnd.ui.trinity.messages+json"
	mailMobileMIMEBody      = "text/vnd.ui.insecure+html; removeCharsetMetaInfo=true"
	mailMobileMobSIBaseURL  = "https://mobsi.mail.com/rest/MobSI"
	mailMobileHSP2BaseURL   = "https://hsp2.mail.com/service/msgsrv/Mailbox/primaryMailbox"
)

type mailMobileSession struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type mailMobileOAuthResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type mailMobileStringList []string

func (values *mailMobileStringList) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*values = list
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err != nil {
		return err
	}
	if strings.TrimSpace(single) == "" {
		*values = nil
	} else {
		*values = []string{single}
	}
	return nil
}

type mailMobileFolder struct {
	FolderIdentifier string             `json:"folderIdentifier"`
	Attribute        mailMobileFolderAt `json:"attribute"`
	Folders          []mailMobileFolder `json:"folders"`
}

type mailMobileFolderAt struct {
	FolderType string `json:"folderType"`
}

type mailMobileFoldersResponse struct {
	Folders []mailMobileFolder `json:"folders"`
}

type mailMobileMessage struct {
	MailURI   string              `json:"mailURI"`
	Attribute mailMobileMessageAt `json:"attribute"`
	Header    mailMobileHeader    `json:"mailHeader"`
}

type mailMobileMessageAt struct {
	MailIdentifier string `json:"mailIdentifier"`
}

type mailMobileHeader struct {
	From    string               `json:"from"`
	To      mailMobileStringList `json:"to"`
	CC      mailMobileStringList `json:"cc"`
	BCC     mailMobileStringList `json:"bcc"`
	Subject string               `json:"subject"`
	Date    int64                `json:"date"`
}

type mailMobileMessagesResponse struct {
	Mail []mailMobileMessage `json:"mail"`
}

func (c *MailClient) CheckMobileAPI(ctx context.Context, account MailAccount) error {
	_, err := c.mobileAPIRequest(ctx, account, http.MethodHead, mailMobileMobSIBaseURL+"/UserData", "application/json")
	return err
}

func (c *MailClient) SyncAliasesMobile(ctx context.Context, account MailAccount, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, string, error) {
	if maxMessages <= 0 {
		maxMessages = 50
	}
	if maxMessages > 200 {
		maxMessages = 200
	}
	aliases := make(map[string]string, len(mailboxes))
	afterByMailbox := make(map[string]time.Time, len(mailboxes))
	now := time.Now()
	for _, mailbox := range mailboxes {
		if id, email := strings.TrimSpace(mailbox.ID), normalizeICloudIMAPEmail(mailbox.Email); id != "" && email != "" {
			aliases[id] = email
			afterByMailbox[id] = mailboxSyncAfter(mailbox, after, now)
		}
	}
	if len(aliases) == 0 {
		return map[string][]ICloudSyncedMessage{}, "", nil
	}

	folders, err := c.mobileFolders(ctx, account)
	if err != nil {
		return nil, "", err
	}
	var candidates []mailMobileMessage
	seen := make(map[string]struct{})
	for _, folder := range folders {
		folderType := strings.ToUpper(strings.TrimSpace(folder.Attribute.FolderType))
		if folder.FolderIdentifier == "" || folderType == "TRASH" || folderType == "DRAFTS" || folderType == "OUTBOX" {
			continue
		}
		messages, listErr := c.mobileFolderMessages(ctx, account, folder.FolderIdentifier, maxMessages)
		if listErr != nil {
			return nil, "", listErr
		}
		for _, message := range messages {
			id := mailMobileResourceID(firstNonEmpty(message.Attribute.MailIdentifier, message.MailURI), "Mail")
			if id == "" {
				continue
			}
			if len(matchingMailboxIDs(mailMobileRecipients(message.Header), aliases)) == 0 {
				continue
			}
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			message.Attribute.MailIdentifier = id
			candidates = append(candidates, message)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Header.Date > candidates[j].Header.Date
	})
	if len(candidates) > maxMessages {
		candidates = candidates[:maxMessages]
	}

	out := make(map[string][]ICloudSyncedMessage, len(aliases))
	lastID := ""
	for _, candidate := range candidates {
		id := candidate.Attribute.MailIdentifier
		if lastID == "" {
			lastID = id
		}
		matchedMailboxIDs := matchingMailboxIDs(mailMobileRecipients(candidate.Header), aliases)
		if len(matchedMailboxIDs) == 0 {
			continue
		}
		receivedAt := mailMobileTime(candidate.Header.Date, now)
		freshMailboxIDs := matchedMailboxIDs[:0]
		for _, mailboxID := range matchedMailboxIDs {
			if threshold := afterByMailbox[mailboxID]; threshold.IsZero() || !receivedAt.Before(threshold) {
				freshMailboxIDs = append(freshMailboxIDs, mailboxID)
			}
		}
		if len(freshMailboxIDs) == 0 {
			continue
		}
		bodyBytes, bodyErr := c.mobileAPIRequest(ctx, account, http.MethodGet, mailMobileHSP2BaseURL+"/Mail/"+url.PathEscape(id)+"/Body?absoluteURI=false", mailMobileMIMEBody)
		if bodyErr != nil {
			return nil, "", bodyErr
		}
		htmlBody := string(bodyBytes)
		plainBody := normalizeMailBody(htmlBody)
		if !shouldIncludeSyncedMessage(candidate.Header.Subject+"\n"+plainBody, keyword) {
			continue
		}
		message := ICloudSyncedMessage{
			RemoteID:   "mail:" + id,
			UID:        id,
			Subject:    strings.TrimSpace(candidate.Header.Subject),
			From:       strings.TrimSpace(candidate.Header.From),
			Body:       plainBody,
			HTMLBody:   htmlBody,
			ReceivedAt: receivedAt,
		}
		for _, mailboxID := range freshMailboxIDs {
			out[mailboxID] = append(out[mailboxID], message)
		}
	}
	for mailboxID := range out {
		sortMessagesByReceivedAt(out[mailboxID])
	}
	return out, lastID, nil
}

func (c *MailClient) mobileFolders(ctx context.Context, account MailAccount) ([]mailMobileFolder, error) {
	data, err := c.mobileAPIRequest(ctx, account, http.MethodGet, mailMobileHSP2BaseURL+"/folders?absoluteURI=false", mailMobileMIMEFolders)
	if err != nil {
		return nil, err
	}
	var response mailMobileFoldersResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, errCode("mail_mobile_response_invalid", "mail.com 移动端文件夹响应格式异常", true)
	}
	return flattenMailMobileFolders(response.Folders), nil
}

func (c *MailClient) mobileFolderMessages(ctx context.Context, account MailAccount, folderID string, amount int) ([]mailMobileMessage, error) {
	query := url.Values{"absoluteURI": {"false"}, "orderBy": {"INTERNALDATE desc"}, "amount": {fmt.Sprint(amount)}, "tagsShowAll": {"true"}}
	endpoint := mailMobileHSP2BaseURL + "/Folder/" + url.PathEscape(mailMobileResourceID(folderID, "Folder")) + "/Mail?" + query.Encode()
	data, err := c.mobileAPIRequest(ctx, account, http.MethodGet, endpoint, mailMobileMIMEMessages)
	if err != nil {
		return nil, err
	}
	var response mailMobileMessagesResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, errCode("mail_mobile_response_invalid", "mail.com 移动端邮件列表响应格式异常", true)
	}
	return response.Mail, nil
}

func (c *MailClient) mobileAPIRequest(ctx context.Context, account MailAccount, method, endpoint, accept string) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.mobileAccessToken(ctx, account)
		if err != nil {
			return nil, err
		}
		req, _ := http.NewRequestWithContext(ctx, method, endpoint, nil)
		setMailMobileHeaders(req)
		req.Header.Set("Accept", accept)
		req.Header.Set("Authorization", "Bearer "+token)
		response, requestErr := c.client.Do(req)
		if requestErr != nil {
			return nil, errCode("mail_mobile_request_failed", "mail.com 移动端邮件接口请求失败："+requestErr.Error(), true)
		}
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		response.Body.Close()
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.expireMobileSession(account.Email)
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, errCode("mail_mobile_request_rejected", fmt.Sprintf("mail.com 移动端邮件接口返回 HTTP %d", response.StatusCode), response.StatusCode >= 500)
		}
		return data, nil
	}
	return nil, errCode("mail_mobile_login_failed", "mail.com 移动端邮件接口登录失效，请重新绑定账号", false)
}

func (c *MailClient) mobileAccessToken(ctx context.Context, account MailAccount) (string, error) {
	email := normalizeICloudIMAPEmail(account.Email)
	c.mobileMu.Lock()
	defer c.mobileMu.Unlock()
	if session := c.mobileSessions[email]; session.AccessToken != "" && (session.ExpiresAt.IsZero() || time.Until(session.ExpiresAt) > time.Minute) {
		return session.AccessToken, nil
	}
	if session := c.mobileSessions[email]; session.RefreshToken != "" {
		refreshed, err := c.mobileRefresh(ctx, session.RefreshToken)
		if err == nil {
			c.mobileSessions[email] = refreshed
			return refreshed.AccessToken, nil
		}
		delete(c.mobileSessions, email)
	}
	session, err := c.mobileLogin(ctx, account)
	if err != nil {
		return "", err
	}
	c.mobileSessions[email] = session
	return session.AccessToken, nil
}

func (c *MailClient) invalidateMobileSession(email string) {
	c.mobileMu.Lock()
	delete(c.mobileSessions, normalizeICloudIMAPEmail(email))
	c.mobileMu.Unlock()
}

func (c *MailClient) expireMobileSession(email string) {
	c.mobileMu.Lock()
	session := c.mobileSessions[normalizeICloudIMAPEmail(email)]
	session.AccessToken = ""
	session.ExpiresAt = time.Time{}
	c.mobileSessions[normalizeICloudIMAPEmail(email)] = session
	c.mobileMu.Unlock()
}

func (c *MailClient) mobileLogin(ctx context.Context, account MailAccount) (mailMobileSession, error) {
	if strings.TrimSpace(account.Password) == "" {
		return mailMobileSession{}, errCode("mail_mobile_login_failed", "mail.com 移动端邮件接口登录缺少账号密码", false)
	}
	flow := c.newMobileAuthFlow()
	verifier := mailMobileRandom(48)
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	state := mailMobileRandom(48)
	authorize, _ := url.Parse(mailOAuthBaseURL + "/authorize")
	query := authorize.Query()
	query.Set("client_id", mailMobileOAuthClientID)
	query.Set("redirect_uri", mailMobileRedirectURI)
	query.Set("response_type", "code")
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("login_hint", account.Email)
	query.Set("code_challenge_method", "S256")
	authorize.RawQuery = query.Encode()

	response, err := flow.webRequest(ctx, authorize.String(), http.MethodGet, "", "", mailMobileWebUserAgent)
	if err != nil {
		return mailMobileSession{}, err
	}
	loginAppURL, err := redirectURL(response, authorize.String())
	if err != nil {
		return mailMobileSession{}, err
	}
	loginApp, parseErr := url.Parse(loginAppURL)
	if parseErr != nil || loginApp.Query().Get("authcode-context") == "" {
		return mailMobileSession{}, errCode("mail_mobile_login_failed", "mail.com 移动端登录未返回授权上下文", true)
	}
	authcodeContext := loginApp.Query().Get("authcode-context")
	page, err := flow.webRequest(ctx, loginAppURL, http.MethodGet, "", "", mailMobileWebUserAgent)
	if err != nil {
		return mailMobileSession{}, err
	}
	page.Body.Close()

	failedURL, _ := url.Parse("https://auth.mail.com/loginapp/oauth2")
	failedQuery := failedURL.Query()
	failedQuery.Set("status", "login_failed")
	failedQuery.Set("login_hint", account.Email)
	failedQuery.Set("authcode-context", authcodeContext)
	failedURL.RawQuery = failedQuery.Encode()
	form := url.Values{
		"password":       {account.Password},
		"service":        {"oauth2"},
		"successURL":     {mailOAuthBaseURL + "/authcode?authcode-context=" + url.QueryEscape(authcodeContext)},
		"loginFailedURL": {failedURL.String()},
		"loginErrorURL":  {"https://auth.mail.com/login/error"},
		"statistics":     {},
		"username":       {account.Email},
	}
	loginResponse, err := flow.webRequestWithReferer(ctx, "https://login.mail.com/login", http.MethodPost, form.Encode(), "https://auth.mail.com", loginAppURL, mailMobileWebUserAgent)
	if err != nil {
		return mailMobileSession{}, err
	}
	authcodeURL, err := redirectURL(loginResponse, "https://login.mail.com/")
	if err != nil {
		return mailMobileSession{}, err
	}
	authcodeResponse, err := flow.webRequest(ctx, authcodeURL, http.MethodGet, "", "", mailMobileWebUserAgent)
	if err != nil {
		return mailMobileSession{}, err
	}
	appRedirect, err := redirectURL(authcodeResponse, authcodeURL)
	if err != nil {
		return mailMobileSession{}, err
	}
	callback, parseErr := url.Parse(appRedirect)
	if parseErr != nil || callback.Query().Get("code") == "" || callback.Query().Get("state") != state {
		return mailMobileSession{}, errCode("mail_mobile_login_failed", "mail.com 移动端 OAuth 未返回有效授权码", true)
	}
	token, err := flow.mobileOAuthToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {callback.Query().Get("code")},
		"redirect_uri":  {mailMobileRedirectURI},
		"client_id":     {mailMobileOAuthClientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		return mailMobileSession{}, err
	}
	if token.AccessToken == "" || token.RefreshToken == "" {
		return mailMobileSession{}, errCode("mail_mobile_login_failed", "mail.com 移动端 OAuth 未返回完整登录令牌", true)
	}
	refreshed, err := flow.mobileRefresh(ctx, token.RefreshToken)
	if err != nil {
		return mailMobileSession{}, err
	}
	return refreshed, nil
}

func (c *MailClient) mobileRefresh(ctx context.Context, refreshToken string) (mailMobileSession, error) {
	token, err := c.mobileOAuthToken(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "scope": {mailMobileScope}})
	if err != nil {
		return mailMobileSession{}, err
	}
	if token.AccessToken == "" {
		return mailMobileSession{}, errCode("mail_mobile_login_failed", "mail.com 移动端会话刷新失败", true)
	}
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}
	return mailMobileSession{AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: mailMobileExpiry(token.ExpiresIn)}, nil
}

func (c *MailClient) mobileOAuthToken(ctx context.Context, form url.Values) (mailMobileOAuthResponse, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, mailOAuthBaseURL+"/token", strings.NewReader(form.Encode()))
	setMailMobileHeaders(req)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Authorization", mailMobileOAuthAuth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	response, err := c.client.Do(req)
	if err != nil {
		return mailMobileOAuthResponse{}, errCode("mail_mobile_login_failed", "mail.com 移动端令牌请求失败："+err.Error(), true)
	}
	defer response.Body.Close()
	var token mailMobileOAuthResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&token); err != nil {
		return mailMobileOAuthResponse{}, errCode("mail_mobile_login_failed", "mail.com 移动端令牌响应格式异常", true)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || token.AccessToken == "" {
		message := firstNonEmpty(strings.TrimSpace(token.ErrorDescription), strings.TrimSpace(token.Error), fmt.Sprintf("HTTP %d", response.StatusCode))
		return mailMobileOAuthResponse{}, errCode("mail_mobile_login_failed", "mail.com 移动端邮件接口登录失败："+message, false)
	}
	return token, nil
}

func (c *MailClient) newMobileAuthFlow() *MailClient {
	jar, _ := cookiejar.New(nil)
	client := newMailHTTPClient(jar, c.client.Transport)
	return &MailClient{client: client, mobileSessions: make(map[string]mailMobileSession)}
}

func setMailMobileHeaders(req *http.Request) {
	req.Header.Set("Accept-Charset", "utf-8")
	req.Header.Set("Accept-Language", "en-IN,en-GB;q=0.9,en;q=0.8")
	req.Header.Set("User-Agent", mailMobileUserAgent)
	req.Header.Set("X-Ui-App", "mailcom.android.androidmail/9.8.0")
}

func flattenMailMobileFolders(folders []mailMobileFolder) []mailMobileFolder {
	var out []mailMobileFolder
	for _, folder := range folders {
		out = append(out, folder)
		out = append(out, flattenMailMobileFolders(folder.Folders)...)
	}
	return out
}

func mailMobileRecipients(header mailMobileHeader) string {
	addresses := append([]string{}, header.To...)
	addresses = append(addresses, header.CC...)
	addresses = append(addresses, header.BCC...)
	return strings.Join(addresses, "\n")
}

func mailMobileResourceID(input, resource string) string {
	decoded, err := url.QueryUnescape(strings.TrimSpace(input))
	if err == nil {
		input = decoded
	}
	marker := "/" + resource + "/"
	if index := strings.LastIndex(input, marker); index >= 0 {
		input = input[index+len(marker):]
	}
	input = strings.TrimPrefix(input, "../../"+resource+"/")
	input = strings.TrimPrefix(input, resource+"/")
	if index := strings.IndexAny(input, "?#"); index >= 0 {
		input = input[:index]
	}
	return strings.Trim(input, "/ ")
}

func mailMobileTime(value int64, fallback time.Time) time.Time {
	if value <= 0 {
		return fallback
	}
	if value > 100000000000 {
		return time.UnixMilli(value)
	}
	return time.Unix(value, 0)
}

func mailMobileRandom(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return randomHex(size)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func mailMobileExpiry(expiresIn int) time.Time {
	if expiresIn <= 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(expiresIn) * time.Second)
}
