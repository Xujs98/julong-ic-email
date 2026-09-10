package app

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

const mailAliasBatchMax = 10

type mailAliasCreateFailure struct {
	Index     int    `json:"index"`
	AccountID string `json:"account_id,omitempty"`
	Account   string `json:"account,omitempty"`
	Address   string `json:"address,omitempty"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable,omitempty"`
}

func (s *Server) publicMailAccount(account MailAccount) publicMailAccount {
	return publicMailAccount{
		ID: account.ID, OwnerID: account.OwnerID, Owner: s.ownerName(account.OwnerID),
		Label: account.Label, Email: account.Email, Status: account.Status,
		LastSyncAt: formatTime(account.LastSyncAt), CreatedAt: formatTime(account.CreatedAt), UpdatedAt: formatTime(account.UpdatedAt),
	}
}

func (s *Server) canAccessMailAccount(r *http.Request, account MailAccount) bool {
	if s.isAdminRequest(r) {
		return true
	}
	ownerID := scopedOwnerID(r, s.store)
	return ownerID == "" || constantTimeEqual(ownerID, account.OwnerID)
}

func (s *Server) handleListMailAccounts(w http.ResponseWriter, r *http.Request) {
	accounts := s.scopedState(r).MailAccounts
	out := make([]publicMailAccount, 0, len(accounts))
	for _, account := range accounts {
		out = append(out, s.publicMailAccount(account))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "accounts": out})
}

func (s *Server) handleCreateMailAccount(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Label    string `json:"label"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	candidate := MailAccount{OwnerID: requestOwnerID(r, s.store), Label: strings.TrimSpace(payload.Label), Email: strings.ToLower(strings.TrimSpace(payload.Email)), Password: strings.TrimSpace(payload.Password)}
	if candidate.Email == "" || candidate.Password == "" {
		writeError(w, http.StatusBadRequest, errCode("mail_credentials_missing", "请输入 mail.com 账号与密码", false))
		return
	}
	existingAccounts := s.store.MailAccountsForOwner(candidate.OwnerID)
	for _, existing := range existingAccounts {
		if strings.EqualFold(existing.Email, candidate.Email) {
			writeError(w, http.StatusConflict, errCode("mail_account_exists", "mail.com 账号已存在", false))
			return
		}
	}
	domains, err := s.mailAliasDomains(r.Context(), candidate)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(domains) == 0 {
		writeError(w, http.StatusBadGateway, errCode("mail_alias_domains_empty", "Web 登录成功，但 mail.com 未返回可用别名域名", true))
		return
	}
	if err := s.checkMailIMAP(r.Context(), candidate); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	account, err := s.store.AddMailAccountForOwner(candidate.OwnerID, candidate.Label, candidate.Email, candidate.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"success": true, "account": s.publicMailAccount(account), "alias_domains": domains,
		"verification": map[string]any{"web_alias": true, "imap": true, "alias_domain_count": len(domains)},
	})
}

func (s *Server) handleDeleteMailAccount(w http.ResponseWriter, r *http.Request) {
	account, ok := s.store.FindMailAccountByID(r.PathValue("id"))
	if !ok || !s.canAccessMailAccount(r, account) {
		writeError(w, http.StatusNotFound, errCode("mail_account_not_found", "mail.com 账号不存在", false))
		return
	}
	if err := s.store.DeleteMailAccountForOwner(account.OwnerID, account.ID); err != nil {
		var coded codedError
		if errors.As(err, &coded) && coded.code == "mail_account_has_mailboxes" {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true, "account_id": account.ID})
}

func (s *Server) handleMailAliasDomains(w http.ResponseWriter, r *http.Request) {
	account, ok := s.store.FindMailAccountByID(r.URL.Query().Get("account_id"))
	if !ok || !s.canAccessMailAccount(r, account) {
		writeError(w, http.StatusNotFound, errCode("mail_account_not_found", "mail.com 账号不存在", false))
		return
	}
	domains, err := s.mailAliasDomains(r.Context(), account)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "account": s.publicMailAccount(account), "domains": domains})
}

func (s *Server) handleCreateMailAlias(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID     string `json:"account_id"`
		RandomAccount bool   `json:"random_account"`
		Address       string `json:"address"`
		Local         string `json:"local"`
		Domain        string `json:"domain"`
		Label         string `json:"label"`
		Note          string `json:"note"`
		Count         int    `json:"count"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if payload.Count == 0 {
		payload.Count = 1
	}
	if payload.Count < 1 || payload.Count > mailAliasBatchMax {
		writeError(w, http.StatusBadRequest, errCode("mail_alias_count_invalid", "生成数量需为 1-10", false))
		return
	}
	accounts := make([]MailAccount, 0)
	if payload.RandomAccount {
		ownerID := requestOwnerID(r, s.store)
		if ownerID != "" {
			accounts = append(accounts, s.store.MailAccountsForOwner(ownerID)...)
		} else {
			accounts = append(accounts, s.scopedState(r).MailAccounts...)
		}
	} else {
		account, ok := s.store.FindMailAccountByID(payload.AccountID)
		if !ok || !s.canAccessMailAccount(r, account) {
			writeError(w, http.StatusNotFound, errCode("mail_account_not_found", "mail.com 账号不存在", false))
			return
		}
		accounts = append(accounts, account)
	}
	if len(accounts) == 0 {
		writeError(w, http.StatusNotFound, errCode("mail_account_not_found", "没有可用于随机生成的 MAIL 账号", false))
		return
	}
	localTemplate, domain := mailAliasTemplateParts(payload.Address, payload.Local, payload.Domain)
	if localTemplate == "" || domain == "" {
		writeError(w, http.StatusBadRequest, errCode("invalid_mail_alias", "请填写别名前缀并选择有效域名", false))
		return
	}
	if payload.Count > 1 && !strings.Contains(localTemplate, "[随机]") {
		writeError(w, http.StatusBadRequest, errCode("mail_alias_template_required", "批量生成时别名前缀必须包含 [随机]", false))
		return
	}
	if _, _, _, err := normalizeMailAliasAddress(strings.ReplaceAll(localTemplate, "[随机]", "abcdefgh") + "@" + domain); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	mailboxes := make([]publicMailbox, 0, payload.Count)
	failures := make([]mailAliasCreateFailure, 0)
	for index := 0; index < payload.Count; index++ {
		account := accounts[0]
		if payload.RandomAccount {
			accountIndex, err := randomIndex(len(accounts))
			if err != nil {
				failures = append(failures, newMailAliasCreateFailure(index+1, MailAccount{}, "", err))
				continue
			}
			account = accounts[accountIndex]
		}
		local := localTemplate
		if strings.Contains(local, "[随机]") {
			randomPart, err := randomAlphaNumeric(8)
			if err != nil {
				failures = append(failures, newMailAliasCreateFailure(index+1, account, "", err))
				continue
			}
			local = strings.ReplaceAll(local, "[随机]", randomPart)
		}
		_, _, address, err := normalizeMailAliasAddress(local + "@" + domain)
		if err != nil {
			failures = append(failures, newMailAliasCreateFailure(index+1, account, address, err))
			continue
		}
		if _, exists := s.store.FindMailboxByEmail(address); exists {
			failures = append(failures, newMailAliasCreateFailure(index+1, account, address, errCode("mailbox_exists", "邮箱已存在", false)))
			continue
		}
		createdAddress, err := s.createMailAlias(r.Context(), account, address)
		if err != nil {
			failures = append(failures, newMailAliasCreateFailure(index+1, account, address, err))
			continue
		}
		label := strings.TrimSpace(payload.Label)
		if label == "" {
			label = "MAIL-" + time.Now().Format("0102-150405")
		}
		mailbox, err := s.store.AddMailboxForOwnerProvider(account.OwnerID, account.ID, MailboxProviderMail, label, createdAddress, payload.Note)
		if err != nil {
			s.rollbackMailAlias(r.Context(), account, mailbox, createdAddress)
			failures = append(failures, newMailAliasCreateFailure(index+1, account, createdAddress, err))
			continue
		}
		updated, updateErr := s.store.SetMailboxRemoteIdentity(mailbox.ID, createdAddress, "MAIL")
		if updateErr != nil {
			s.rollbackMailAlias(r.Context(), account, mailbox, createdAddress)
			failures = append(failures, newMailAliasCreateFailure(index+1, account, createdAddress, updateErr))
			continue
		}
		mailbox = updated
		mailboxes = append(mailboxes, s.publicMailbox(r, mailbox))
	}

	if len(mailboxes) == 0 {
		message := "MAIL 别名生成失败"
		retryable := false
		status := http.StatusBadGateway
		if len(failures) > 0 {
			message = failures[0].Message
			retryable = failures[0].Retryable
			if failures[0].Code == "internal_error" {
				status = http.StatusInternalServerError
			}
		}
		writeJSON(w, status, map[string]any{"success": false, "code": "mail_alias_batch_failed", "message": message, "retryable": retryable, "created": 0, "failed": len(failures), "failures": failures})
		return
	}
	status := http.StatusCreated
	if len(failures) > 0 {
		status = http.StatusMultiStatus
	}
	response := map[string]any{"success": true, "mailboxes": mailboxes, "created": len(mailboxes), "failed": len(failures), "failures": failures, "mailbox": mailboxes[0], "html_url": mailboxes[0].HTMLLinkURL, "api_url": mailboxes[0].APIURL}
	writeJSON(w, status, response)
}

func mailAliasTemplateParts(address, local, domain string) (string, string) {
	address = strings.ToLower(strings.TrimSpace(address))
	local = strings.ToLower(strings.TrimSpace(local))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if address != "" {
		if at := strings.LastIndex(address, "@"); at > 0 {
			return address[:at], address[at+1:]
		}
	}
	return local, domain
}

func newMailAliasCreateFailure(index int, account MailAccount, address string, err error) mailAliasCreateFailure {
	failure := mailAliasCreateFailure{Index: index, AccountID: account.ID, Account: account.Email, Address: address, Code: "internal_error", Message: err.Error()}
	var coded codedError
	if errors.As(err, &coded) {
		failure.Code = coded.code
		failure.Message = coded.message
		failure.Retryable = coded.retryable
	}
	return failure
}

func (s *Server) rollbackMailAlias(ctx context.Context, account MailAccount, mailbox Mailbox, address string) {
	if mailbox.ID != "" {
		if err := s.store.DeleteMailbox(mailbox.ID); err != nil {
			s.logger.Warn("local mail.com mailbox rollback failed", "mailbox_id", mailbox.ID, "err", err)
		}
	}
	if s.deleteMailAlias != nil {
		if err := s.deleteMailAlias(ctx, account, address); err != nil {
			s.logger.Warn("mail.com alias rollback failed", "account_id", account.ID, "address", address, "err", err)
		}
	}
}

func (s *Server) handleSyncMailAliases(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		AccountID string `json:"account_id"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	accounts := s.scopedState(r).MailAccounts
	if strings.TrimSpace(payload.AccountID) != "" {
		filtered := accounts[:0]
		for _, account := range accounts {
			if constantTimeEqual(account.ID, payload.AccountID) {
				filtered = append(filtered, account)
			}
		}
		accounts = filtered
	}
	if len(accounts) == 0 {
		writeError(w, http.StatusNotFound, errCode("mail_account_not_found", "mail.com 账号不存在", false))
		return
	}
	total := 0
	results := make([]map[string]any, 0, len(accounts))
	state := s.scopedState(r)
	for _, account := range accounts {
		mailboxes := mailboxesForMailAccount(state.Mailboxes, account.ID)
		synced, err := s.syncMailAccountMailboxes(r.Context(), account, mailboxes, time.Now().Add(-24*time.Hour), allMailboxMessagesKeyword, 100)
		result := map[string]any{"account_id": account.ID, "email": account.Email, "synced": synced}
		if err != nil {
			result["error"] = err.Error()
		} else {
			total += synced
		}
		results = append(results, result)
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "synced": total, "results": results})
}

func mailboxesForMailAccount(mailboxes []Mailbox, accountID string) []Mailbox {
	out := make([]Mailbox, 0)
	for _, mailbox := range mailboxes {
		if mailbox.ProviderKind() == MailboxProviderMail && constantTimeEqual(mailbox.AccountID, accountID) {
			out = append(out, mailbox)
		}
	}
	return out
}

func (s *Server) syncMailAccountMailboxes(ctx context.Context, account MailAccount, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (int, error) {
	if len(mailboxes) == 0 {
		return 0, nil
	}
	syncKeyword := keyword
	if s.store.SystemSettings().StoreAllMessages {
		syncKeyword = allMailboxMessagesKeyword
	}
	messagesByMailbox, lastUID, err := s.syncMailAliases(ctx, account, mailboxes, after, syncKeyword, maxMessages)
	if err != nil {
		return 0, err
	}
	synced := 0
	now := time.Now()
	for _, mailbox := range mailboxes {
		latestAt := mailbox.LastSyncAt
		mailboxUID := mailbox.LastSyncUID
		for _, message := range messagesByMailbox[mailbox.ID] {
			if !s.store.SystemSettings().StoreAllMessages && extractOTP(message.Subject+"\n"+message.Body) == "" {
				continue
			}
			remoteID := strings.TrimSpace(message.RemoteID)
			if remoteID == "" && message.UID != "" {
				remoteID = "mail:" + message.UID
			}
			_, created, upsertErr := s.store.UpsertMessageContent(mailbox.ID, remoteID, "mail", message.Subject, message.From, message.Body, message.HTMLBody, message.ReceivedAt)
			if upsertErr != nil {
				return synced, upsertErr
			}
			if created {
				synced++
			}
			if message.ReceivedAt.After(latestAt) {
				latestAt = message.ReceivedAt
				mailboxUID = firstNonEmpty(message.UID, remoteID)
			}
		}
		if latestAt.IsZero() {
			latestAt = now
		}
		if mailboxUID == "" {
			mailboxUID = lastUID
		}
		if _, err := s.store.SetMailboxSyncCursor(mailbox.ID, latestAt, mailboxUID); err != nil {
			return synced, err
		}
	}
	_, _ = s.store.SetMailAccountSyncAt(account.ID, now)
	return synced, nil
}
