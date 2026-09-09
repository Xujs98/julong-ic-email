package app

import (
	"context"
	"net/http"
	"strings"
	"time"
)

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
	account, err := s.store.AddMailAccountForOwner(candidate.OwnerID, candidate.Label, candidate.Email, candidate.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	domains := []string{"mail.com", "email.com", "usa.com", "post.com", "myself.com", "workmail.com"}
	if s.mailAliasDomains != nil {
		if detected, detectErr := s.mailAliasDomains(r.Context(), account); detectErr == nil && len(detected) > 0 {
			domains = detected
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "account": s.publicMailAccount(account), "alias_domains": domains})
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
		AccountID string `json:"account_id"`
		Address   string `json:"address"`
		Local     string `json:"local"`
		Domain    string `json:"domain"`
		Label     string `json:"label"`
		Note      string `json:"note"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	account, ok := s.store.FindMailAccountByID(payload.AccountID)
	if !ok || !s.canAccessMailAccount(r, account) {
		writeError(w, http.StatusNotFound, errCode("mail_account_not_found", "mail.com 账号不存在", false))
		return
	}
	address := strings.ToLower(strings.TrimSpace(payload.Address))
	if address == "" {
		address = strings.ToLower(strings.TrimSpace(payload.Local)) + "@" + strings.ToLower(strings.TrimSpace(payload.Domain))
	}
	if _, ok := s.store.FindMailboxByEmail(address); ok {
		writeError(w, http.StatusBadRequest, errCode("mailbox_exists", "邮箱已存在", false))
		return
	}
	createdAddress, err := s.createMailAlias(r.Context(), account, address)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	label := strings.TrimSpace(payload.Label)
	if label == "" {
		label = "MAIL-" + time.Now().Format("0102-150405")
	}
	mailbox, err := s.store.AddMailboxForOwnerProvider(account.OwnerID, account.ID, MailboxProviderMail, label, createdAddress, payload.Note)
	if err != nil {
		// The remote alias was already created. Best-effort cleanup keeps the
		// local/remote records consistent when persisting the mailbox fails.
		if mailbox.ID != "" {
			if deleteErr := s.store.DeleteMailbox(mailbox.ID); deleteErr != nil {
				s.logger.Warn("local mail.com mailbox rollback failed", "mailbox_id", mailbox.ID, "err", deleteErr)
			}
		}
		if s.deleteMailAlias != nil {
			if deleteErr := s.deleteMailAlias(r.Context(), account, createdAddress); deleteErr != nil {
				s.logger.Warn("mail.com alias rollback failed", "account_id", account.ID, "address", createdAddress, "err", deleteErr)
			}
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	mailbox, _ = s.store.SetMailboxRemoteIdentity(mailbox.ID, createdAddress, "MAIL")
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "mailbox": s.publicMailbox(r, mailbox), "html_url": s.publicMailbox(r, mailbox).HTMLLinkURL, "api_url": s.mailboxAPIURL(r, mailbox)})
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
