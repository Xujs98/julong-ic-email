package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestForwardingInboundStoresAndDeduplicatesMail(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.AddDomainForOwner("", "接收域名", "example.test")
	if err != nil {
		t.Fatal(err)
	}
	mailboxes, err := store.AddDomainMailboxesForOwner("", domain.ID, "转发批次", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	settings := store.SystemSettings()
	settings.ForwardingEnabled = true
	settings.ForwardingDomain = domain.Name
	settings.ForwardingSecret = "test-forwarding-secret"
	if _, err := store.SaveSystemSettings(settings); err != nil {
		t.Fatal(err)
	}

	raw := []byte("Message-ID: <forwarding-test@example.test>\r\nFrom: Sender <sender@example.net>\r\nSubject: Verification 654321\r\nDate: Thu, 20 Aug 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYour verification code is 654321\r\n")
	payload := map[string]any{
		"from":       "sender@example.net",
		"to":         mailboxes[0].Email,
		"message_id": "<forwarding-test@example.test>",
		"raw_base64": base64.StdEncoding.EncodeToString(raw),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().Unix()
	// The test signs a real current Unix timestamp.
	unixHeader := strconv.FormatInt(timestamp, 10)
	mac := hmac.New(sha256.New, []byte(settings.ForwardingSecret))
	_, _ = mac.Write([]byte(unixHeader + "\n"))
	_, _ = mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))

	handler := NewServer(Config{}, store, discardLogger())
	request := httptest.NewRequest(http.MethodPost, "/api/v1/forwarding/inbound", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Julong-Forwarding-Timestamp", unixHeader)
	request.Header.Set("X-Julong-Forwarding-Signature", "sha256="+signature)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("inbound status=%d body=%s", response.Code, response.Body.String())
	}
	if got := store.MessagesForMailbox(mailboxes[0].ID); len(got) != 1 || !strings.Contains(got[0].Body, "654321") || got[0].Source != "cloudflare_forwarding" {
		t.Fatalf("stored forwarding messages=%+v", got)
	}

	duplicate := httptest.NewRecorder()
	requestDuplicate := httptest.NewRequest(http.MethodPost, "/api/v1/forwarding/inbound", bytes.NewReader(body))
	requestDuplicate.Header = request.Header.Clone()
	handler.ServeHTTP(duplicate, requestDuplicate)
	if duplicate.Code != http.StatusOK || len(store.MessagesForMailbox(mailboxes[0].ID)) != 1 {
		t.Fatalf("duplicate status=%d body=%s messages=%d", duplicate.Code, duplicate.Body.String(), len(store.MessagesForMailbox(mailboxes[0].ID)))
	}
}
