package app

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestExtractOTP(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "openai subject", text: "Your OpenAI code is 123456", want: "123456"},
		{name: "chinese", text: "验证码：654321，请勿泄露", want: "654321"},
		{name: "fallback", text: "Use 246810 to continue.", want: "246810"},
		{name: "zero invalid", text: "code 000000", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractOTP(tt.text); got != tt.want {
				t.Fatalf("extractOTP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBrandAssetsAreServed(t *testing.T) {
	handler := NewServer(Config{}, newTestStore(t), discardLogger())
	for _, tt := range []struct {
		path        string
		contentType string
		prefix      string
	}{
		{path: "/favicon.ico", contentType: "image/x-icon", prefix: "\x00\x00\x01\x00"},
		{path: "/logo.png", contentType: "image/png", prefix: "\x89PNG\r\n\x1a\n"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", tt.path, rr.Code, http.StatusOK)
			}
			if got := rr.Header().Get("Content-Type"); got != tt.contentType {
				t.Fatalf("GET %s content type = %q, want %q", tt.path, got, tt.contentType)
			}
			if !strings.HasPrefix(rr.Body.String(), tt.prefix) {
				t.Fatalf("GET %s body does not start with expected signature", tt.path)
			}
		})
	}

	for _, name := range []string{"templates/landing.html", "templates/index.html", "templates/login.html", "templates/manage.html", "templates/mailbox.html", "templates/mailbox_expired.html"} {
		data, err := webFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(data), `rel="icon"`) {
			t.Fatalf("%s does not reference favicon", name)
		}
	}
}

func TestComposeDefaultsToRollingLatestImage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`docker.io/qq1371446705/julong-ic-email:latest`,
		`pull_policy: always`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("compose rolling update configuration missing %q", want)
		}
	}
}

func TestMailboxHTMLPageShowsDayHourMinuteSecondCountdown(t *testing.T) {
	data, err := webFS.ReadFile("templates/mailbox.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`剩余 ${d}天 ${h}时 ${m}分 ${s}秒`,
		`setTTL(data.ttl_seconds)`,
		`Date.now()-ttlMeasuredAt`,
		`setInterval(renderTTL,1000)`,
		`setRefreshSeconds(data.refresh_seconds)`,
		`setTimeout(loadData,refreshSeconds*1000)`,
		`id="refreshInfo"`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("mailbox HTML countdown source missing %q", want)
		}
	}
}

func TestMailboxTableHeaderStaysAboveRows(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`.mailbox-table-wrap {`,
		`isolation: isolate;`,
		`.mailbox-table thead { position: relative; z-index: 2; }`,
		`.mailbox-table th {`,
		`position: sticky;`,
		`z-index: 3;`,
		`background-color: var(--th-bg);`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("mailbox table header CSS missing %q", want)
		}
	}
}

func TestThemePickerTemplateUsesCommercialCustomControl(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`id="themePicker"`,
		`toggleThemePicker(event)`,
		`class="theme-option-grid"`,
		`data-theme-option="aurora"`,
		`class="theme-select-native"`,
		`THEME_LABELS`,
		`aria-selected`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("theme picker source missing %q", want)
		}
	}
	if strings.Contains(source, `<label class="theme-select"`) {
		t.Fatal("native theme select wrapper should be replaced by custom picker")
	}
}

func TestAppleAccountKeepAliveTemplateShowsAutomaticRetry(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`.manage-refresh-clock.retrying`,
		`data-retrying=`,
		`新接口重试`,
		`apple_account_keep_alive_failures`,
		`连续失败 ${failureCount} 次`,
		`系统${refreshAt ? `,
		`自动重试`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("apple account keepalive retry source missing %q", want)
		}
	}
	if strings.Contains(source, `新接口保活：已停止`) {
		t.Fatal("failed Apple Account login state should keep retrying instead of showing keepalive stopped")
	}
}

func TestConfiguredAdminPathIsOnlyLoginAndRegistrationEntry(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK || rr.Header().Get("Location") != "" || !strings.Contains(rr.Body.String(), "欢迎使用矩龙邮箱") || strings.Contains(rr.Body.String(), "/manage") {
		t.Fatalf("unauthenticated home exposed entry: status=%d location=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/manage", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "注册并登录") {
		t.Fatalf("default entry page = %d body=%s", rr.Code, rr.Body.String())
	}

	for _, path := range []string{"/login", "/api/auth/login", "/api/auth/register", "/api/auth/register-status"} {
		rr = httptest.NewRecorder()
		method := http.MethodGet
		if path == "/api/auth/login" || path == "/api/auth/register" {
			method = http.MethodPost
		}
		handler.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("legacy auth path %s = %d body=%s, want 404", path, rr.Code, rr.Body.String())
		}
	}

	adminCookie, _ := registerTestUser(t, handler, "entry-admin", "admin123")
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "管理总览") {
		t.Fatalf("authenticated home = %d body=%s", rr.Code, rr.Body.String())
	}
	settings := store.SystemSettings()
	settings.AdminPath = "/julongyx"
	if _, err := store.SaveSystemSettings(settings); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "/julongyx") || strings.Contains(rr.Body.String(), "登录") || strings.Contains(rr.Body.String(), "注册") {
		t.Fatalf("public landing exposed custom entry: status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/julongyx", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "注册并登录") {
		t.Fatalf("custom entry page = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/julongyx/register-status", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"registration_enabled":true`) {
		t.Fatalf("custom registration status = %d body=%s", rr.Code, rr.Body.String())
	}

	for _, path := range []string{"/manage", "/manage/login", "/manage/register"} {
		rr = httptest.NewRecorder()
		method := http.MethodGet
		if strings.HasSuffix(path, "/login") || strings.HasSuffix(path, "/register") {
			method = http.MethodPost
		}
		handler.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("old entry path %s = %d body=%s, want 404", path, rr.Code, rr.Body.String())
		}
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/julongyx/login", strings.NewReader(`{"username":"entry-admin","password":"admin123"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("custom entry login = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/julongyx/register", strings.NewReader(`{"username":"entry-user","password":"user123"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("custom entry registration = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/julongyx", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "账号数据管理") {
		t.Fatalf("authenticated custom entry = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMailboxMessagesAreScopedAndSorted(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "mailbox-message-viewer", "multi123")
	target, err := store.AddMailboxForOwner(user.ID, "", "target", "target@example.icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.AddMailboxForOwner(user.ID, "", "other", "other@example.icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	if _, err := store.AddMessage(target.ID, "older message", "old@example.com", "old body", older); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(target.ID, "newer message", "new@example.com", "new body", newer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(other.ID, "other mailbox", "other@example.com", "other body", newer.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes/"+target.ID+"/messages", nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list messages status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Messages []publicMessage `json:"messages"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Messages) != 2 {
		t.Fatalf("messages len = %d, want 2", len(body.Messages))
	}
	if body.Messages[0].Subject != "newer message" || body.Messages[1].Subject != "older message" {
		t.Fatalf("message order = %+v, want newest first", body.Messages)
	}
	for _, message := range body.Messages {
		if message.MailboxID != target.ID {
			t.Fatalf("message mailbox = %q, want %q", message.MailboxID, target.ID)
		}
	}
}

func TestMailboxTableMessageColumnUsesDialog(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`class="mailbox-message-count-button"`,
		`openMailboxMessages('${row.id}')`,
		`id="mailboxMessagesModal"`,
		`/api/mailboxes/${encodeURIComponent(id)}/messages`,
		`buildMailboxMessageDocument`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("mailbox message dialog source missing %q", want)
		}
	}
}

func TestSystemSettingsTemplateIncludesMailRetentionAndExpiryDeleteSwitches(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`settings-panel`,
		`ADMINISTRATION · POLICY CENTER`,
		`class="settings-summary-card"`,
		`class="settings-metrics"`,
		`class="settings-control-grid"`,
		`class="settings-save-bar"`,
		`id="settingsAccessMetric"`,
		`id="verificationOnly"`,
		`id="htmlExpiryDeleteMailbox"`,
		`id="htmlLinkLifecycleEnabled"`,
		`id="htmlPageMessageLimit"`,
		`id="htmlPageRefreshSeconds"`,
		`id="htmlLinkTTLSeconds"`,
		`id="htmlLinkTTLPreview"`,
		`id="domainSMTPEnabled"`,
		`id="domainSMTPHost"`,
		`id="domainSMTPPort"`,
		`id="domainSMTPMaxMessageBytes"`,
		`markSystemSettingsDirty`,
		`updateSystemSettingsPreview`,
		`applySystemSettings`,
		`verification_only:`,
		`html_link_ttl_seconds:`,
		`html_page_message_limit:`,
		`html_page_refresh_seconds:`,
		`html_expiry_delete_mailbox:`,
		`html_link_lifecycle_enabled:`,
		`domain_smtp_enabled:`,
		`domain_smtp_port:`,
		`formatTTLDuration`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("system settings template source missing %q", want)
		}
	}
}

func TestManagementWorkbenchCommercialUIAndIndependentLogs(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`class="commercial-hero"`,
		`class="commercial-hero-metrics"`,
		`class="commercial-section-label"`,
		`id="headerMore" class="header-more"`,
		`class="header-more-account"`,
		`class="header-more-links"`,
		`function closeOpenPopovers(except = null)`,
		`document.addEventListener('click', event => {`,
		`class="mailbox-column-grid"`,
		`id="mailboxColumnVisibleCount"`,
		`class="mailbox-column-foot"`,
		`/api/system-settings/theme`,
		`.app-shell { grid-template-columns: clamp(218px, 12vw, 246px) minmax(0, 1fr);`,
		`overflow: hidden; scrollbar-width: none;`,
		`.sidebar::-webkit-scrollbar { display: none; }`,
		`grid-auto-rows: clamp(48px, 6.1vh, 56px);`,
		`data-view="logs" onclick="setActiveView('logs', this)"`,
		`id="globalLogPanel" class="view-section panel global-log-panel logs-panel" data-view="logs"`,
		`logs: ['运行日志', '集中查看运行、创建和定时任务记录。']`,
		`if (panel) panel.hidden = activeView !== 'logs';`,
		`data-log-category="runtime"`,
		`data-log-category="create"`,
		`data-log-category="schedule"`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("commercial workbench/log center source missing %q", want)
		}
	}
}

func TestMailboxInventoryAndOutboundUseCommercialResponsiveWorkbench(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`id="mailboxWorkspace" class="view-section panel mailbox-workspace"`,
		`data-mailbox-mode="inventory"`,
		`class="toolbar list-toolbar mailbox-operations"`,
		`id="mailboxWorkbenchKicker"`,
		`id="mailboxWorkbenchTitle"`,
		`id="mailboxWorkbenchMode"`,
		`class="mailbox-control-group"`,
		`class="mailbox-search-input-wrap"`,
		`id="mailboxSearchClear"`,
		`aria-label="清空搜索"`,
		`function updateMailboxSearchClearButton()`,
		`function handleMailboxSearchKeydown(event)`,
		`clearButton.hidden = !input || !input.value.trim();`,
		`dataset.mailboxMode = outbound ? 'outbound' : 'inventory'`,
		`OUTBOUND DELIVERY CENTER`,
		`.mailbox-control-stack { grid-column: 1 / -1;`,
		`flex-wrap: wrap;`,
		`.mailbox-workspace[data-mailbox-mode="outbound"] .mailbox-operations`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("commercial mailbox workbench source missing %q", want)
		}
	}
	if strings.Contains(source, `<button onclick="clearMailboxSearch()">清空搜索</button>`) {
		t.Fatal("mailbox clear search action should live inside the search input instead of the business action row")
	}
}

func TestSystemThemePersistsAndPublicMailboxUsesIt(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "theme-admin", "admin123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/system-settings/theme", strings.NewReader(`{"theme":"violet"}`))
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || store.SystemSettings().Theme != "violet" {
		t.Fatalf("save theme = %d body=%s settings=%+v", rr.Code, rr.Body.String(), store.SystemSettings())
	}

	mailbox, err := store.AddMailbox("", "theme", "theme@example.com")
	if err != nil {
		t.Fatal(err)
	}
	link, ok := store.MailboxHTMLLinkForMailbox(mailbox.ID)
	if !ok {
		t.Fatal("mailbox HTML link missing")
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mailbox/"+link.Token+"/data", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"theme":"violet"`) {
		t.Fatalf("public mailbox theme = %d body=%s", rr.Code, rr.Body.String())
	}

	data, err := webFS.ReadFile("templates/mailbox.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{`function applySystemTheme(theme)`, `applySystemTheme(data.theme)`, `document.documentElement.dataset.theme=normalized`} {
		if !strings.Contains(source, want) {
			t.Fatalf("public mailbox theme source missing %q", want)
		}
	}
}

func TestMailboxTableSupportsOutboundWorkflow(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`data-view="outbound"`,
		`id="navOutboundCount"`,
		`id="mailboxBatchOutboundButton"`,
		`batchOutboundMailboxes()`,
		`batchReturnMailboxes()`,
		`params.set('status', 'outbound')`,
		`params.set('exclude_status', 'outbound')`,
		`outbound:'出库'`,
		`id="mailboxExportAllButton"`,
		`id="mailboxBatchExportButton"`,
		`id="mailboxExportModal"`,
		`openMailboxExport('batch')`,
		`selectedOutboundExportFields`,
		`selectedOutboundExportFormat`,
		`loadAllOutboundMailboxesForExport`,
		`outboundExportCSV`,
		`outboundExportTXT`,
		`.join('----')`,
		`outboundExportJSON`,
		`outboundExportContent`,
		`copyOutboundMailboxes`,
		`mailboxExportCopy`,
		`inventoryMailboxSearch`,
		`outboundMailboxSearch`,
		`activeMailboxSearchValue`,
		`name="mailboxExportFormat" value="txt"`,
		`name="mailboxExportFormat" value="csv"`,
		`name="mailboxExportFormat" value="json"`,
		`id="mailboxHTMLStateFilter"`,
		`data-html-state-filter="all"`,
		`data-html-state-filter="activated"`,
		`data-html-state-filter="unactivated"`,
		`data-html-state-filter="expired"`,
		`setMailboxHTMLStateFilter('expired')`,
		`params.set('html_state', activeMailboxHTMLStateFilter)`,
		`id="mailboxCleanupExpiredButton"`,
		`cleanupExpiredHTMLMailboxes()`,
		`/api/mailboxes/html-expired/cleanup`,
		`.mailbox-html-state-filter[hidden]`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("mailbox outbound workflow source missing %q", want)
		}
	}
}

func TestMailboxOutboundBatchSearchAndColumnPickerTemplate(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`/api/mailboxes/batch-outbound`,
		`inputLabel: '出库批次'`,
		`留空时自动使用当前 13 位时间戳`,
		`data-mailbox-column="batch"`,
		`data-mailbox-column-toggle="batch"`,
		`mailboxColumnStorageKey`,
		`toggleMailboxColumn`,
		`[批次] && [已激活]`,
		`![已激活]`,
		`renderMailboxBatch(row)`,
		`id="mailboxBatchOverviewButton"`,
		`id="mailboxBatchesModal"`,
		`function openOutboundBatchOverview()`,
		`function selectOutboundBatchFromOverview(batch)`,
		`setMailboxBatchSearch(batch)`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("outbound batch/search/column template missing %q", want)
		}
	}
}

func TestMailboxTableUsesViewSpecificTime(t *testing.T) {
	data, err := webFS.ReadFile("templates/index.html")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`id="mailboxCreatedColumnTitle">创建时间</th>`,
		`id="mailboxCreatedColumnLabel">创建时间`,
		`class="mailbox-created-cell"`,
		`activeView === 'outbound' ? row.updated_at : row.created_at`,
		`createdColumnTitle = outbound ? '更新时间' : '创建时间'`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("mailbox view-specific time source missing %q", want)
		}
	}
}

func TestMailboxListSortsByViewTimeAndKeepsCreatedAt(t *testing.T) {
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.Local)
	mailboxes := []Mailbox{
		{ID: "mbx_000001", Email: "older@icloud.com", CreatedAt: base, UpdatedAt: base.Add(2 * time.Hour)},
		{ID: "mbx_000002", Email: "newer@icloud.com", CreatedAt: base.Add(time.Hour), UpdatedAt: base.Add(time.Hour)},
	}
	sortMailboxesForList(mailboxes)
	if mailboxes[0].ID != "mbx_000002" || mailboxes[1].ID != "mbx_000001" {
		t.Fatalf("mailbox order = [%s %s], want newest creation first", mailboxes[0].ID, mailboxes[1].ID)
	}
	outbound := []Mailbox{
		{ID: "mbx_000003", Email: "older-outbound@icloud.com", Status: StatusOutbound, CreatedAt: base.Add(3 * time.Hour), UpdatedAt: base.Add(3 * time.Hour)},
		{ID: "mbx_000004", Email: "newly-updated-outbound@icloud.com", Status: StatusOutbound, CreatedAt: base, UpdatedAt: base.Add(4 * time.Hour)},
	}
	sortOutboundMailboxesForList(outbound)
	if outbound[0].ID != "mbx_000004" || outbound[1].ID != "mbx_000003" {
		t.Fatalf("outbound order = [%s %s], want newest update first", outbound[0].ID, outbound[1].ID)
	}

	store := newTestStore(t)
	created, err := store.AddMailbox("", "created", "created-once@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	originalCreatedAt := created.CreatedAt
	updated, err := store.SetMailboxStatus(created.ID, nil, nil, StatusUsed, "later operation")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.CreatedAt.Equal(originalCreatedAt) {
		t.Fatalf("created_at changed after status update: got %s want %s", updated.CreatedAt, originalCreatedAt)
	}
}

func TestMailboxListSearchCountsAndOutboundSorting(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "list-search-owner", "search123")
	older := createTestMailboxWithCookie(t, handler, cookie, "older", "older-search@icloud.com")
	newer := createTestMailboxWithCookie(t, handler, cookie, "newer", "newer-search@icloud.com")
	other := createTestMailboxWithCookie(t, handler, cookie, "other", "other@icloud.com")

	if _, err := store.SetMailboxesOutbound([]string{older.ID, newer.ID}, "search-sort", "test outbound"); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 19, 10, 0, 0, 0, time.Local)
	store.mu.Lock()
	for i := range store.state.Mailboxes {
		switch store.state.Mailboxes[i].ID {
		case older.ID:
			store.state.Mailboxes[i].CreatedAt = base.Add(2 * time.Hour)
			store.state.Mailboxes[i].UpdatedAt = base.Add(time.Hour)
		case newer.ID:
			store.state.Mailboxes[i].CreatedAt = base
			store.state.Mailboxes[i].UpdatedAt = base.Add(3 * time.Hour)
		}
	}
	err := store.saveLocked()
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	list := func(query url.Values) (struct {
		Mailboxes  []publicMailbox      `json:"mailboxes"`
		Groups     []publicMailboxGroup `json:"groups"`
		Pagination publicPagination     `json:"pagination"`
	}, string) {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?"+query.Encode(), nil)
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list %s = %d body=%s", query.Encode(), rr.Code, rr.Body.String())
		}
		var body struct {
			Mailboxes  []publicMailbox      `json:"mailboxes"`
			Groups     []publicMailboxGroup `json:"groups"`
			Pagination publicPagination     `json:"pagination"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body, rr.Body.String()
	}

	searchBody, _ := list(url.Values{"exclude_status": {StatusOutbound}, "search": {"other"}, "page": {"1"}, "page_size": {"10"}})
	if searchBody.Pagination.Total != 1 || searchBody.Pagination.TotalAll != 1 || len(searchBody.Groups) != 1 || searchBody.Groups[0].Count != 1 || len(searchBody.Mailboxes) != 1 || searchBody.Mailboxes[0].ID != other.ID {
		t.Fatalf("search list = %+v, want one matching mailbox", searchBody)
	}

	outboundBody, _ := list(url.Values{"status": {StatusOutbound}, "page": {"1"}, "page_size": {"10"}})
	if len(outboundBody.Mailboxes) != 2 || outboundBody.Mailboxes[0].ID != newer.ID || outboundBody.Mailboxes[1].ID != older.ID {
		t.Fatalf("outbound list order = %+v, want newest update first", outboundBody.Mailboxes)
	}
}

func testIMAPSession(ownerID, accountID, email string) ICloudSession {
	email = normalizeICloudIMAPEmail(email)
	if email == "" {
		email = "receiver@example.com"
	}
	return ICloudSession{
		OwnerID:   ownerID,
		AccountID: accountID,
		AppleID:   email,
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateICloudIMAP,
			Host:              defaultICloudIMAPHost,
			Origin:            "imaps://" + defaultICloudIMAPHost,
			SavedAt:           time.Now(),
			IMAPEmail:         email,
			IMAPUsername:      email,
			IMAPHost:          defaultICloudIMAPHost,
			IMAPPort:          defaultICloudIMAPPort,
			IMAPAppPassword:   "app-specific-password",
			LastCheckedAt:     time.Now(),
			LastCheckOK:       true,
			LastStatusMessage: "取码登录正常",
		}},
	}
}

func TestGenerateAppleHashcash(t *testing.T) {
	challenge := "0123456789abcdef0123456789abcdef"
	now := time.Date(2026, 6, 29, 14, 2, 22, 0, time.UTC)
	got, err := generateAppleHashcash(8, challenge, now)
	if err != nil {
		t.Fatalf("generateAppleHashcash() error = %v", err)
	}
	parts := strings.Split(got, ":")
	if len(parts) != 6 {
		t.Fatalf("hashcash parts = %d, want 6 in %q", len(parts), got)
	}
	if parts[0] != "1" || parts[1] != "8" || parts[2] != "20260629140222" || parts[3] != challenge || parts[4] != "" || parts[5] == "" {
		t.Fatalf("hashcash format mismatch: %q", got)
	}
	sum := sha1.Sum([]byte(got))
	if leadingZeroBits(sum[:]) < 8 {
		t.Fatalf("hashcash does not satisfy requested difficulty")
	}
}

func TestAppleAccountFDClientInfoUsesBrowserFingerprint(t *testing.T) {
	var info map[string]string
	if err := json.Unmarshal([]byte(appleAccountFDClientInfo(appleAccountManageUserAgent)), &info); err != nil {
		t.Fatal(err)
	}
	if info["U"] != appleAccountManageUserAgent {
		t.Fatalf("U = %q, want manage user agent", info["U"])
	}
	if info["L"] != appleAccountManageLanguage || info["Z"] != appleAccountManageGMTOffset || info["V"] != "1.1" {
		t.Fatalf("unexpected locale fields: %+v", info)
	}
	if len(info["F"]) < 80 {
		t.Fatalf("F length = %d, want browser fingerprint", len(info["F"]))
	}
}

func TestAppleDomainRedirectMapsDomainToHost(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{domain: "iCloud.com", want: "www.icloud.com"},
		{domain: "www.icloud.com", want: "www.icloud.com"},
		{domain: "https://www.icloud.com.cn/", want: "www.icloud.com.cn"},
		{domain: "example.com", want: ""},
	}
	for _, tt := range tests {
		if got := appleDomainToHost(tt.domain); got != tt.want {
			t.Fatalf("appleDomainToHost(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestParseAppleDomainRedirect(t *testing.T) {
	redirect, ok := parseAppleDomainRedirect(http.StatusFound, []byte(`{"domainToUse":"iCloud.com"}`))
	if !ok {
		t.Fatal("parseAppleDomainRedirect did not detect redirect")
	}
	if redirect.Host != "www.icloud.com" || redirect.DomainToUse != "iCloud.com" {
		t.Fatalf("redirect = %+v, want www.icloud.com", redirect)
	}

	if _, ok := parseAppleDomainRedirect(http.StatusOK, []byte(`{"domainToUse":"iCloud.com"}`)); ok {
		t.Fatal("parseAppleDomainRedirect detected non-redirect status")
	}
}

func TestAppleAuthSessionSwitchHost(t *testing.T) {
	session := &appleAuthSession{Endpoints: appleAuthEndpointsForHost("www.icloud.com.cn")}
	if !session.switchHost("www.icloud.com") {
		t.Fatal("switchHost returned false, want true")
	}
	if session.Endpoints.Host != "www.icloud.com" || !strings.Contains(session.Endpoints.Auth, "idmsa.apple.com/appleauth") {
		t.Fatalf("endpoints after switch = %+v", session.Endpoints)
	}
	if session.switchHost("www.icloud.com") {
		t.Fatal("switchHost returned true for same host")
	}
}

func TestAppleHostForAccountCountry(t *testing.T) {
	tests := []struct {
		country string
		want    string
	}{
		{country: "", want: ""},
		{country: "CHN", want: "www.icloud.com.cn"},
		{country: "CN", want: "www.icloud.com.cn"},
		{country: "USA", want: "www.icloud.com"},
		{country: "sgp", want: "www.icloud.com"},
	}
	for _, tt := range tests {
		if got := appleHostForAccountCountry(tt.country); got != tt.want {
			t.Fatalf("appleHostForAccountCountry(%q) = %q, want %q", tt.country, got, tt.want)
		}
	}
}

func TestAppleAuthSessionRedirectForAccountCountry(t *testing.T) {
	session := &appleAuthSession{
		Endpoints:      appleAuthEndpointsForHost("www.icloud.com.cn"),
		AccountCountry: "USA",
	}
	redirect, ok := session.redirectForAccountCountry()
	if !ok {
		t.Fatal("redirectForAccountCountry returned ok=false")
	}
	if redirect.Host != "www.icloud.com" || redirect.DomainToUse != "iCloud.com" {
		t.Fatalf("redirect = %+v, want www.icloud.com", redirect)
	}

	session = &appleAuthSession{
		Endpoints:      appleAuthEndpointsForHost("www.icloud.com.cn"),
		AccountCountry: "CHN",
	}
	if _, ok := session.redirectForAccountCountry(); ok {
		t.Fatal("redirectForAccountCountry returned ok=true for matching China host")
	}
}

func TestAppleTransientNetworkErrorDetection(t *testing.T) {
	if !isAppleTransientNetworkError(&url.Error{Op: "Post", URL: "https://setup.icloud.com/setup/ws/1/accountLogin", Err: io.EOF}) {
		t.Fatal("EOF url error should be transient")
	}
	if !isAppleTransientNetworkError(fmt.Errorf("net/http: timeout awaiting response headers")) {
		t.Fatal("timeout should be transient")
	}
	if isAppleTransientNetworkError(errCode("apple_protocol_http_error", "Apple 协议 HTTP 401", true)) {
		t.Fatal("HTTP business error should not be transient")
	}
}

func TestRetryAppleTransientRetriesEOF(t *testing.T) {
	attempts := 0
	err := retryAppleTransient(t.Context(), func() error {
		attempts++
		if attempts < 2 {
			return io.EOF
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestCookieHeaderFiltersByDomainAndExpiry(t *testing.T) {
	cookies := []SessionCookie{
		{Name: "ok", Value: "1", Domain: ".icloud.com.cn", Path: "/"},
		{Name: "other", Value: "2", Domain: ".example.com", Path: "/"},
		{Name: "expired", Value: "3", Domain: ".icloud.com.cn", Path: "/", Expires: 1},
	}
	got := cookieHeader(cookies, "https://p213-maildomainws.icloud.com.cn/v1/hme/generate")
	if got != "ok=1" {
		t.Fatalf("cookieHeader() = %q, want ok=1", got)
	}
}

func TestAppleDebugBodyRedactsSecrets(t *testing.T) {
	got := appleDebugBody([]byte(`{"apiKey":"secret-api","emailAddress":"alias@example.com","nested":{"sessionToken":"secret-token","forwardToEmail":"main@example.com"},"ok":true}`))
	if strings.Contains(got, "secret-api") || strings.Contains(got, "secret-token") || strings.Contains(got, "alias@example.com") || strings.Contains(got, "main@example.com") {
		t.Fatalf("debug body leaked secret: %s", got)
	}
	if !strings.Contains(got, "<redacted>") || !strings.Contains(got, `"ok":true`) {
		t.Fatalf("debug body = %s, want redacted secret and visible safe fields", got)
	}
}

func TestAppleAccountManageFingerprintUsesCapturedLocale(t *testing.T) {
	var info map[string]string
	if err := json.Unmarshal([]byte(appleAccountFDClientInfo("test-agent")), &info); err != nil {
		t.Fatal(err)
	}
	if info["U"] != "test-agent" || info["L"] != appleAccountManageLanguage || info["Z"] != "GMT+08:00" {
		t.Fatalf("fingerprint info = %#v, want zh/GMT+08:00", info)
	}
	if strings.TrimSpace(info["F"]) == "" {
		t.Fatalf("fingerprint info missing compressed fingerprint: %#v", info)
	}
}

func TestAppleAccountAPIErrorTreatsGenericUnauthorizedAsAuthSuspect(t *testing.T) {
	generic := appleAccountAPIError(http.StatusUnauthorized, []byte(`<html><body>401 Unauthorized</body></html>`), "测试阶段")
	if isCodedError(generic, "apple_account_auth_failed") {
		t.Fatalf("generic 401 classified as auth failed: %v", generic)
	}
	if !isCodedError(generic, "apple_account_auth_suspect") {
		t.Fatalf("generic 401 code = %v, want apple_account_auth_suspect", generic)
	}

	expired := appleAccountAPIError(http.StatusUnauthorized, []byte(`{"service_errors":[{"message":"authentication_failed"}]}`), "测试阶段")
	if !isCodedError(expired, "apple_account_auth_failed") {
		t.Fatalf("explicit auth error = %v, want apple_account_auth_failed", expired)
	}
}

func TestLoadConfigPublicCodeSyncSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"mail_watcher_enabled":false,"mail_watcher_poll_ms":2500,"mail_watcher_fetch_limit":6,"mail_watcher_initial_fetch_limit":16,"mail_watcher_lookback_hours":12,"public_fast_sync_wait_ms":250,"public_sync_min_interval_ms":1500,"apple_account_keep_alive_enabled":true,"apple_account_keep_alive_ms":123000}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MailWatcherEnabled {
		t.Fatal("mail watcher enabled = true, want false from config")
	}
	if cfg.MailWatcherPollMS != 2500 || cfg.MailWatcherFetchLimit != 6 || cfg.MailWatcherInitialFetchLimit != 16 || cfg.MailWatcherLookbackHours != 12 {
		t.Fatalf("mail watcher settings = poll:%d fetch:%d initial:%d lookback:%d, want 2500/6/16/12", cfg.MailWatcherPollMS, cfg.MailWatcherFetchLimit, cfg.MailWatcherInitialFetchLimit, cfg.MailWatcherLookbackHours)
	}
	if cfg.PublicFastSyncWaitMS != 250 || cfg.PublicSyncMinIntervalMS != 1500 {
		t.Fatalf("public sync settings = fast:%d min:%d, want 250/1500", cfg.PublicFastSyncWaitMS, cfg.PublicSyncMinIntervalMS)
	}
	if !cfg.AppleAccountKeepAliveEnabled || cfg.AppleAccountKeepAliveMS != 123000 {
		t.Fatalf("apple account keepalive settings = enabled:%t ms:%d, want true/123000", cfg.AppleAccountKeepAliveEnabled, cfg.AppleAccountKeepAliveMS)
	}
}

func TestAppleAccountOperationGateSerializesSameAccount(t *testing.T) {
	release, err := acquireAppleAccountOperationGate(context.Background(), "test-owner:test-account")
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = acquireAppleAccountOperationGate(ctx, "test-owner:test-account")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second gate error = %v, want context deadline", err)
	}
}

func TestICloudEndpointAddsProtocolQuery(t *testing.T) {
	client := NewICloudClient()
	got, err := client.endpoint(ICloudSession{
		PremiumMailBaseURL: "https://p213-maildomainws.icloud.com.cn:443",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
	}, "/v1/hme/generate")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://p213-maildomainws.icloud.com.cn:443/v1/hme/generate?",
		"clientBuildNumber=build",
		"clientMasteringNumber=master",
		"clientId=cid",
		"dsid=123",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("endpoint %q missing %q", got, want)
		}
	}
}

func TestMailGatewayBaseURLFallback(t *testing.T) {
	got, err := mailGatewayBaseURL(ICloudSession{MailBaseURL: "https://p213-mailws.icloud.com.cn:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://p213-mccgateway.icloud.com.cn:443" {
		t.Fatalf("mailGatewayBaseURL() = %q", got)
	}

	got, err = mailGatewayBaseURL(ICloudSession{PremiumMailBaseURL: "https://p213-maildomainws.icloud.com.cn:443"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://p213-mccgateway.icloud.com.cn:443" {
		t.Fatalf("mailGatewayBaseURL() from premium = %q", got)
	}
}

func TestICloudClientMoveRemoteMessagesToTrashAndEmptyTrash(t *testing.T) {
	var sawMove bool
	var sawDestroy bool
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		response := `{}`
		switch r.URL.Path {
		case "/mailws2/v1/geqs/query":
			response = `{"domainObjects":[{"identifier":"31","name":"INBOX","messageCount":1},{"identifier":"53","name":"Deleted Messages","messageCount":1}]}`
		case "/mailws2/v1/message/list":
			if strings.Contains(string(body), `"value":"31"`) {
				response = `{"domainObjects":[{"uid":7,"identifier":"msg-inbox","mboxRef":{"id":"31"}}]}`
			} else if strings.Contains(string(body), `"value":"53"`) {
				response = `{"domainObjects":[{"uid":7,"identifier":"msg-trash","mboxRef":{"id":"53"}}]}`
			}
		case "/mailws2/v1/email/set":
			if strings.Contains(string(body), `"batchUpdate"`) {
				sawMove = true
				response = `{"updated":{"msg-inbox":{"modseq":4}}}`
			} else if strings.Contains(string(body), `"destroy"`) {
				sawDestroy = true
				response = `{"destroyed":["msg-trash"]}`
			}
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(response)),
			Request:    r,
		}, nil
	})}}
	session := ICloudSession{
		MailGatewayBaseURL: "https://p39-mccgateway.icloud.com",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	}
	moved, err := client.MoveRemoteMessagesToTrash(t.Context(), session, []string{"icloud:INBOX:7", "local:bad"})
	if err != nil {
		t.Fatal(err)
	}
	if moved.MovedToTrash != 1 || moved.Skipped != 1 || !sawMove {
		t.Fatalf("moved = %+v sawMove=%v, want moved=1 skipped=1", moved, sawMove)
	}
	destroyed, err := client.EmptyTrash(t.Context(), session)
	if err != nil {
		t.Fatal(err)
	}
	if destroyed != 1 || !sawDestroy {
		t.Fatalf("destroyed=%d sawDestroy=%v, want 1", destroyed, sawDestroy)
	}
}

func TestPublicSessionIncludesLastCheckStatus(t *testing.T) {
	checkedAt := time.Date(2026, 6, 21, 23, 0, 0, 0, time.UTC)
	session := ICloudSession{
		SavedAt:           checkedAt.Add(-time.Hour),
		AppleID:           "user@example.com",
		DSID:              "1234567890",
		IsICloudPlus:      true,
		CanCreateHME:      true,
		Cookies:           []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com.cn", Path: "/"}},
		LastCheckedAt:     checkedAt,
		LastCheckOK:       false,
		LastStatusMessage: "最近检测失败：请重新登录",
	}
	got := publicSession(&session)
	if got.LastCheckedAt != formatTime(checkedAt) {
		t.Fatalf("LastCheckedAt = %q, want %q", got.LastCheckedAt, formatTime(checkedAt))
	}
	if got.LastCheckOK {
		t.Fatalf("LastCheckOK = true, want false")
	}
	if got.LastStatusMessage != session.LastStatusMessage {
		t.Fatalf("LastStatusMessage = %q, want %q", got.LastStatusMessage, session.LastStatusMessage)
	}
}

func TestPublicSessionSeparatesLoginStateKinds(t *testing.T) {
	appleOnly := publicSession(&ICloudSession{
		SavedAt: time.Now(),
		AppleID: "apple@example.com",
		DSID:    "123456",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	})
	if !appleOnly.AppleAccountLoginSaved || !appleOnly.AppleAccountManageReady {
		t.Fatalf("apple account state not exposed: %+v", appleOnly)
	}
	if appleOnly.ICloudWebLoginSaved || appleOnly.NeedsManualLogin {
		t.Fatalf("apple-only state mixed with iCloud web: %+v", appleOnly)
	}

	icloudOnly := publicSession(&ICloudSession{
		SavedAt:      time.Now(),
		AppleID:      "icloud@example.com",
		DSID:         "654321",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	})
	if !icloudOnly.ICloudWebLoginSaved || !icloudOnly.ProviderConfigured {
		t.Fatalf("icloud web state not exposed: %+v", icloudOnly)
	}
	if icloudOnly.AppleAccountLoginSaved || icloudOnly.AppleAccountManageReady {
		t.Fatalf("icloud-only state mixed with apple account: %+v", icloudOnly)
	}
	if icloudOnly.AppleAccountNextRefreshAt != "" || icloudOnly.AppleAccountManageExpiresAt != "" {
		t.Fatalf("icloud-only state should not expose apple account refresh time: %+v", icloudOnly)
	}
}

func TestPublicSessionExposesPerLoginStateCheckStatus(t *testing.T) {
	checkedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	expiresAt := checkedAt.Add(15 * time.Minute)
	session := ICloudSession{
		SavedAt: time.Now(),
		AppleID: "state@example.com",
		LoginStates: []LoginState{
			{
				Kind:              LoginStateAppleAccount,
				Scnt:              "scnt",
				APIKey:            "api-key",
				LastCheckedAt:     checkedAt,
				LastCheckOK:       true,
				LastStatusMessage: "新接口登录态正常",
				ManageExpiresAt:   expiresAt,
			},
			{
				Kind:              LoginStateICloudWeb,
				Cookies:           []SessionCookie{{Name: "icloud", Value: "ok"}},
				LastCheckedAt:     checkedAt,
				LastCheckOK:       false,
				LastStatusMessage: "旧接口登录态异常",
			},
		},
	}
	got := publicSession(&session)
	if !got.AppleAccountLoginChecked || !got.AppleAccountLoginOK || got.AppleAccountLoginStatus != "登录态正常" {
		t.Fatalf("apple account status = checked:%t ok:%t text:%q", got.AppleAccountLoginChecked, got.AppleAccountLoginOK, got.AppleAccountLoginStatus)
	}
	wantNext := checkedAt.Add(appleAccountKeepAliveIntervalForSession(session, appleAccountKeepAliveDefaultInterval))
	if got.AppleAccountManageExpiresAt != formatTime(expiresAt) || got.AppleAccountNextRefreshAt != formatTime(wantNext) {
		t.Fatalf("apple account refresh times = next:%q expires:%q", got.AppleAccountNextRefreshAt, got.AppleAccountManageExpiresAt)
	}
	if !got.ICloudWebLoginChecked || got.ICloudWebLoginOK || got.ICloudWebLoginStatus != "登录态异常" {
		t.Fatalf("icloud web status = checked:%t ok:%t text:%q", got.ICloudWebLoginChecked, got.ICloudWebLoginOK, got.ICloudWebLoginStatus)
	}
}

func TestPublicSessionExposesAppleKeepAliveRetryTimeWhenLoginStateFailed(t *testing.T) {
	checkedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	retryAt := checkedAt.Add(30 * time.Second)
	session := ICloudSession{
		SavedAt: time.Now(),
		AppleID: "failed@example.com",
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "scnt",
			APIKey:            "api-key",
			LastCheckedAt:     checkedAt,
			LastCheckOK:       false,
			LastStatusMessage: "新接口登录态异常",
			KeepAliveFailures: 1,
			KeepAliveRetryAt:  retryAt,
		}},
	}
	got := publicSession(&session)
	if !got.AppleAccountLoginSaved || !got.AppleAccountLoginChecked || got.AppleAccountLoginOK {
		t.Fatalf("apple account failed state not exposed correctly: %+v", got)
	}
	if got.AppleAccountNextRefreshAt != formatTime(retryAt) || got.AppleAccountKeepAliveFailures != 1 {
		t.Fatalf("failed apple account retry = time:%q failures:%d, want %q/1", got.AppleAccountNextRefreshAt, got.AppleAccountKeepAliveFailures, formatTime(retryAt))
	}
}

func TestAppleAccountKeepAliveRoundSavesUpdatedState(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive"
	account, err := store.AddAccountForOwner(ownerID, "KeepAlive", "keepalive@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "keepalive@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "old-scnt",
			APIKey:            "old-key",
			LastCheckedAt:     time.Now().Add(-time.Hour),
			LastCheckOK:       false,
			KeepAliveFailures: 2,
			KeepAliveRetryAt:  time.Now().Add(-time.Minute),
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	var calls int
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		calls++
		state.Scnt = "kept-scnt"
		state.APIKey = "kept-key"
		markAppleAccountManageOK(&state)
		return state, nil
	}

	server.keepAliveAppleAccountRound(context.Background())

	if calls != 1 {
		t.Fatalf("keepalive calls = %d, want 1", calls)
	}
	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("updated session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "kept-scnt" || state.APIKey != "kept-key" || !state.LastCheckOK || state.KeepAliveFailures != 0 || !state.KeepAliveRetryAt.IsZero() {
		t.Fatalf("saved apple account state = %+v ok=%v, want updated keepalive state", state, ok)
	}
}

func TestAppleAccountKeepAliveRoundRetriesFailedLoginState(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-failed"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveFailed", "failed@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "failed@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "scnt",
			APIKey:            "api-key",
			LastCheckedAt:     time.Now().Add(-time.Hour),
			LastCheckOK:       false,
			LastStatusMessage: "新接口登录态异常",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		state.Scnt = "recovered-scnt"
		state.APIKey = "recovered-key"
		markAppleAccountManageOK(&state)
		return state, nil
	}

	server.keepAliveAppleAccountRound(context.Background())

	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("recovered session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || !state.LastCheckOK || state.Scnt != "recovered-scnt" || state.APIKey != "recovered-key" {
		t.Fatalf("retried apple account state = %+v ok=%v, want recovered state", state, ok)
	}
}

func TestAppleAccountKeepAliveRoundSavesTransientFailureForRetry(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-keepalive-transient"
	account, err := store.AddAccountForOwner(ownerID, "KeepAliveTransient", "transient@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	checkedAt := time.Now().Add(-time.Hour)
	session := ICloudSession{
		OwnerID:   ownerID,
		AccountID: account.ID,
		AppleID:   "transient@example.com",
		SavedAt:   time.Now(),
		LoginStates: []LoginState{{
			Kind:          LoginStateAppleAccount,
			Scnt:          "old-scnt",
			APIKey:        "old-key",
			Cookies:       []SessionCookie{{Name: "session", Value: "cookie"}},
			LastCheckedAt: checkedAt,
			LastCheckOK:   true,
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{AppleAccountKeepAliveEnabled: true, AppleAccountKeepAliveMS: 1000}, store, discardLogger())
	server, ok := handler.(*Server)
	if !ok {
		t.Fatalf("handler type = %T, want *Server", handler)
	}
	server.keepAliveAppleAccountState = func(ctx context.Context, state LoginState) (LoginState, error) {
		state.Scnt = "rotated-scnt"
		return state, errors.New("temporary network timeout")
	}

	server.keepAliveAppleAccountRound(context.Background())

	got, ok := store.ICloudSessionForOwnerAccount(ownerID, account.ID)
	if !ok {
		t.Fatal("failed session not found")
	}
	state, ok := appleAccountLoginState(got)
	if !ok || state.LastCheckOK || !state.LastCheckedAt.After(checkedAt) {
		t.Fatalf("saved failed apple account state = %+v ok=%v", state, ok)
	}
	if state.Scnt != "rotated-scnt" || state.APIKey != "old-key" || len(state.Cookies) != 1 {
		t.Fatalf("failed keepalive credentials were not preserved: %+v", state)
	}
	if state.KeepAliveFailures != 1 || state.KeepAliveRetryAt.IsZero() || time.Until(state.KeepAliveRetryAt) < 5*time.Second {
		t.Fatalf("failed keepalive retry schedule = failures:%d retry:%s", state.KeepAliveFailures, state.KeepAliveRetryAt)
	}
	if !strings.Contains(state.LastStatusMessage, "10秒后自动复核") || !strings.Contains(state.LastStatusMessage, "temporary network timeout") {
		t.Fatalf("failed keepalive status = %q", state.LastStatusMessage)
	}
}

func TestAppleAccountKeepAliveScanIntervalPollsBeforeBaseInterval(t *testing.T) {
	if got := appleAccountKeepAliveScanInterval(4 * time.Minute); got != 30*time.Second {
		t.Fatalf("scan interval for 4m = %s, want 30s", got)
	}
	if got := appleAccountKeepAliveScanInterval(12 * time.Second); got != 5*time.Second {
		t.Fatalf("scan interval for 12s = %s, want 5s floor", got)
	}
}

func TestAppleAccountKeepAliveRetryDelayUsesFastBackoff(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 1, want: 10 * time.Second},
		{failures: 2, want: 30 * time.Second},
		{failures: 3, want: time.Minute},
		{failures: 4, want: 2 * time.Minute},
		{failures: 5, want: 4 * time.Minute},
		{failures: 6, want: 5 * time.Minute},
		{failures: 9, want: 5 * time.Minute},
	}
	for _, tt := range tests {
		if got := appleAccountKeepAliveRetryDelay(tt.failures); got != tt.want {
			t.Fatalf("retry delay for %d failures = %s, want %s", tt.failures, got, tt.want)
		}
	}
}

func TestAppleAccountKeepAliveFailureKeepsRecentHealthyStateDuringRecovery(t *testing.T) {
	now := time.Now()
	previous := LoginState{
		Kind:                   LoginStateAppleAccount,
		Scnt:                   "saved-scnt",
		APIKey:                 "saved-key",
		LastCheckedAt:          now.Add(-time.Minute),
		LastCheckOK:            true,
		KeepAliveLastSuccessAt: now.Add(-time.Minute),
	}
	transient := appleAccountKeepAliveFailureState(previous, previous, now, errors.New("temporary timeout"))
	if !transient.LastCheckOK || transient.KeepAliveFailures != 1 || !strings.Contains(transient.LastStatusMessage, "保活恢复中") {
		t.Fatalf("transient recovery state = %+v", transient)
	}
	firstAuth := appleAccountKeepAliveFailureState(previous, previous, now, errCode("apple_account_auth_suspect", "unauthorized", true))
	if !firstAuth.LastCheckOK || firstAuth.KeepAliveAuthFailures != 1 {
		t.Fatalf("first auth verification state = %+v", firstAuth)
	}
	secondAuth := appleAccountKeepAliveFailureState(firstAuth, firstAuth, now.Add(10*time.Second), errCode("apple_account_auth_suspect", "unauthorized", true))
	if secondAuth.LastCheckOK || secondAuth.KeepAliveAuthFailures != 2 || !strings.Contains(secondAuth.LastStatusMessage, "登录态异常") {
		t.Fatalf("confirmed auth failure state = %+v", secondAuth)
	}
}

func TestAppleAccountKeepAliveDueUsesExplicitRetryTime(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	state := LoginState{
		LastCheckedAt:     now.Add(-time.Hour),
		KeepAliveFailures: 1,
		KeepAliveRetryAt:  now.Add(30 * time.Second),
	}
	if appleAccountKeepAliveDue(state, now, time.Second) {
		t.Fatal("keepalive should wait for explicit retry time")
	}
	if !appleAccountKeepAliveDue(state, now.Add(30*time.Second), time.Hour) {
		t.Fatal("keepalive should run when explicit retry time arrives")
	}
}

func TestAppleAccountKeepAliveIntervalRefreshesBeforeShortTokenTTL(t *testing.T) {
	checkedAt := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	session := ICloudSession{LoginStates: []LoginState{{
		Kind:            LoginStateAppleAccount,
		Scnt:            "scnt",
		APIKey:          "key",
		LastCheckedAt:   checkedAt,
		ManageExpiresAt: checkedAt.Add(3 * time.Minute),
	}}}
	if got := appleAccountKeepAliveIntervalForSession(session, 4*time.Minute); got != time.Minute {
		t.Fatalf("adaptive keepalive interval = %s, want 1m", got)
	}
}

func TestPublicViewsExposeFullAppleID(t *testing.T) {
	store := newTestStore(t)
	server := &Server{cfg: Config{PublicBaseURL: "https://mail.example"}, store: store, logger: discardLogger()}
	account, err := store.AddAccountForOwner("owner-full", "Main", "full.user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner("owner-full", account.ID, "Alias", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	gotAccount := server.publicAccount(account)
	if gotAccount.AppleID != "full.user@example.com" {
		t.Fatalf("public account AppleID = %q, want full email", gotAccount.AppleID)
	}

	gotMailbox := server.publicMailbox(httptest.NewRequest(http.MethodGet, "https://panel.example/", nil), mailbox)
	if gotMailbox.AccountAppleID != "full.user@example.com" {
		t.Fatalf("public mailbox account AppleID = %q, want full email", gotMailbox.AccountAppleID)
	}

	gotSession := publicSession(&ICloudSession{
		SavedAt:   time.Now(),
		AccountID: account.ID,
		AppleID:   "session.user@example.com",
	})
	if gotSession.AppleID != "session.user@example.com" {
		t.Fatalf("public session AppleID = %q, want full email", gotSession.AppleID)
	}

	matched := publicSessionForAppleID([]publicICloudSession{gotSession}, "session.user@example.com")
	if matched.AppleID != gotSession.AppleID {
		t.Fatalf("publicSessionForAppleID did not match full email: %+v", matched)
	}
}

func TestStatusReturnsOwnerICloudSessionForAdminUser(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	if err := store.SaveICloudSessionForOwner(adminUser.ID, ICloudSession{
		SavedAt:       time.Now(),
		AppleID:       "admin@example.com",
		DSID:          "12345678908382",
		IsICloudPlus:  true,
		CanCreateHME:  true,
		Cookies:       []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com.cn", Path: "/"}},
		LastCheckOK:   true,
		LastCheckedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		ICloudSession publicICloudSession `json:"icloud_session"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.ICloudSession.Saved || body.ICloudSession.CookieCount != 1 || !body.ICloudSession.ProviderConfigured {
		t.Fatalf("icloud session = %+v, want saved owner session", body.ICloudSession)
	}
}

func TestICloudCreateLimitErrorIsClassified(t *testing.T) {
	err := iCloudAPIError("You have reached the limit of addresses you can create right now. Please try again later.")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "icloud_hme_limit" || !coded.retryable {
		t.Fatalf("coded error = %+v, want icloud_hme_limit retryable", coded)
	}
	if !strings.Contains(err.Error(), "原始返回：You have reached the limit") {
		t.Fatalf("error = %q, want raw limit message", err.Error())
	}
}

func TestAppleAccountAPIErrorIncludesStageHTTPAndRawBody(t *testing.T) {
	err := appleAccountAPIError(http.StatusNotFound, []byte("<html><body>not found</body></html>"), "生成候选隐私邮箱")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "apple_account_api_failed" || !coded.retryable {
		t.Fatalf("coded error = %+v, want apple_account_api_failed retryable", coded)
	}
	message := err.Error()
	for _, want := range []string{"阶段：生成候选隐私邮箱", "HTTP 404", "<html><body>not found</body></html>"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error = %q, want %q", message, want)
		}
	}
}

func TestICloudClientAppleAccountGenerateEmptyIncludesRawBody(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			_, _ = w.Write([]byte(`{"unexpected":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	_, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-current",
			APIKey:          "fresh-key",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err == nil {
		t.Fatal("expected error")
	}
	coded, ok := err.(codedError)
	if !ok || coded.code != "apple_account_generate_empty" {
		t.Fatalf("error = %#v, want apple_account_generate_empty", err)
	}
	message := err.Error()
	for _, want := range []string{"阶段：生成候选隐私邮箱", `原始返回：{"unexpected":true}`} {
		if !strings.Contains(message, want) {
			t.Fatalf("error = %q, want %q", message, want)
		}
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRetriesNetworkErrors(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleAccountManageBaseURL = "https://appleid.test"

	addAttempts := 0
	completeAttempts := 0
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addAttempts++
			if addAttempts < 3 {
				return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: context.DeadlineExceeded}
			}
			return appleAccountTestResponse(r, http.StatusOK, `{"emailAddress":"Retry.Alias@icloud.com"}`), nil
		case "PUT /account/manage/email/private/add/complete":
			completeAttempts++
			return appleAccountTestResponse(r, http.StatusOK, `{"emailAddress":"Retry.Alias@icloud.com","label":"LAB","note":"note","active":true}`), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}}

	remote, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), appleAccountFreshSessionForTest(), "", "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if addAttempts != 3 {
		t.Fatalf("add attempts = %d, want 3", addAttempts)
	}
	if completeAttempts != 1 {
		t.Fatalf("complete attempts = %d, want 1", completeAttempts)
	}
	if remote.Email != "retry.alias@icloud.com" || remote.Origin != "APPLE_ACCOUNT" {
		t.Fatalf("remote = %+v, want retry alias from Apple Account", remote)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountDoesNotRetryHTTPError(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	appleAccountManageBaseURL = "https://appleid.test"

	addAttempts := 0
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addAttempts++
			return appleAccountTestResponse(r, http.StatusInternalServerError, `<html><body>temporary</body></html>`), nil
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	})}}

	_, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), appleAccountFreshSessionForTest(), "", "LAB", "note")
	if err == nil {
		t.Fatal("expected error")
	}
	if addAttempts != 1 {
		t.Fatalf("add attempts = %d, want 1", addAttempts)
	}
	if !isCodedError(err, "apple_account_transient") {
		t.Fatalf("error = %#v, want apple_account_transient", err)
	}
}

func appleAccountFreshSessionForTest() ICloudSession {
	now := time.Now()
	return ICloudSession{
		OwnerID:   "owner-test",
		AccountID: "account-test",
		AppleID:   "apple-test@example.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-current",
			APIKey:          "fresh-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
			Origin:          appleAccountManageOrigin,
		}},
	}
}

func appleAccountTestResponse(r *http.Request, status int, body string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccount(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Apple-I-Request-Context") != "ca" {
			t.Fatalf("request context = %q, want ca", r.Header.Get("X-Apple-I-Request-Context"))
		}
		if r.Header.Get("Origin") != "https://account.apple.com" {
			t.Fatalf("origin = %q, want account.apple.com", r.Header.Get("Origin"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("token api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("manage api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			body, _ := io.ReadAll(r.Body)
			if strings.TrimSpace(string(body)) != "{}" {
				t.Fatalf("add body = %s, want {}", body)
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","newToPrivateEmail":false,"exists":false,"type":"settings","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("complete api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["emailAddress"] != "Candidate.Alias@icloud.com" || body["label"] != "LAB" || body["note"] != "note" {
				t.Fatalf("complete body = %+v", body)
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","label":"LAB","note":"note","id":"abc123","type":"settings","active":false}`))
		case "GET /account/manage/email/private/abc123.em":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("confirm api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","label":"LAB","note":"note","id":"abc123","forwardToEmail":"main@example.com","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Scnt:   "scnt-token",
			APIKey: "stale-key",
		}},
	}, "", "LAB", "note")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "candidate.alias@icloud.com" || remote.Label != "LAB" || remote.AnonymousID != "abc123" || !remote.IsActive || remote.ForwardToEmail != "main@example.com" || remote.Origin != "APPLE_ACCOUNT" {
		t.Fatalf("remote = %+v", remote)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/abc123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "account-key" {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed scnt/api key", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountReusesFreshState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token", "GET /account/manage":
			t.Fatalf("unexpected refresh request %s %s", r.Method, r.URL.Path)
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-current" {
				t.Fatalf("add scnt header = %q, want scnt-current", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("complete api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","id":"fresh123","active":true}`))
		case "GET /account/manage/email/private/fresh123.em":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("confirm api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Fresh.Alias@icloud.com","id":"fresh123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-current",
			APIKey:          "fresh-key",
			LastCheckedAt:   checkedAt,
			ManageExpiresAt: checkedAt.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "fresh.alias@icloud.com" {
		t.Fatalf("remote email = %q, want fresh.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/fresh123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "fresh-key" || !updatedState.LastCheckOK || updatedState.LastCheckedAt.IsZero() || updatedState.LastCheckedAt.Before(checkedAt) {
		t.Fatalf("updated apple account state = %+v ok=%v, want reused fresh state marked ok", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesExpiredManageState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "stale-scnt" {
				t.Fatalf("token scnt header = %q, want stale-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"TTL.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"TTL.Alias@icloud.com","id":"ttl123","active":true}`))
		case "GET /account/manage/email/private/ttl123.em":
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"TTL.Alias@icloud.com","id":"ttl123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "stale-scnt",
			APIKey:          "stale-key",
			LastCheckedAt:   now.Add(-2 * time.Minute),
			ManageExpiresAt: now.Add(-30 * time.Second),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "ttl.alias@icloud.com" {
		t.Fatalf("remote email = %q, want ttl.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/ttl123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "fresh-key" || updatedState.Scnt != "scnt-after-confirm" || !updatedState.LastCheckOK || !updatedState.ManageExpiresAt.After(now) {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed TTL state", updatedState, ok)
	}
}

func TestICloudClientRefreshAppleAccountManageStateUsesBootstrapTTLWhenInitialTokenIsEmpty(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls == 1 {
				if r.Header.Get("scnt") != "start-scnt" {
					t.Fatalf("first token scnt header = %q, want start-scnt", r.Header.Get("scnt"))
				}
				w.Header().Set("scnt", "token-empty-scnt")
				_, _ = w.Write([]byte(`{}`))
				return
			}
			if r.Header.Get("scnt") != "" {
				t.Fatalf("second token scnt header = %q, want empty like browser refresh", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "token-refreshed-scnt")
			_, _ = w.Write([]byte(`{}`))
		case "GET /account/manage/section/privacy":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("privacy page scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("scnt", "page-scnt")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("bootstrap scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "token-refreshed-scnt" {
				t.Fatalf("manage scnt header = %q, want token-refreshed-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	state, err := client.RefreshAppleAccountManageState(t.Context(), LoginState{
		Kind:   LoginStateAppleAccount,
		Origin: ts.URL,
		Scnt:   "start-scnt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.APIKey != "account-key" || state.Scnt != "manage-scnt" || !state.LastCheckOK || !state.ManageExpiresAt.After(now) {
		t.Fatalf("state = %+v, want api key, updated scnt, ok and bootstrap TTL", state)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestICloudClientRefreshAppleAccountManageStateRecoversAfterExpiredToken(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls == 1 {
				if r.Header.Get("scnt") != "expired-scnt" {
					t.Fatalf("first token scnt = %q, want expired-scnt", r.Header.Get("scnt"))
				}
				w.Header().Set("Set-Cookie", "token_recovery=1; Path=/")
				w.Header().Set("scnt", "failed-response-scnt")
				w.WriteHeader(appleAccountHTTPStatusSessionTimeout)
				_, _ = w.Write([]byte(`{"error":"session expired"}`))
				return
			}
			if r.Header.Get("scnt") != "" {
				t.Fatalf("recovery token scnt = %q, want empty", r.Header.Get("scnt"))
			}
			if cookie := r.Header.Get("Cookie"); !strings.Contains(cookie, "token_recovery=1") || !strings.Contains(cookie, "portal_recovery=1") {
				t.Fatalf("recovery token cookie = %q", cookie)
			}
			w.Header().Set("scnt", "recovered-token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/section/privacy":
			if !strings.Contains(r.Header.Get("Cookie"), "token_recovery=1") {
				t.Fatalf("privacy cookie = %q, want failed response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Set-Cookie", "portal_recovery=1; Path=/")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "recovered-token-scnt" {
				t.Fatalf("manage scnt = %q, want recovered-token-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "recovered-manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"recovered-key"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	state, err := client.RefreshAppleAccountManageState(t.Context(), LoginState{
		Kind:   LoginStateAppleAccount,
		Origin: ts.URL,
		Scnt:   "expired-scnt",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	if state.Scnt != "recovered-manage-scnt" || state.APIKey != "recovered-key" || !state.LastCheckOK || len(state.Cookies) != 2 {
		t.Fatalf("recovered state = %+v", state)
	}
}

func TestAppleAccountErrorResponsesPreserveRotatedSessionState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "rotated_cookie="+strings.Trim(strings.ReplaceAll(r.URL.Path, "/", "_"), "_")+"; Path=/")
		w.Header().Set("scnt", "rotated-scnt")
		w.Header().Set("X-Apple-ID-Session-Id", "rotated-session")
		w.WriteHeader(appleAccountHTTPStatusSessionTimeout)
		_, _ = w.Write([]byte(`{"error":"session expired"}`))
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL
	client := &ICloudClient{client: ts.Client()}

	t.Run("manage api", func(t *testing.T) {
		state := LoginState{Kind: LoginStateAppleAccount, Origin: ts.URL, Scnt: "old-scnt"}
		if _, err := client.callAppleAccountRawOnce(t.Context(), &state, "", http.MethodGet, "/account/manage", nil, nil); err == nil {
			t.Fatal("manage API error = nil, want session error")
		}
		if state.Scnt != "rotated-scnt" || state.SessionID != "rotated-session" || len(state.Cookies) != 1 {
			t.Fatalf("manage API error state = %+v", state)
		}
	})

	t.Run("portal", func(t *testing.T) {
		state := LoginState{Kind: LoginStateAppleAccount, Origin: ts.URL, Scnt: "old-scnt"}
		if _, err := client.callAppleAccountPortalOnce(t.Context(), &state, "/bootstrap/portal", "application/json", true, "empty", "cors"); err == nil {
			t.Fatal("portal error = nil, want session error")
		}
		if state.Scnt != "rotated-scnt" || state.SessionID != "rotated-session" || len(state.Cookies) != 1 {
			t.Fatalf("portal error state = %+v", state)
		}
	})
}

func TestICloudClientKeepAliveAppleAccountManageStateTouchesRealManageAPI(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/section/privacy":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("privacy page scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Set-Cookie", "portal_warm=1; Path=/")
			w.Header().Set("scnt", "portal-scnt")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			if !strings.Contains(r.Header.Get("Cookie"), "portal_warm=1") {
				t.Fatalf("bootstrap cookie = %q, want portal_warm", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "bootstrap-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "bootstrap-scnt" {
				t.Fatalf("token scnt header = %q, want bootstrap-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "token-scnt" {
				t.Fatalf("manage scnt header = %q, want token-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "GET /account/manage/forwardemail":
			if r.Header.Get("X-Apple-Api-Key") == "old-key" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"reason":"token_refresh_required"}`))
				return
			}
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("forwardemail api key = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "manage-scnt" {
				t.Fatalf("forwardemail scnt header = %q, want manage-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "touch-scnt")
			_, _ = w.Write([]byte(`{"forwardToEmail":"receiver@icloud.com"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	state, err := client.KeepAliveAppleAccountManageState(t.Context(), LoginState{
		Kind:      LoginStateAppleAccount,
		Origin:    ts.URL,
		Scnt:      "start-scnt",
		APIKey:    "old-key",
		SessionID: "old-session",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"GET /account/manage/forwardemail",
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"GET /account/manage/forwardemail",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	if state.APIKey != "fresh-key" || state.Scnt != "touch-scnt" || state.SessionID != "old-session" || !state.LastCheckOK || state.LastCheckedAt.Before(now) || len(state.Cookies) == 0 {
		t.Fatalf("state = %+v, want touched real manage API state", state)
	}
}

func TestICloudClientKeepAliveUsesLightProbeWhileTokenWorks(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/account/manage/forwardemail":
			if r.Header.Get("X-Apple-Api-Key") != "working-key" {
				t.Fatalf("probe api key = %q", r.Header.Get("X-Apple-Api-Key"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "probe-scnt")
			http.SetCookie(w, &http.Cookie{Name: "probe", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"forwardToEmail":"receiver@icloud.com"}`))
		case "/bootstrap/portal":
			if !strings.Contains(r.Header.Get("Cookie"), "probe=ok") {
				t.Fatalf("bootstrap cookie = %q", r.Header.Get("Cookie"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("scnt", "bootstrap-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL
	state, err := (&ICloudClient{client: ts.Client()}).KeepAliveAppleAccountManageState(t.Context(), LoginState{
		Kind: LoginStateAppleAccount, Origin: ts.URL, Scnt: "old-scnt", APIKey: "working-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(paths, "\n"), "GET /account/manage/forwardemail\nGET /bootstrap/portal"; got != want {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	if !state.LastCheckOK || state.Scnt != "bootstrap-scnt" || state.KeepAliveLastSuccessAt.IsZero() || state.ManageExpiresAt.Before(time.Now().Add(14*time.Minute)) {
		t.Fatalf("light keepalive state = %+v", state)
	}
}

func TestAppleAccountRedirectPreservesCookieAndDetectsLoginPage(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account/manage/forwardemail":
			http.SetCookie(w, &http.Cookie{Name: "rotated", Value: "yes", Path: "/"})
			http.Redirect(w, r, "/sign-in", http.StatusFound)
		case "/sign-in":
			if !strings.Contains(r.Header.Get("Cookie"), "rotated=yes") {
				t.Fatalf("redirect cookie = %q", r.Header.Get("Cookie"))
			}
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>Sign in with your Apple Account</body></html>`))
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL
	state := LoginState{Kind: LoginStateAppleAccount, Origin: ts.URL, Scnt: "scnt", APIKey: "key"}
	_, err := (&ICloudClient{client: ts.Client()}).callAppleAccountRaw(t.Context(), &state, state.APIKey, http.MethodGet, "/account/manage/forwardemail", nil, nil)
	if !isCodedError(err, "apple_account_auth_failed") {
		t.Fatalf("redirect error = %v", err)
	}
	if cookie := cookieHeader(state.Cookies, ts.URL+"/account/manage"); !strings.Contains(cookie, "rotated=yes") {
		t.Fatalf("saved redirect cookie = %q", cookie)
	}
}

func TestMergeSessionCookiesRemovesExpiredCookie(t *testing.T) {
	u, _ := url.Parse("https://account.apple.com/account/manage")
	cookies := []SessionCookie{{Name: "session", Value: "old", Domain: "account.apple.com", Path: "/"}}
	mergeSessionCookies(&cookies, u, []*http.Cookie{{Name: "session", Value: "old", Path: "/", MaxAge: -1}})
	if len(cookies) != 0 {
		t.Fatalf("expired cookies = %+v, want none", cookies)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountReusesFreshStateAfterFailedCheck(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token", "GET /account/manage":
			t.Fatalf("unexpected refresh request %s %s", r.Method, r.URL.Path)
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "recent-key" {
				t.Fatalf("add api key header = %q, want recent-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "recent-scnt" {
				t.Fatalf("add scnt header = %q, want recent-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Recovered.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "recent-key" {
				t.Fatalf("complete api key header = %q, want recent-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-add" {
				t.Fatalf("complete scnt header = %q, want scnt-after-add", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-complete")
			_, _ = w.Write([]byte(`{"emailAddress":"Recovered.Alias@icloud.com","id":"recovered123","active":true}`))
		case "GET /account/manage/email/private/recovered123.em":
			if r.Header.Get("X-Apple-Api-Key") != "recent-key" {
				t.Fatalf("confirm api key header = %q, want recent-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-complete" {
				t.Fatalf("confirm scnt header = %q, want scnt-after-complete", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-confirm")
			_, _ = w.Write([]byte(`{"emailAddress":"Recovered.Alias@icloud.com","id":"recovered123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Scnt:              "recent-scnt",
			APIKey:            "recent-key",
			LastCheckedAt:     checkedAt,
			ManageExpiresAt:   checkedAt.Add(15 * time.Minute),
			LastCheckOK:       false,
			LastStatusMessage: "新接口登录态异常：HTTP 404",
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "recovered.alias@icloud.com" {
		t.Fatalf("remote email = %q, want recovered.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/recovered123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.Scnt != "scnt-after-confirm" || updatedState.APIKey != "recent-key" || !updatedState.LastCheckOK || updatedState.LastCheckedAt.IsZero() || updatedState.LastCheckedAt.Before(checkedAt) {
		t.Fatalf("updated apple account state = %+v ok=%v, want reused state marked ok", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAfterAuthFailure(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	addCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addCalls++
			if addCalls == 1 {
				if r.Header.Get("X-Apple-Api-Key") != "old-key" {
					t.Fatalf("first add api key header = %q, want old-key", r.Header.Get("X-Apple-Api-Key"))
				}
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"authentication_failed"}]}`))
				return
			}
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("retry add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("retry add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","active":false}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("X-Apple-Api-Key") != "" {
				t.Fatalf("token api key header = %q, want empty", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-old" {
				t.Fatalf("token scnt header = %q, want scnt-old", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "PUT /account/manage/email/private/add/complete":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("complete api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","id":"retry123","active":true}`))
		case "GET /account/manage/email/private/retry123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Retry.Alias@icloud.com","id":"retry123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-old",
			APIKey:          "old-key",
			LastCheckedAt:   time.Now(),
			ManageExpiresAt: time.Now().Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "retry.alias@icloud.com" {
		t.Fatalf("remote email = %q, want retry.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/retry123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" || updatedState.Scnt != "scnt-after-add" || !updatedState.LastCheckOK {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed state", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAfterSessionTimeout(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	addCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /account/manage/email/private/add":
			addCalls++
			if addCalls == 1 {
				w.WriteHeader(appleAccountHTTPStatusSessionTimeout)
				_, _ = w.Write([]byte(`{"service_errors":[{"message":"session timeout"}]}`))
				return
			}
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("retry add api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("retry add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-add")
			_, _ = w.Write([]byte(`{"emailAddress":"Timeout.Alias@icloud.com","active":false}`))
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"Timeout.Alias@icloud.com","id":"timeout123","active":true}`))
		case "GET /account/manage/email/private/timeout123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Timeout.Alias@icloud.com","id":"timeout123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	remote, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Scnt:            "scnt-old",
			APIKey:          "old-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	if remote.Email != "timeout.alias@icloud.com" {
		t.Fatalf("remote email = %q, want timeout.alias@icloud.com", remote.Email)
	}
	wantPaths := []string{
		"POST /account/manage/email/private/add",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/timeout123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" || updatedState.Scnt != "scnt-after-add" || !updatedState.LastCheckOK || !updatedState.ManageExpiresAt.After(now) {
		t.Fatalf("updated apple account state = %+v ok=%v, want refreshed state", updatedState, ok)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRequiresManageSession(t *testing.T) {
	client := NewICloudClient()
	_, _, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{}, "account-key", "LAB", "")
	coded, ok := err.(codedError)
	if !ok {
		t.Fatalf("error type = %T, want codedError", err)
	}
	if coded.code != "apple_account_session_missing" {
		t.Fatalf("code = %q, want apple_account_session_missing", coded.code)
	}
}

func TestCheckSavedLoginStatesChecksAppleAccountState(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/section/privacy":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "GET /account/manage/forwardemail":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("forwardemail api key = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("forwardemail scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-touch")
			_, _ = w.Write([]byte(`{"forwardToEmail":"receiver@icloud.com"}`))
		case "POST /v2/jslogs":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("jslogs api key = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	checkedAt := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	client := &ICloudClient{client: ts.Client()}
	session, ok, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Origin: appleAccountManageOrigin,
			Scnt:   "scnt-token",
		}},
	}, checkedAt)
	if err != nil || !ok {
		t.Fatalf("checkSavedLoginStates err=%v ok=%t", err, ok)
	}
	state, found := appleAccountLoginState(session)
	if !found {
		t.Fatalf("apple account state missing: %+v", session.LoginStates)
	}
	if state.APIKey != "account-key" || state.Scnt != "scnt-after-touch" || !state.LastCheckOK || !state.LastCheckedAt.Equal(checkedAt) || state.LastStatusMessage != "新接口登录态正常" {
		t.Fatalf("updated state = %+v", state)
	}
	if !session.LastCheckOK || !strings.Contains(session.LastStatusMessage, "新接口正常") {
		t.Fatalf("session check status = ok:%t message:%q", session.LastCheckOK, session.LastStatusMessage)
	}
	wantPaths := []string{
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"GET /account/manage/forwardemail",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestCheckSavedLoginStatesKeepsRecentlyHealthyAppleAccountState(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "should not refresh recently healthy state", http.StatusTeapot)
	}))
	defer ts.Close()

	now := time.Now()
	client := &ICloudClient{client: ts.Client()}
	session, ok, err := checkSavedLoginStates(context.Background(), client, ICloudSession{
		LoginStates: []LoginState{{
			Kind:              LoginStateAppleAccount,
			Host:              "appleid.apple.com",
			Origin:            ts.URL,
			Scnt:              "fresh-scnt",
			APIKey:            "fresh-key",
			LastCheckOK:       true,
			LastCheckedAt:     now.Add(-time.Minute),
			ManageExpiresAt:   now.Add(14 * time.Minute),
			LastStatusMessage: "新接口登录态正常",
		}},
	}, now)
	if err != nil || !ok {
		t.Fatalf("checkSavedLoginStates err=%v ok=%t", err, ok)
	}
	if called {
		t.Fatal("recently healthy Apple Account state should not be refreshed")
	}
	state, found := appleAccountLoginState(session)
	if !found || !state.LastCheckOK || state.LastStatusMessage != "新接口登录态正常" || !state.LastCheckedAt.Equal(now) {
		t.Fatalf("state = %+v found=%t, want healthy state updated at check time", state, found)
	}
}

func TestAppleAuthClientPrimeAppleAccountManageStateKeepsChallengeScnt(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/section/privacy":
			w.Header().Set("scnt", "page-scnt")
			_, _ = w.Write([]byte(`<html></html>`))
		case "GET /bootstrap/portal":
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "" {
				t.Fatalf("pre-login token scnt header = %q, want empty", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "manage-scnt")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	session := &appleAuthSession{
		Endpoints: appleAccountManageAuthEndpoints(),
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.primeAppleAccountManageState(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if session.ManageScnt != "manage-scnt" {
		t.Fatalf("ManageScnt = %q, want manage-scnt", session.ManageScnt)
	}
	wantPaths := []string{
		"GET /account/manage/section/privacy",
		"GET /bootstrap/portal",
		"GET /account/manage/gs/ws/token",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestAppleAuthClientAuthStartPreservesAppleAccountCompleteHashcashChallenge(t *testing.T) {
	var gotPath string
	var gotAuthVersion string
	var gotSecFetchDest string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthVersion = r.URL.Query().Get("authVersion")
		gotSecFetchDest = r.Header.Get("Sec-Fetch-Dest")
		if r.Header.Get("Accept") == "" || !strings.Contains(r.Header.Get("Accept"), "text/html") {
			t.Fatalf("Accept = %q, want browser navigation accept", r.Header.Get("Accept"))
		}
		w.Header().Set("X-Apple-HC-Bits", "8")
		w.Header().Set("X-Apple-HC-Challenge", "initial-challenge")
		_, _ = w.Write([]byte(`<html></html>`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:  appleAccountManageOAuthClientID,
		FrameID:   "unit",
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.authStart(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/authorize/signin" {
		t.Fatalf("path = %q, want /authorize/signin", gotPath)
	}
	if gotAuthVersion != "8.0.2" {
		t.Fatalf("authVersion = %q, want 8.0.2", gotAuthVersion)
	}
	if gotSecFetchDest != "iframe" {
		t.Fatalf("Sec-Fetch-Dest = %q, want iframe", gotSecFetchDest)
	}
	if session.CompleteHCBits != 8 || session.CompleteHCChallenge != "initial-challenge" {
		t.Fatalf("complete hashcash = %d/%q, want 8/initial-challenge", session.CompleteHCBits, session.CompleteHCChallenge)
	}

	session.HCBits = 12
	session.HCChallenge = "later-challenge"
	bits, challenge := session.completeHashcashChallenge()
	if bits != 8 || challenge != "initial-challenge" {
		t.Fatalf("completeHashcashChallenge() = %d/%q, want preserved initial challenge", bits, challenge)
	}
}

func TestAppleAuthClientAuthFederateEnablesRememberMeForAppleAccountManage(t *testing.T) {
	var body map[string]any
	var rememberQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/federate" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		rememberQuery = r.URL.Query().Get("isRememberMeEnabled")
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		AppleID:   "user@example.com",
		ClientID:  appleAccountManageOAuthClientID,
		UserAgent: appleAccountManageUserAgent,
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.authFederate(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if rememberQuery != "true" {
		t.Fatalf("isRememberMeEnabled = %q, want true", rememberQuery)
	}
	if body["rememberMe"] != true {
		t.Fatalf("rememberMe = %#v, want true", body["rememberMe"])
	}
	if body["accountName"] != "user@example.com" {
		t.Fatalf("accountName = %#v, want user@example.com", body["accountName"])
	}
}

func TestAppleAuthClientAuthSRPUsesPreservedAppleAccountHashcashAndBrowserBody(t *testing.T) {
	var completeHashcash string
	var completeBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /signin/init":
			w.Header().Set("X-Apple-HC-Bits", "12")
			w.Header().Set("X-Apple-HC-Challenge", "later-challenge")
			_, _ = w.Write([]byte(`{"iteration":1,"salt":"c2FsdA==","protocol":"s2k","b":"Ag==","c":"proof-context"}`))
		case "POST /signin/complete":
			completeHashcash = r.Header.Get("X-Apple-HC")
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &completeBody); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		AppleID:        "user@example.com",
		ClientID:       appleAccountManageOAuthClientID,
		HCBits:         8,
		HCChallenge:    "initial-challenge",
		UserAgent:      appleAccountManageUserAgent,
		Scnt:           "scnt",
		SessionID:      "session-id",
		AuthAttributes: "attributes",
	}
	session.rememberCompleteHashcashChallenge()

	client := &AppleAuthClient{httpClient: ts.Client()}
	needs2FA, err := client.authSRP(t.Context(), session, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !needs2FA {
		t.Fatalf("needs2FA = false, want true")
	}
	if !strings.Contains(completeHashcash, ":8:") || !strings.Contains(completeHashcash, ":initial-challenge::") {
		t.Fatalf("X-Apple-HC = %q, want preserved initial challenge", completeHashcash)
	}
	if completeBody["rememberMe"] != true {
		t.Fatalf("rememberMe = %#v, want true", completeBody["rememberMe"])
	}
	if _, ok := completeBody["trustTokens"]; ok {
		t.Fatalf("trustTokens present in Apple Account manage complete body: %#v", completeBody["trustTokens"])
	}
	if completeBody["accountName"] != "user@example.com" {
		t.Fatalf("accountName = %#v, want user@example.com", completeBody["accountName"])
	}
}

func TestAppleAccountFallbackPhoneNumber(t *testing.T) {
	if got := string(appleAccountFallbackPhoneNumber(nil)); got != `{"id":1,"nonFTEU":true}` {
		t.Fatalf("nil fallback = %s", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(json.RawMessage(`null`))); got != `{"id":1,"nonFTEU":true}` {
		t.Fatalf("null fallback = %s", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(nil, json.RawMessage(`{"id":3}`))); got != `{"id":3}` {
		t.Fatalf("stored fallback = %s", got)
	}
	if got := string(appleAccountFallbackPhoneNumber(json.RawMessage(`{"id":2}`))); got != `{"id":2}` {
		t.Fatalf("explicit phone = %s", got)
	}
}

func TestAppleAuthClientRequestsBrowser2FACodeEndpoints(t *testing.T) {
	var paths []string
	var phoneBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "PUT /verify/trusteddevice/securitycode":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
		case "PUT /verify/phone":
			if err := json.NewDecoder(r.Body).Decode(&phoneBody); err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:       appleAccountManageOAuthClientID,
		FrameID:        "unit",
		UserAgent:      appleAccountManageUserAgent,
		Scnt:           "scnt-token",
		SessionID:      "session-id",
		TwoFactorPhone: json.RawMessage(`{"id":2,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.requestTrustedDeviceCode(t.Context(), session); err != nil {
		t.Fatal(err)
	}
	if err := client.requestPhoneSecurityCode(t.Context(), session, nil); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"PUT /verify/trusteddevice/securitycode",
		"PUT /verify/phone",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	phone, ok := phoneBody["phoneNumber"].(map[string]any)
	if !ok {
		t.Fatalf("phoneNumber = %#v, want object", phoneBody["phoneNumber"])
	}
	if phone["id"] != float64(2) {
		t.Fatalf("phone id = %#v, want 2", phone["id"])
	}
	if _, ok := phone["nonFTEU"]; ok {
		t.Fatalf("send phoneNumber should not include nonFTEU: %#v", phone)
	}
	if phoneBody["mode"] != "sms" {
		t.Fatalf("mode = %#v, want sms", phoneBody["mode"])
	}
}

func TestSubmitAppleAccountManage2FADefaultsTrustedDeviceAndUsesFreshScnt(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var authPaths []string
	var submittedCode string
	authTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authPaths = append(authPaths, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /verify/trusteddevice/securitycode":
			var body struct {
				SecurityCode struct {
					Code string `json:"code"`
				} `json:"securityCode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			submittedCode = body.SecurityCode.Code
			w.Header().Set("scnt", "fresh-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "fresh-session")
			w.WriteHeader(http.StatusNoContent)
		case "GET /2sv/trust":
			if r.Header.Get("scnt") != "fresh-scnt" {
				t.Fatalf("trust scnt header = %q, want fresh-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "trusted-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "trusted-session")
			http.SetCookie(w, &http.Cookie{Name: "trust-cookie", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authTS.Close()

	var managePaths []string
	tokenCalls := 0
	manageTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		managePaths = append(managePaths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("scnt") != "trusted-scnt" {
				t.Fatalf("token scnt header = %q, want trusted-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "token-scnt")
			http.SetCookie(w, &http.Cookie{Name: "manage-token", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "token-scnt" {
				t.Fatalf("manage scnt header = %q, want token-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-token=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected manage request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer manageTS.Close()
	appleAccountManageBaseURL = manageTS.URL

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: authTS.URL,
			Host: "appleid.apple.com",
		},
		AppleID:    "user@example.com",
		ClientID:   appleAccountManageOAuthClientID,
		FrameID:    "unit",
		UserAgent:  appleAccountManageUserAgent,
		Scnt:       "old-scnt",
		ManageScnt: "stale-manage-scnt",
		SessionID:  "old-session",
	}
	client := &AppleAuthClient{httpClient: authTS.Client()}
	icloudSession, err := client.SubmitAppleAccountManage2FA(t.Context(), appleAuthPending{Session: session}, "123456", nil)
	if err != nil {
		t.Fatal(err)
	}
	if submittedCode != "123456" {
		t.Fatalf("submitted code = %q, want 123456", submittedCode)
	}
	wantAuthPaths := []string{
		"POST /verify/trusteddevice/securitycode",
		"GET /2sv/trust",
	}
	if strings.Join(authPaths, "\n") != strings.Join(wantAuthPaths, "\n") {
		t.Fatalf("auth paths = %#v, want %#v", authPaths, wantAuthPaths)
	}
	wantManagePaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
	}
	if strings.Join(managePaths, "\n") != strings.Join(wantManagePaths, "\n") {
		t.Fatalf("manage paths = %#v, want %#v", managePaths, wantManagePaths)
	}
	state, ok := appleAccountLoginState(icloudSession)
	if !ok || state.Scnt != "manage-scnt" || state.APIKey != "account-key" || state.SessionID != "trusted-session" {
		t.Fatalf("apple account state = %+v ok=%v, want fresh session/scnt/api key", state, ok)
	}
	if !strings.Contains(cookieHeader(state.Cookies, authTS.URL+"/2sv/trust"), "trust-cookie=ok") {
		t.Fatalf("apple account state cookies = %+v, want trust cookie saved", state.Cookies)
	}
}

func TestSubmitAppleAccountManage2FAUsesPhoneMethod(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var authPaths []string
	var submittedCode string
	var submittedPhoneID float64
	authTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authPaths = append(authPaths, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "POST /verify/phone/securitycode":
			var body struct {
				PhoneNumber struct {
					ID float64 `json:"id"`
				} `json:"phoneNumber"`
				SecurityCode struct {
					Code string `json:"code"`
				} `json:"securityCode"`
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			submittedCode = body.SecurityCode.Code
			submittedPhoneID = body.PhoneNumber.ID
			if body.Mode != "sms" {
				t.Fatalf("mode = %q, want sms", body.Mode)
			}
			w.Header().Set("scnt", "fresh-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "fresh-session")
			w.WriteHeader(http.StatusNoContent)
		case "GET /2sv/trust":
			w.Header().Set("scnt", "trusted-scnt")
			w.Header().Set("X-Apple-ID-Session-Id", "trusted-session")
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected auth request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer authTS.Close()

	manageTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			w.Header().Set("scnt", "token-scnt")
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			w.Header().Set("scnt", "manage-scnt")
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		default:
			t.Fatalf("unexpected manage request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer manageTS.Close()
	appleAccountManageBaseURL = manageTS.URL

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: authTS.URL,
			Host: "appleid.apple.com",
		},
		AppleID:         "user@example.com",
		ClientID:        appleAccountManageOAuthClientID,
		FrameID:         "unit",
		UserAgent:       appleAccountManageUserAgent,
		Scnt:            "old-scnt",
		SessionID:       "old-session",
		TwoFactorMethod: appleTwoFactorMethodPhone,
		TwoFactorPhone:  json.RawMessage(`{"id":9,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: authTS.Client()}
	icloudSession, err := client.SubmitAppleAccountManage2FA(t.Context(), appleAuthPending{Session: session}, "654321", nil)
	if err != nil {
		t.Fatal(err)
	}
	if submittedCode != "654321" || submittedPhoneID != 9 {
		t.Fatalf("submitted code/id = %q/%v, want 654321/9", submittedCode, submittedPhoneID)
	}
	wantAuthPaths := []string{
		"POST /verify/phone/securitycode",
		"GET /2sv/trust",
	}
	if strings.Join(authPaths, "\n") != strings.Join(wantAuthPaths, "\n") {
		t.Fatalf("auth paths = %#v, want %#v", authPaths, wantAuthPaths)
	}
	state, ok := appleAccountLoginState(icloudSession)
	if !ok || state.Scnt != "manage-scnt" || state.APIKey != "account-key" || state.SessionID != "trusted-session" {
		t.Fatalf("apple account state = %+v ok=%v, want fresh session/scnt/api key", state, ok)
	}
}

func TestAppleAuthClientValidatePhoneCodeUsesStoredPhoneNumber(t *testing.T) {
	var body map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/verify/phone/securitycode" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	session := &appleAuthSession{
		Endpoints: appleAuthEndpoints{
			Home: "https://account.apple.com",
			Auth: ts.URL,
		},
		ClientID:       appleAccountManageOAuthClientID,
		FrameID:        "unit",
		UserAgent:      appleAccountManageUserAgent,
		TwoFactorPhone: json.RawMessage(`{"id":4,"nonFTEU":true}`),
	}
	client := &AppleAuthClient{httpClient: ts.Client()}
	if err := client.validatePhoneSecurityCode(t.Context(), session, "123456", nil); err != nil {
		t.Fatal(err)
	}
	phone, ok := body["phoneNumber"].(map[string]any)
	if !ok {
		t.Fatalf("phoneNumber = %#v, want object", body["phoneNumber"])
	}
	if phone["id"] != float64(4) || phone["nonFTEU"] != true {
		t.Fatalf("phoneNumber = %#v, want stored id and nonFTEU", phone)
	}
	securityCode := body["securityCode"].(map[string]any)
	if securityCode["code"] != "123456" || body["mode"] != "sms" {
		t.Fatalf("body = %#v, want code and sms mode", body)
	}
}

func TestAppleAuthSessionRememberTwoFactorPhoneNumberFromAuthHTML(t *testing.T) {
	session := &appleAuthSession{}
	session.rememberTwoFactorPhoneNumber([]byte(`<html><script id="app_config" type="application/json">{"bootData":{"twoSV":{"trustedDeviceVerification":{"phoneNumberVerification":{"trustedPhoneNumbers":[{"id":7,"numberWithDialCode":"+1 ***"}]}}}}}</script></html>`))
	if string(session.TwoFactorPhone) != `{"id":7}` {
		t.Fatalf("TwoFactorPhone = %s, want id 7", session.TwoFactorPhone)
	}
}

func TestICloudClientCreatePrivacyMailboxWithAppleAccountRefreshesAPIKey(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			tokenCalls++
			if tokenCalls != 1 {
				t.Fatalf("unexpected token call %d", tokenCalls)
			}
			if r.Header.Get("scnt") != "scnt-token" {
				t.Fatalf("token scnt header = %q, want scnt-token", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "scnt-after-token")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "scnt-after-token" {
				t.Fatalf("manage scnt header = %q, want scnt-after-token", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "scnt-after-manage")
			http.SetCookie(w, &http.Cookie{Name: "manage-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"apiKey":"account-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "account-key" {
				t.Fatalf("api key header = %q, want account-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "scnt-after-manage" {
				t.Fatalf("add scnt header = %q, want scnt-after-manage", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-cookie=ok") {
				t.Fatalf("add cookie header = %q, want manage response cookie", r.Header.Get("Cookie"))
			}
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","active":false}`))
		case "PUT /account/manage/email/private/add/complete":
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","id":"abc123","active":true}`))
		case "GET /account/manage/email/private/abc123.em":
			_, _ = w.Write([]byte(`{"emailAddress":"Candidate.Alias@icloud.com","id":"abc123","active":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	client := &ICloudClient{client: ts.Client()}
	_, updatedSession, err := client.CreatePrivacyMailboxWithAppleAccount(t.Context(), ICloudSession{
		LoginStates: []LoginState{{
			Kind: LoginStateAppleAccount,
			Scnt: "scnt-token",
		}},
	}, "", "LAB", "")
	if err != nil {
		t.Fatal(err)
	}
	updatedState, ok := appleAccountLoginState(updatedSession)
	if !ok || updatedState.APIKey != "account-key" {
		t.Fatalf("updated apple account state = %+v ok=%v, want api key", updatedState, ok)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
		"PUT /account/manage/email/private/add/complete",
		"GET /account/manage/email/private/abc123.em",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestICloudClientListPrivacyMailboxes(t *testing.T) {
	var sawRequest bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest = true
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v2/hme/list" {
			t.Fatalf("path = %s, want /v2/hme/list", r.URL.Path)
		}
		if r.URL.Query().Get("dsid") != "123" {
			t.Fatalf("dsid query = %q, want 123", r.URL.Query().Get("dsid"))
		}
		if r.Header.Get("Origin") != "https://www.icloud.com.cn" {
			t.Fatalf("Origin = %q, want https://www.icloud.com.cn", r.Header.Get("Origin"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": ["main@example.com"],
				"hmeEmails": [
					{"anonymousId":"a1","hme":"Phone.Created@iCloud.com","label":"PHONE","isActive":true,"forwardToEmail":"main@example.com","origin":"ON_DEMAND"},
					{"anonymousId":"a2","hme":"old@icloud.com","isActive":false,"origin":"MAIL"}
				]
			}
		}`))
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com.cn",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sawRequest {
		t.Fatal("server did not receive request")
	}
	if len(remotes) != 2 {
		t.Fatalf("remotes len = %d, want 2", len(remotes))
	}
	if remotes[0].Email != "phone.created@icloud.com" || remotes[0].Label != "PHONE" || !remotes[0].IsActive {
		t.Fatalf("first remote = %+v", remotes[0])
	}
	if remotes[1].Email != "old@icloud.com" || remotes[1].IsActive {
		t.Fatalf("second remote = %+v", remotes[1])
	}
}

func TestICloudClientDeletePrivacyMailboxDeactivatesThenDeletes(t *testing.T) {
	var paths []string
	var requestBodies []map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v2/hme/list":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[{"anonymousId":"remote-1","hme":"Delete.Me@icloud.com","isActive":true}]}}`))
		case "POST /v1/hme/deactivate", "POST /v1/hme/delete":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			requestBodies = append(requestBodies, body)
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	client := &ICloudClient{client: ts.Client()}
	result, err := client.DeletePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	}, "delete.me@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Found || !result.Deactivated || !result.Deleted || result.AlreadyMissing || result.AnonymousID != "remote-1" {
		t.Fatalf("delete result = %+v", result)
	}
	wantPaths := []string{"GET /v2/hme/list", "POST /v1/hme/deactivate", "POST /v1/hme/delete"}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
	if len(requestBodies) != 2 || requestBodies[0]["anonymousId"] != "remote-1" || requestBodies[1]["anonymousId"] != "remote-1" {
		t.Fatalf("delete request bodies = %#v", requestBodies)
	}
}

func TestICloudClientDeletePrivacyMailboxTreatsMissingRemoteAsDeleted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/hme/list" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[]}}`))
	}))
	defer ts.Close()

	result, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	}, "missing@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if result.Found || result.Deleted || !result.AlreadyMissing {
		t.Fatalf("missing remote result = %+v", result)
	}
}

func TestICloudClientDeletePrivacyMailboxAcceptsEmptyMutationResponses(t *testing.T) {
	var mutationCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v2/hme/list":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[{"anonymousId":"remote-empty","hme":"Empty.Response@icloud.com","isActive":true}]}}`))
		case "POST /v1/hme/deactivate", "POST /v1/hme/delete":
			mutationCalls++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer ts.Close()

	result, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "123",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: "127.0.0.1", Path: "/"}},
	}, "empty.response@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if mutationCalls != 2 {
		t.Fatalf("mutation calls = %d, want deactivate and delete", mutationCalls)
	}
	if !result.Found || !result.Deactivated || !result.Deleted || result.AlreadyMissing {
		t.Fatalf("delete result = %+v", result)
	}
}

func TestICloudClientDeletePrivacyMailboxUsesSavedICloudWebLoginState(t *testing.T) {
	var mutationCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v2/hme/list":
			_, _ = w.Write([]byte(`{"success":true,"result":{"hmeEmails":[{"anonymousId":"state-only","hme":"State.Only@icloud.com","isActive":true}]}}`))
		case "POST /v1/hme/deactivate", "POST /v1/hme/delete":
			mutationCalls++
			_, _ = w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	}))
	defer ts.Close()

	result, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailbox(t.Context(), ICloudSession{
		PremiumMailBaseURL: ts.URL,
		DSID:               "state-only-dsid",
		Host:               "www.icloud.com",
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Host:    "www.icloud.com",
			Cookies: []SessionCookie{{Name: "session", Value: "state-cookie", Domain: "127.0.0.1", Path: "/"}},
		}},
	}, "state.only@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if mutationCalls != 2 {
		t.Fatalf("mutation calls = %d, want deactivate and delete", mutationCalls)
	}
	if !result.Found || !result.Deactivated || !result.Deleted || result.AlreadyMissing {
		t.Fatalf("delete result = %+v", result)
	}
}

func TestICloudClientDeletePrivacyMailboxUsesAppleAccountInterface(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-Apple-Api-Key") != "delete-key" {
			t.Fatalf("api key = %q, want delete-key", r.Header.Get("X-Apple-Api-Key"))
		}
		if r.Header.Get("scnt") != "delete-scnt" {
			t.Fatalf("scnt = %q, want delete-scnt", r.Header.Get("scnt"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/email/private":
			_, _ = w.Write([]byte(`{"privateEmailList":[{"id":"apple-remote-1","emailAddress":"Apple.Delete@icloud.com","label":"new-api"}],"inactivePrivateEmailList":[]}`))
		case "DELETE /account/manage/email/private/apple-remote-1/stop", "DELETE /account/manage/email/private/apple-remote-1/remove":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	result, updatedSession, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithRemote(t.Context(), ICloudSession{
		AccountID: "acc-new-api",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Origin:          ts.URL,
			Scnt:            "delete-scnt",
			APIKey:          "delete-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "apple.delete@icloud.com", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Found || !result.Deactivated || !result.Deleted || result.AlreadyMissing || result.AnonymousID != "apple-remote-1" {
		t.Fatalf("delete result = %+v", result)
	}
	if state, ok := appleAccountLoginState(updatedSession); !ok || !state.LastCheckOK {
		t.Fatalf("updated Apple Account state = %+v ok=%v", state, ok)
	}
	wantPaths := []string{
		"GET /account/manage/email/private",
		"DELETE /account/manage/email/private/apple-remote-1/stop",
		"DELETE /account/manage/email/private/apple-remote-1/remove",
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestICloudClientDeletePrivacyMailboxUsesSavedAppleRemoteID(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodDelete {
			t.Fatalf("unexpected list request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	result, _, err := (&ICloudClient{client: ts.Client()}).DeletePrivacyMailboxWithRemote(t.Context(), ICloudSession{
		AccountID: "acc-saved-id",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Origin:          ts.URL,
			Scnt:            "saved-id-scnt",
			APIKey:          "saved-id-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}, "", "saved.id@icloud.com", "saved-remote-id", "APPLE_ACCOUNT", true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Found || !result.Deactivated || !result.Deleted || result.AnonymousID != "saved-remote-id" {
		t.Fatalf("delete result = %+v", result)
	}
	wantPaths := []string{
		"DELETE /account/manage/email/private/saved-remote-id/stop",
		"DELETE /account/manage/email/private/saved-remote-id/remove",
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestICloudClientDeletePrivacyMailboxCachesAppleAccountList(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	listCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/account/manage/email/private":
			listCalls++
			_, _ = w.Write([]byte(`{"privateEmailList":[{"id":"cache-1","emailAddress":"cache.one@icloud.com"},{"id":"cache-2","emailAddress":"cache.two@icloud.com"}],"inactivePrivateEmailList":[]}`))
		case r.Method == http.MethodDelete:
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	now := time.Now()
	session := ICloudSession{
		AccountID: "acc-cache",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Origin:          ts.URL,
			Scnt:            "cache-scnt",
			APIKey:          "cache-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}
	client := &ICloudClient{client: ts.Client()}
	for _, email := range []string{"cache.one@icloud.com", "cache.two@icloud.com"} {
		result, updatedSession, err := client.DeletePrivacyMailboxWithRemote(t.Context(), session, "", email, "", "", true)
		if err != nil {
			t.Fatalf("delete %s: %v", email, err)
		}
		if !result.Deleted {
			t.Fatalf("delete %s result = %+v", email, result)
		}
		session = updatedSession
	}
	if listCalls != 1 {
		t.Fatalf("Apple Account list calls = %d, want 1", listCalls)
	}
}

func TestICloudClientListPrivacyMailboxesRetriesEOF(t *testing.T) {
	attempts := 0
	client := &ICloudClient{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, io.EOF
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{
				"success": true,
				"timestamp": 1,
				"result": {"hmeEmails": [{"anonymousId":"a1","hme":"Retry.OK@icloud.com","label":"retry","isActive":true}]}
			}`)),
			Request: r,
		}, nil
	})}}
	remotes, err := client.ListPrivacyMailboxes(t.Context(), ICloudSession{
		PremiumMailBaseURL: "https://p39-maildomainws.icloud.com:443",
		DSID:               "123",
		ClientID:           "cid",
		ClientBuildNumber:  "build",
		MasteringNumber:    "master",
		Host:               "www.icloud.com",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if len(remotes) != 1 || remotes[0].Email != "retry.ok@icloud.com" {
		t.Fatalf("remotes = %+v", remotes)
	}
}

func TestUpsertMailboxFromRemoteCreatesAndUpdates(t *testing.T) {
	store := newTestStore(t)
	remote := ICloudRemoteMailbox{
		AnonymousID:    "a1",
		Email:          "Phone.Created@iCloud.com",
		Label:          "PHONE",
		ForwardToEmail: "main@example.com",
		IsActive:       true,
		Origin:         "APPLE_ACCOUNT",
	}
	mailbox, created, err := store.UpsertMailboxFromRemote("usr_1", "acc_1", remote, "synced from iCloud")
	if err != nil {
		t.Fatal(err)
	}
	if !created || mailbox.OwnerID != "usr_1" || mailbox.AccountID != "acc_1" || mailbox.Email != "phone.created@icloud.com" || mailbox.Status != StatusAvailable || mailbox.RemoteID != "a1" || mailbox.RemoteOrigin != "APPLE_ACCOUNT" {
		t.Fatalf("created mailbox = %+v created=%v", mailbox, created)
	}
	token := mailbox.APIToken

	remote.Label = "PHONE-UPDATED"
	remote.IsActive = false
	updated, created, err := store.UpsertMailboxFromRemote("usr_1", "", remote, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatalf("second upsert created=true, want update")
	}
	if updated.ID != mailbox.ID || updated.APIToken != token || updated.Label != "PHONE-UPDATED" || updated.ICloudActive {
		t.Fatalf("updated mailbox = %+v", updated)
	}
	if len(store.Snapshot().Mailboxes) != 1 {
		t.Fatalf("mailboxes len = %d, want 1", len(store.Snapshot().Mailboxes))
	}

	_, _, err = store.UpsertMailboxFromRemote("usr_2", "", remote, "")
	coded, ok := err.(codedError)
	if !ok || coded.code != "mailbox_exists_other_owner" {
		t.Fatalf("cross owner err = %T %+v, want mailbox_exists_other_owner", err, err)
	}
}

func TestMailboxSyncAfterUsesCursorOverlap(t *testing.T) {
	now := time.Date(2026, 6, 22, 11, 0, 0, 0, time.UTC)
	mailbox := Mailbox{LastSyncAt: now.Add(-time.Minute)}
	got := mailboxSyncAfter(mailbox, now.Add(-5*time.Minute), now)
	want := now.Add(-time.Minute).Add(-mailboxSyncCursorOverlap)
	if !got.Equal(want) {
		t.Fatalf("mailboxSyncAfter() = %s, want %s", got, want)
	}

	got = mailboxSyncAfter(Mailbox{}, now.Add(-5*time.Minute), now)
	if !got.Equal(now.Add(-5 * time.Minute)) {
		t.Fatalf("mailboxSyncAfter(no cursor) = %s", got)
	}
}

func TestLooksLikeVerificationText(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{text: "Your ChatGPT code is ready", want: true},
		{text: "验证码 123456", want: true},
		{text: "Ordinary newsletter", want: false},
	}
	for _, tt := range tests {
		if got := looksLikeVerificationText(tt.text, "OpenAI"); got != tt.want {
			t.Fatalf("looksLikeVerificationText(%q) = %v, want %v", tt.text, got, tt.want)
		}
	}
	if !shouldIncludeSyncedMessage("Ordinary newsletter", allMailboxMessagesKeyword) {
		t.Fatal("all-message sync mode should bypass verification text filtering")
	}
}

func TestIMAPQuoteEscapesUnsafeCharacters(t *testing.T) {
	got := imapQuote("a\"b\\c\r\n")
	if got != `"a\"b\\c"` {
		t.Fatalf("imapQuote() = %q", got)
	}
}

func TestSaveICloudIMAPLoginStoresStateWithoutReturningPassword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var checkedEmail, checkedPassword string
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		checkedEmail = email
		checkedPassword = appPassword
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-user", "imap123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"IMAP.User@iCloud.com","app_password":"app-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap login status = %d body=%s", rr.Code, rr.Body.String())
	}
	if checkedEmail != "imap.user@icloud.com" || checkedPassword != "app-secret" {
		t.Fatalf("checked credentials = %q/%q", checkedEmail, checkedPassword)
	}
	if strings.Contains(rr.Body.String(), "app-secret") {
		t.Fatalf("response leaked app password: %s", rr.Body.String())
	}
	var body struct {
		Session publicICloudSession `json:"session"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Session.ICloudIMAPLoginSaved || !body.Session.ICloudIMAPLoginOK || body.Session.ICloudIMAPEmail != "imap.user@icloud.com" {
		t.Fatalf("public session missing imap state: %+v", body.Session)
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(sessions))
	}
	state, ok := iCloudIMAPLoginState(sessions[0])
	if !ok || state.IMAPEmail != "imap.user@icloud.com" || state.IMAPAppPassword != "app-secret" || !state.LastCheckOK {
		t.Fatalf("saved imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginCanAttachICloudMailAliasToDifferentAppleID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var checkedEmail, checkedPassword string
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		checkedEmail = email
		checkedPassword = appPassword
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-alias-user", "imap123")

	primaryAppleID := "1953258942@qq.com"
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: primaryAppleID,
		LoginStates: []LoginState{{
			Kind:    LoginStateAppleAccount,
			Host:    "appleid.apple.com",
			Origin:  "https://account.apple.com",
			APIKey:  "api-key",
			Scnt:    "scnt",
			SavedAt: time.Now(),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 || strings.TrimSpace(sessions[0].AccountID) == "" {
		t.Fatalf("seed sessions = %+v", sessions)
	}
	accountID := sessions[0].AccountID
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: "q1953258942@icloud.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateICloudIMAP,
			IMAPEmail:       "q1953258942@icloud.com",
			IMAPAppPassword: "old-secret",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if sessions := store.ICloudSessionsForOwner(user.ID); len(sessions) != 2 {
		t.Fatalf("seed sessions len = %d, want 2", len(sessions))
	}

	rr := httptest.NewRecorder()
	payload := fmt.Sprintf(`{"account_id":%q,"email":"Q1953258942@iCloud.com","app_password":"app-secret"}`, accountID)
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap alias status = %d body=%s", rr.Code, rr.Body.String())
	}
	if checkedEmail != "q1953258942@icloud.com" || checkedPassword != "app-secret" {
		t.Fatalf("checked credentials = %q/%q", checkedEmail, checkedPassword)
	}
	var body struct {
		Session publicICloudSession `json:"session"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Session.AccountID != accountID || body.Session.AppleID != primaryAppleID {
		t.Fatalf("response session = %+v, want account %s apple id %s", body.Session, accountID, primaryAppleID)
	}
	if !body.Session.ICloudIMAPLoginSaved || body.Session.ICloudIMAPEmail != "q1953258942@icloud.com" {
		t.Fatalf("response imap state = %+v", body.Session)
	}
	sessions = store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1: %+v", len(sessions), sessions)
	}
	if accounts := store.SnapshotForOwner(user.ID).Accounts; len(accounts) != 1 {
		t.Fatalf("accounts len = %d, want 1: %+v", len(accounts), accounts)
	}
	if sessions[0].AppleID != primaryAppleID || sessions[0].AccountID != accountID {
		t.Fatalf("stored session identity = %+v", sessions[0])
	}
	state, ok := iCloudIMAPLoginState(sessions[0])
	if !ok || state.IMAPEmail != "q1953258942@icloud.com" || state.IMAPAppPassword != "app-secret" {
		t.Fatalf("stored imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginMatchesCreateAccountByEmailLocalPart(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-localpart-user", "imap123")

	primaryAppleID := "qq1953258942@gmail.com"
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: primaryAppleID,
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Origin: "https://account.apple.com",
			APIKey: "api-key",
			Scnt:   "scnt",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	accountID := store.ICloudSessionsForOwner(user.ID)[0].AccountID

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"qq1953258942@icloud.com","app_password":"app-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap alias status = %d body=%s", rr.Code, rr.Body.String())
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1: %+v", len(sessions), sessions)
	}
	if sessions[0].AccountID != accountID || sessions[0].AppleID != primaryAppleID {
		t.Fatalf("stored session identity = %+v", sessions[0])
	}
	state, ok := iCloudIMAPLoginState(sessions[0])
	if !ok || state.IMAPEmail != "qq1953258942@icloud.com" {
		t.Fatalf("stored imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginMatchesAppleSecondaryEmailPrefix(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		return nil
	}
	cookie, user := registerTestUser(t, handler, "imap-prefix-user", "imap123")

	primaryAppleID := "1953258942@qq.com"
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: primaryAppleID,
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Cookies: []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	accountID := store.ICloudSessionsForOwner(user.ID)[0].AccountID
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID: user.ID,
		AppleID: "qq1953258942@gmail.com",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Origin: "https://account.apple.com",
			APIKey: "api-key",
			Scnt:   "scnt",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"q1953258942@icloud.com","app_password":"app-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save imap prefix alias status = %d body=%s", rr.Code, rr.Body.String())
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 2 {
		t.Fatalf("sessions len = %d, want 2: %+v", len(sessions), sessions)
	}
	var matched ICloudSession
	for _, session := range sessions {
		if session.AccountID == accountID {
			matched = session
			break
		}
	}
	if matched.AccountID != accountID || matched.AppleID != primaryAppleID {
		t.Fatalf("stored session identity = %+v", matched)
	}
	state, ok := iCloudIMAPLoginState(matched)
	if !ok || state.IMAPEmail != "q1953258942@icloud.com" {
		t.Fatalf("stored imap state = %+v ok=%v", state, ok)
	}
}

func TestSaveICloudIMAPLoginFailureDoesNotStorePassword(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.checkIMAPLogin = func(ctx context.Context, email, appPassword string) error {
		return errCode("imap_login_failed", "IMAP 登录失败", false)
	}
	cookie, user := registerTestUser(t, handler, "imap-fail", "imap123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/imap-login/save", strings.NewReader(`{"email":"fail@icloud.com","app_password":"bad-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("save imap login failure status = %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "bad-secret") {
		t.Fatalf("error response leaked app password: %s", rr.Body.String())
	}
	if sessions := store.ICloudSessionsForOwner(user.ID); len(sessions) != 0 {
		t.Fatalf("sessions len = %d, want 0", len(sessions))
	}
}

func TestSetMailboxSyncCursor(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	syncedAt := time.Date(2026, 6, 22, 11, 1, 0, 0, time.UTC)
	updated, err := store.SetMailboxSyncCursor(mailbox.ID, syncedAt, "12345")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.LastSyncAt.Equal(syncedAt) || updated.LastSyncUID != "12345" {
		t.Fatalf("updated cursor = %+v", updated)
	}
	stored, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || !stored.LastSyncAt.Equal(syncedAt) || stored.LastSyncUID != "12345" {
		t.Fatalf("stored cursor = %+v ok=%v", stored, ok)
	}
}

func TestUpsertMessageDeduplicatesRemoteID(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.UpsertMessage(mailbox.ID, "remote-1", "icloud", "code 123456", "noreply", "first", zeroTime()); err != nil || !created {
		t.Fatalf("first upsert created=%v err=%v", created, err)
	}
	if _, created, err := store.UpsertMessage(mailbox.ID, "remote-1", "icloud", "code 654321", "noreply", "updated", zeroTime()); err != nil || created {
		t.Fatalf("second upsert created=%v err=%v", created, err)
	}
	state := store.Snapshot()
	if len(state.Messages) != 1 {
		t.Fatalf("messages len = %d, want 1", len(state.Messages))
	}
	if state.Messages[0].Body != "updated" {
		t.Fatalf("message body = %q", state.Messages[0].Body)
	}
	if state.Mailboxes[0].ReceiveCount != 1 {
		t.Fatalf("receive_count = %d, want 1", state.Mailboxes[0].ReceiveCount)
	}
}

func TestFileStoreSetPathMigratesAndLoadsState(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccount("UPI-1", "user@example.com", ""); err != nil {
		t.Fatal(err)
	}
	nextPath := filepath.Join(t.TempDir(), "custom-data", "state.json")
	state, err := store.SetPath(nextPath)
	if err != nil {
		t.Fatal(err)
	}
	if store.Path() != nextPath {
		t.Fatalf("Path() = %q, want %q", store.Path(), nextPath)
	}
	if len(state.Accounts) != 1 {
		t.Fatalf("migrated accounts = %d, want 1", len(state.Accounts))
	}

	other := newTestStore(t)
	if _, err := other.AddMailbox("", "UPI-2", "alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	otherPath := other.Path()
	loaded, err := store.SetPath(otherPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Mailboxes) != 1 || loaded.Mailboxes[0].Email != "alias@icloud.com" {
		t.Fatalf("loaded state = %+v", loaded)
	}
}

func TestRuntimeExportIncludesAccountsMailboxesAndSession(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.AddAccount("UPI-1", "user@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailbox("", "UPI-2", "alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSession(ICloudSession{DSID: "123", Cookies: []SessionCookie{{Name: "session", Value: "x"}}}); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("export status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Accounts      []Account      `json:"accounts"`
		Mailboxes     []Mailbox      `json:"mailboxes"`
		ICloudSession *ICloudSession `json:"icloud_session"`
		Messages      []Message      `json:"messages"`
		MessageCount  int            `json:"message_count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Accounts) != 1 || len(body.Mailboxes) != 1 || body.ICloudSession == nil {
		t.Fatalf("export body = %+v", body)
	}
	if len(body.Messages) != 0 || body.MessageCount != 0 {
		t.Fatalf("messages exported by default = %d count=%d", len(body.Messages), body.MessageCount)
	}
}

func TestMailboxAPITextExportIsScoped(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	userCookie, _ := registerTestUser(t, handler, "alice", "alice123")

	adminBox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "admin-alias@icloud.com")
	userBox := createTestMailboxWithCookie(t, handler, userCookie, "USER", "user-alias@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-apis", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user mailbox api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain", ct)
	}
	userBody := rr.Body.String()
	if !strings.Contains(userBody, userBox.Email+"----"+userBox.APIURL+"\n") {
		t.Fatalf("user export missing own mailbox api: %q", userBody)
	}
	if strings.Contains(userBody, adminBox.Email) {
		t.Fatalf("user export leaked admin mailbox: %q", userBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-apis", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mailbox api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	adminBody := rr.Body.String()
	for _, row := range []string{adminBox.Email + "----" + adminBox.APIURL + "\n", userBox.Email + "----" + userBox.APIURL + "\n"} {
		if !strings.Contains(adminBody, row) {
			t.Fatalf("admin export missing row %q in %q", row, adminBody)
		}
	}
}

func TestMailboxEmailExportFormatsAreScoped(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	userCookie, _ := registerTestUser(t, handler, "alice", "alice123")

	adminBox := createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN", "admin-alias@icloud.com")
	userBox := createTestMailboxWithCookie(t, handler, userCookie, "USER", "user-alias@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=csv", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user mailbox email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content-type = %q, want text/csv", ct)
	}
	userBody := rr.Body.String()
	if !strings.Contains(userBody, userBox.Email+"\n") {
		t.Fatalf("user export missing own email: %q", userBody)
	}
	if strings.Contains(userBody, adminBox.Email) || strings.Contains(userBody, "----") {
		t.Fatalf("user email export leaked admin/API data: %q", userBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=tsv", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mailbox email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	adminBody := rr.Body.String()
	for _, email := range []string{adminBox.Email + "\n", userBox.Email + "\n"} {
		if !strings.Contains(adminBody, email) {
			t.Fatalf("admin export missing email %q in %q", email, adminBody)
		}
	}
}

func TestMailboxExportFiltersByAccountID(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	accOne, err := store.AddAccountForOwner("", "Apple One", "one@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	accTwo, err := store.AddAccountForOwner("", "Apple Two", "two@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accOne.ID, "ONE", "one-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", accTwo.ID, "TWO", "two-alias@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-apis?account_id="+url.QueryEscape(accOne.ID), nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("account filtered api export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "one-alias@icloud.com----https://mail.example/api/v1/mailboxes/one-alias@icloud.com/code?key=") {
		t.Fatalf("filtered export missing account one API: %q", body)
	}
	if strings.Contains(body, "two-alias@icloud.com") {
		t.Fatalf("filtered export leaked account two: %q", body)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=jsonl&account_id="+url.QueryEscape(accTwo.ID), nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("account filtered email export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body = rr.Body.String()
	if !strings.Contains(body, `"email":"two-alias@icloud.com"`) || strings.Contains(body, "one-alias@icloud.com") || strings.Contains(body, "/api/v1/") {
		t.Fatalf("filtered email export body = %q", body)
	}
}

func TestMailboxExportAdminOwnerAndAccountFilter(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	_, normalUser := registerTestUser(t, handler, "alice", "alice123")
	adminAcc, err := store.AddAccountForOwner("", "Admin Apple", "admin@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	userAcc, err := store.AddAccountForOwner(normalUser.ID, "User Apple", "user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner("", adminAcc.ID, "ADMIN", "admin-only@icloud.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMailboxForOwner(normalUser.ID, userAcc.ID, "USER", "user-only@icloud.com"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?owner_id="+url.QueryEscape(normalUser.ID)+"&account_id="+url.QueryEscape(userAcc.ID), nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner/account filtered export status = %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "user-only@icloud.com\n") || strings.Contains(body, "admin-only@icloud.com") {
		t.Fatalf("owner/account filtered export body = %q", body)
	}
}

func TestMailboxExportRejectsInvalidFormat(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/runtime/export-mailbox-emails?format=xlsx", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid format status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestUserLoginScopesDataAndFirstUserIsAdmin(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	userCookie, normalUser := registerTestUser(t, handler, "alice", "alice123")
	if !adminUser.IsAdmin {
		t.Fatalf("first registered user should be admin: %+v", adminUser)
	}
	if normalUser.IsAdmin {
		t.Fatalf("second registered user should be normal: %+v", normalUser)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin auth me = %d body=%s", rr.Code, rr.Body.String())
	}
	var me struct {
		Authenticated bool       `json:"authenticated"`
		User          publicUser `json:"user"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.Authenticated || me.User.Username != "admin" || !me.User.IsAdmin {
		t.Fatalf("admin auth me = %+v", me)
	}

	createTestMailboxWithCookie(t, handler, adminCookie, "ADMIN-MBX", "admin@icloud.com")
	userMailbox := createTestMailboxWithCookie(t, handler, userCookie, "USER-MBX", "alice@icloud.com")

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user list mailboxes = %d body=%s", rr.Code, rr.Body.String())
	}
	var userList struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &userList); err != nil {
		t.Fatal(err)
	}
	if len(userList.Mailboxes) != 1 || userList.Mailboxes[0].Email != "alice@icloud.com" {
		t.Fatalf("user scoped mailboxes = %+v", userList.Mailboxes)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("user manage data = %d body=%s", rr.Code, rr.Body.String())
	}
	var userManageData struct {
		UserSummaries []publicUserSummary `json:"user_summaries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &userManageData); err != nil {
		t.Fatal(err)
	}
	if len(userManageData.UserSummaries) != 1 || userManageData.UserSummaries[0].OwnerID != normalUser.ID || userManageData.UserSummaries[0].MailboxCount != 1 {
		t.Fatalf("user summaries = %+v, want one scoped summary with one mailbox", userManageData.UserSummaries)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin manage data = %d body=%s", rr.Code, rr.Body.String())
	}
	var adminData struct {
		IsAdmin       bool                `json:"is_admin"`
		Users         []publicUser        `json:"users"`
		UserSummaries []publicUserSummary `json:"user_summaries"`
		Mailboxes     []publicMailbox     `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &adminData); err != nil {
		t.Fatal(err)
	}
	if !adminData.IsAdmin || len(adminData.Users) != 2 || len(adminData.Mailboxes) != 2 {
		t.Fatalf("admin manage data = %+v", adminData)
	}
	summaryByOwner := map[string]publicUserSummary{}
	for _, summary := range adminData.UserSummaries {
		summaryByOwner[summary.OwnerID] = summary
	}
	if summaryByOwner[adminUser.ID].MailboxCount != 1 || summaryByOwner[normalUser.ID].MailboxCount != 1 {
		t.Fatalf("admin user summaries = %+v, want both users with one mailbox", adminData.UserSummaries)
	}
	if adminData.Mailboxes[0].OwnerID == "" || adminData.Mailboxes[1].OwnerID == "" {
		t.Fatalf("mailboxes should expose owner_id for admin filtering: %+v", adminData.Mailboxes)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+userMailbox.ID+"/status", strings.NewReader(`{"status":"used"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mutate user mailbox = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestAdminCanDeleteNormalUserAndOwnedData(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	userCookie, normalUser := registerTestUser(t, handler, "alice", "alice123")
	account, err := store.AddAccountForOwner(normalUser.ID, "Alice Apple", "alice@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveICloudSessionForOwner(normalUser.ID, ICloudSession{
		OwnerID: normalUser.ID,
		AppleID: "alice@example.com",
		DSID:    "alice-dsid",
		Cookies: []SessionCookie{{Name: "session", Value: "secret"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(normalUser.ID, account.ID, "ALICE", "alice-alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Your OpenAI code is 123456", "noreply@example.com", "123456", time.Now()); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+normalUser.ID, nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin delete user = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Deleted DeleteUserResult `json:"deleted"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Deleted.UserID != normalUser.ID || body.Deleted.Accounts != 1 || body.Deleted.Mailboxes != 1 || body.Deleted.Messages != 1 || body.Deleted.ICloudSessions != 1 || body.Deleted.WebSessions == 0 {
		t.Fatalf("deleted result = %+v", body.Deleted)
	}

	state := store.Snapshot()
	if len(state.Users) != 1 || state.Users[0].ID != adminUser.ID {
		t.Fatalf("users after delete = %+v", state.Users)
	}
	if len(state.Accounts) != 0 || len(state.Mailboxes) != 0 || len(state.Messages) != 0 || len(state.ICloudSessions) != 0 {
		t.Fatalf("owned data after delete accounts=%d mailboxes=%d messages=%d sessions=%d", len(state.Accounts), len(state.Mailboxes), len(state.Messages), len(state.ICloudSessions))
	}
	for _, session := range state.WebSessions {
		if session.UserID == normalUser.ID {
			t.Fatalf("deleted user session still present: %+v", session)
		}
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/manage/data", nil)
	req.AddCookie(userCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("deleted user manage data = %d body=%s, want 401", rr.Code, rr.Body.String())
	}
}

func TestAdminDeleteUserRejectsSelfAndAdminAccounts(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())

	adminCookie, adminUser := registerTestUser(t, handler, "admin", "admin123")
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+adminUser.ID, nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "cannot_delete_self") {
		t.Fatalf("admin self delete = %d body=%s", rr.Code, rr.Body.String())
	}

	secondAdmin, err := store.CreateUser("second-admin", "admin123")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	for i := range store.state.Users {
		if store.state.Users[i].ID == secondAdmin.ID {
			store.state.Users[i].IsAdmin = true
		}
	}
	if err := store.saveLocked(); err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	store.mu.Unlock()
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+secondAdmin.ID, nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "cannot_delete_admin_user") {
		t.Fatalf("delete other admin = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSensitiveKeysAreNotAcceptedFromQueryString(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{APIKey: "global-secret"}, store, discardLogger())

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{
			name:   "management query key rejected",
			method: http.MethodGet,
			path:   "/api/status?admin_key=admin-secret",
		},
		{
			name:   "global api key query rejected on claim",
			method: http.MethodPost,
			path:   "/api/v1/mailboxes/claim?key=global-secret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s = %d body=%s, want 401", tt.method, tt.path, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestMailboxCodeQueryAcceptsOnlyPerMailboxToken(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Your OpenAI code is 135790", "noreply@example.com", "Use 135790 to continue.", time.Now()); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-secret"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/alias%40icloud.com/code?key=global-secret&after=2000-01-01T00:00:00Z", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code with global query key = %d body=%s, want 401", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/alias%40icloud.com/code?key="+mailbox.APIToken+"&after=2000-01-01T00:00:00Z", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code with mailbox query key = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "135790" {
		t.Fatalf("code body = %+v", body)
	}
}

func TestMailboxCodeQuerySyncsBeforeReturningCachedOldCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-fresh"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-fresh@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 111111 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-new",
				UID:        "2",
				Subject:    "ChatGPT code",
				Body:       "Use 222222 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	rr := httptest.NewRecorder()
	lookupAfter := time.Now().Add(-10 * time.Second).UTC().Format(time.RFC3339Nano)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&after="+url.QueryEscape(lookupAfter), nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool   `json:"success"`
		Code      string `json:"code"`
		MessageID string `json:"message_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "222222" {
		t.Fatalf("code body = %+v, want fresh 222222", body)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("sync calls = %d, want 1", got)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox missing")
	}
	if updated.LastCodeMessageID == "" || updated.LastCodeMessageID != body.MessageID {
		t.Fatalf("LastCodeMessageID=%q response message_id=%q", updated.LastCodeMessageID, body.MessageID)
	}
}

func TestMailboxCodeQueryReturnsLocalCachedCodeBeforeSync(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-code-local-first"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-local@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 333333 to continue.", time.Now()); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		return nil, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken, nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "333333" {
		t.Fatalf("code body = %+v, want local cached 333333", body)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("sync calls = %d, want 0", got)
	}
}

func TestMailWatcherPreloadsCodeMessages(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-mail-watcher"
	accountID := "acc-mail-watcher"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "watcher-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "UPI-1", "watcher@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{
		MailWatcherEnabled:           true,
		MailWatcherFetchLimit:        8,
		MailWatcherInitialFetchLimit: 20,
		MailWatcherLookbackHours:     24,
		PublicSyncMinIntervalMS:      1,
	}, store, discardLogger())
	server := handler.(*Server)
	var gotMaxThreads int
	var gotAfter time.Time
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		gotMaxThreads = maxMessages
		gotAfter = after
		if len(mailboxes) != 1 || mailboxes[0].ID != mailbox.ID {
			t.Fatalf("mailboxes = %+v, want only %s", mailboxes, mailbox.ID)
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-watcher",
				UID:        "10",
				Subject:    "ChatGPT code",
				Body:       "Use 555555 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	server.markMailWatcherActive(mailbox.ID)
	server.syncMailWatcherRound(context.Background(), true)
	if gotMaxThreads != 20 {
		t.Fatalf("maxThreads = %d, want initial fetch limit 20", gotMaxThreads)
	}
	if gotAfter.IsZero() || time.Since(gotAfter) < 23*time.Hour {
		t.Fatalf("watcher initial after = %v, want roughly 24h lookback", gotAfter)
	}
	if msg, code, ok := latestMailboxCode(store.MessagesForMailbox(mailbox.ID), time.Time{}, "ChatGPT", time.Now()); !ok || code != "555555" || msg.RemoteID != "remote-watcher" {
		t.Fatalf("stored code = msg:%+v code:%q ok:%v, want watcher code 555555", msg, code, ok)
	}
}

func TestMailWatcherPreloadsAPIActiveMailboxesWithoutPriorCodeRequest(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-mail-watcher-auto"
	accountID := "acc-mail-watcher-auto"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "watcher-auto@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "UPI-1", "auto-watcher@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{
		MailWatcherEnabled:           true,
		MailWatcherFetchLimit:        8,
		MailWatcherInitialFetchLimit: 20,
		MailWatcherLookbackHours:     24,
		PublicSyncMinIntervalMS:      1,
	}, store, discardLogger())
	server := handler.(*Server)
	var synced int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&synced, 1)
		if len(mailboxes) != 1 || mailboxes[0].ID != mailbox.ID {
			t.Fatalf("mailboxes = %+v, want auto included %s", mailboxes, mailbox.ID)
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-auto-watcher",
				UID:        "12",
				Subject:    "ChatGPT code",
				Body:       "Use 888888 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	server.syncMailWatcherRound(context.Background(), true)
	if atomic.LoadInt64(&synced) != 1 {
		t.Fatalf("watcher sync calls = %d, want 1", synced)
	}
	if msg, code, ok := latestMailboxCode(store.MessagesForMailbox(mailbox.ID), time.Time{}, "ChatGPT", time.Now()); !ok || code != "888888" || msg.RemoteID != "remote-auto-watcher" {
		t.Fatalf("stored code = msg:%+v code:%q ok:%v, want auto watcher code 888888", msg, code, ok)
	}
}

func TestMailboxCodeQueryReturnsQuicklyWhileBackgroundSyncContinues(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-fast"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-fast@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "fast@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicFastSyncWaitMS: 20, PublicSyncMinIntervalMS: 1}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce sync.Once
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-fast",
				UID:        "9",
				Subject:    "ChatGPT code",
				Body:       "Use 444444 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	start := time.Now()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken, nil)
	handler.ServeHTTP(rr, req)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("code request took %v, want quick no_code response", elapsed)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Success || body.Code != "no_code" {
		t.Fatalf("first response = %+v, want no_code while background sync continues", body)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("background sync did not start")
	}
	close(release)

	deadline := time.Now().Add(time.Second)
	for {
		if msg, code, ok := latestMailboxCode(store.MessagesForMailbox(mailbox.ID), time.Time{}, "ChatGPT", time.Now()); ok && code == "444444" {
			if msg.RemoteID != "remote-fast" {
				t.Fatalf("message remote id = %q, want remote-fast", msg.RemoteID)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("background sync did not store code, messages=%+v", store.MessagesForMailbox(mailbox.ID))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMailboxCodeQueryWaitMSWaitsForSyncResult(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-wait-ms"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-wait@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "wait@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicFastSyncWaitMS: 20, PublicSyncMinIntervalMS: 1}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		time.Sleep(100 * time.Millisecond)
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "remote-wait",
				UID:        "11",
				Subject:    "ChatGPT code",
				Body:       "Use 777777 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&wait_ms=500", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "777777" {
		t.Fatalf("code body = %+v, want waited code 777777", body)
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.mailboxCodeMu.Lock()
		pollers := len(server.mailboxCodePollers)
		server.mailboxCodeMu.Unlock()
		if pollers == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mailbox code poller still active after waited result")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestMailboxCodeQueryReturnsCodeInsertedDuringWaitTimeout(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })
	oldLocalPoll := mailboxCodeLocalPollInterval
	mailboxCodeLocalPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { mailboxCodeLocalPollInterval = oldLocalPoll })

	store := newTestStore(t)
	ownerID := "owner-code-timeout-cache"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-timeout@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "timeout@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{PublicFastSyncWaitMS: 20, PublicSyncMinIntervalMS: 1}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan struct{})
	release := make(chan struct{})
	syncDone := make(chan struct{})
	insertDone := make(chan struct{})
	var startedOnce sync.Once
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		defer close(syncDone)
		startedOnce.Do(func() { close(started) })
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return map[string][]ICloudSyncedMessage{}, nil
	}

	go func() {
		defer close(insertDone)
		<-started
		time.Sleep(20 * time.Millisecond)
		_, _ = store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 909090 to continue.", time.Now())
	}()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&keyword=ChatGPT&wait_ms=500&peek=1", nil)
	start := time.Now()
	handler.ServeHTTP(rr, req)
	elapsed := time.Since(start)
	close(release)
	select {
	case <-syncDone:
	case <-time.After(time.Second):
		t.Fatal("background sync did not finish")
	}
	select {
	case <-insertDone:
	case <-time.After(time.Second):
		t.Fatal("message insert did not finish")
	}
	deadline := time.Now().Add(time.Second)
	for {
		server.mailboxCodeMu.Lock()
		pollers := len(server.mailboxCodePollers)
		server.mailboxCodeMu.Unlock()
		if pollers == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("mailbox code poller still active")
		}
		time.Sleep(time.Millisecond)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "909090" {
		t.Fatalf("code body = %+v, want code inserted while poller was still waiting", body)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("code request took %v, want local insert to be observed before wait_ms timeout", elapsed)
	}
}

func TestMailboxCodeQueryDoesNotRepeatServedCachedCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-repeat"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-repeat@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 135790 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		return map[string][]ICloudSyncedMessage{}, nil
	}

	requestCode := func(query string) struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
		Error   string `json:"error"`
	} {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+query, nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request %q = %d body=%s", query, rr.Code, rr.Body.String())
		}
		var body struct {
			Success bool   `json:"success"`
			Code    string `json:"code"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	first := requestCode("")
	if !first.Success || first.Code != "135790" {
		t.Fatalf("first code = %+v, want 135790", first)
	}
	second := requestCode("")
	if second.Success || second.Code != "no_code" {
		t.Fatalf("second code = %+v, want no_code without repeating cached OTP", second)
	}
	cached := requestCode("&cache=1")
	if !cached.Success || cached.Code != "135790" {
		t.Fatalf("cache code = %+v, want cached 135790", cached)
	}
}

func TestMailboxCodePeekDoesNotConsumeServedCode(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-peek"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "", "receiver-peek@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "", "UPI-1", "alias-peek@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "ChatGPT code", "noreply@example.com", "Use 246802 to continue.", time.Now().Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		return map[string][]ICloudSyncedMessage{}, nil
	}

	requestCode := func(query string) struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	} {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+query, nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request %q = %d body=%s", query, rr.Code, rr.Body.String())
		}
		var body struct {
			Success bool   `json:"success"`
			Code    string `json:"code"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	peek := requestCode("&peek=1")
	if !peek.Success || peek.Code != "246802" {
		t.Fatalf("peek code = %+v, want 246802", peek)
	}
	firstPublic := requestCode("")
	if !firstPublic.Success || firstPublic.Code != "246802" {
		t.Fatalf("public code after peek = %+v, want 246802", firstPublic)
	}
	secondPublic := requestCode("")
	if secondPublic.Success || secondPublic.Code != "no_code" {
		t.Fatalf("second public code = %+v, want no_code", secondPublic)
	}
	secondPeek := requestCode("&peek=1")
	if !secondPeek.Success || secondPeek.Code != "246802" {
		t.Fatalf("peek after public = %+v, want 246802", secondPeek)
	}
}

func TestLatestMailboxCodeSelectsNewestAndHonorsAfter(t *testing.T) {
	oldTime := time.Date(2026, 6, 21, 21, 36, 50, 0, time.FixedZone("CST", 8*3600))
	newTime := oldTime.Add(30 * time.Minute)
	now := newTime.Add(time.Minute)
	messages := []Message{
		{ID: "old", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 733849", ReceivedAt: oldTime},
		{ID: "new", Subject: "Your temporary ChatGPT verification code", Body: "Enter this temporary verification code to continue: 246810", ReceivedAt: newTime},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	msg, code, ok = latestMailboxCode(messages, newTime.Add(-time.Minute), "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "246810" {
		t.Fatalf("latestMailboxCode(after) msg=%s code=%q ok=%v, want new 246810 true", msg.ID, code, ok)
	}

	_, _, ok = latestMailboxCode(messages, newTime.Add(time.Minute), "ChatGPT", now)
	if ok {
		t.Fatalf("latestMailboxCode(after future) ok=true, want false")
	}
}

func TestLatestMailboxCodeOnlyUsesFiveMinuteWindow(t *testing.T) {
	now := time.Date(2026, 6, 22, 10, 0, 0, 0, time.UTC)
	messages := []Message{
		{ID: "too-old", Subject: "ChatGPT code", Body: "code 111111", ReceivedAt: now.Add(-6 * time.Minute)},
		{ID: "older", Subject: "ChatGPT code", Body: "code 222222", ReceivedAt: now.Add(-4 * time.Minute)},
		{ID: "newest", Subject: "ChatGPT code", Body: "code 333333", ReceivedAt: now.Add(-30 * time.Second)},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "newest" || code != "333333" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want newest 333333 true", msg.ID, code, ok)
	}

	tooOld := Message{ID: "too-old", Subject: "ChatGPT code", Body: "code 111111", ReceivedAt: now.Add(-6 * time.Minute)}
	_, _, ok = latestMailboxCode([]Message{tooOld}, time.Time{}, "ChatGPT", now)
	if ok {
		t.Fatalf("latestMailboxCode(old only) ok=true, want false")
	}
}

func TestLatestMailboxCodeUsesCreatedAtWhenReceivedAtMissing(t *testing.T) {
	now := time.Date(2026, 6, 21, 20, 6, 0, 0, time.UTC)
	messages := []Message{
		{ID: "old", Subject: "ChatGPT code", Body: "code 111111", CreatedAt: time.Date(2026, 6, 21, 20, 0, 0, 0, time.UTC)},
		{ID: "new", Subject: "ChatGPT code", Body: "code 222222", CreatedAt: time.Date(2026, 6, 21, 20, 5, 0, 0, time.UTC)},
	}

	msg, code, ok := latestMailboxCode(messages, time.Time{}, "ChatGPT", now)
	if !ok || msg.ID != "new" || code != "222222" {
		t.Fatalf("latestMailboxCode() msg=%s code=%q ok=%v, want new 222222 true", msg.ID, code, ok)
	}
}

func TestSyncMailboxSerializesPerOwner(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-sync"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "acc", "sync-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	first, err := store.AddMailboxForOwner(ownerID, "acc", "first", "first@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(ownerID, "acc", "second", "second@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	started := make(chan string, 2)
	release := make(chan struct{})
	var active int64
	var maxActive int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		if len(mailboxes) != 1 {
			t.Fatalf("mailboxes = %d, want 1", len(mailboxes))
		}
		mailbox := mailboxes[0]
		nowActive := atomic.AddInt64(&active, 1)
		for {
			old := atomic.LoadInt64(&maxActive)
			if nowActive <= old || atomic.CompareAndSwapInt64(&maxActive, old, nowActive) {
				break
			}
		}
		started <- mailbox.Email
		select {
		case <-release:
		case <-ctx.Done():
			atomic.AddInt64(&active, -1)
			return nil, ctx.Err()
		}
		atomic.AddInt64(&active, -1)
		return map[string][]ICloudSyncedMessage{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	go func() {
		_, err := server.syncMailbox(ctx, first, time.Time{}, "ChatGPT")
		errs <- err
	}()
	if got := <-started; got != first.Email {
		t.Fatalf("first started %s, want %s", got, first.Email)
	}
	go func() {
		_, err := server.syncMailbox(ctx, second, time.Time{}, "ChatGPT")
		errs <- err
	}()

	select {
	case got := <-started:
		t.Fatalf("second sync started before first finished: %s", got)
	case <-time.After(50 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got := <-started; got != second.Email {
		t.Fatalf("second started %s, want %s", got, second.Email)
	}
	release <- struct{}{}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&maxActive); got != 1 {
		t.Fatalf("max active sync = %d, want 1", got)
	}
}

func TestMailboxCodeRequestsShareOwnerBatchSync(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-code"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "acc", "batch-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	first, err := store.AddMailboxForOwner(ownerID, "acc", "first", "first@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.AddMailboxForOwner(ownerID, "acc", "second", "second@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int64
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		atomic.AddInt64(&calls, 1)
		now := time.Now()
		out := make(map[string][]ICloudSyncedMessage, len(mailboxes))
		for _, mailbox := range mailboxes {
			switch mailbox.Email {
			case first.Email:
				out[mailbox.ID] = []ICloudSyncedMessage{{
					RemoteID:   "r1",
					UID:        "1",
					Subject:    "ChatGPT code",
					Body:       "Use 111111 to continue.",
					ReceivedAt: now,
				}}
			case second.Email:
				out[mailbox.ID] = []ICloudSyncedMessage{{
					RemoteID:   "r2",
					UID:        "2",
					Subject:    "ChatGPT code",
					Body:       "Use 222222 to continue.",
					ReceivedAt: now,
				}}
			}
		}
		return out, nil
	}

	type response struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	requestCode := func(mailbox Mailbox) response {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&after=2000-01-01T00:00:00Z", nil)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("code request for %s = %d body=%s", mailbox.Email, rr.Code, rr.Body.String())
		}
		var body response
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var firstBody, secondBody response
	go func() {
		defer wg.Done()
		firstBody = requestCode(first)
	}()
	go func() {
		defer wg.Done()
		secondBody = requestCode(second)
	}()
	wg.Wait()

	if !firstBody.Success || firstBody.Code != "111111" {
		t.Fatalf("first body = %+v, want 111111", firstBody)
	}
	if !secondBody.Success || secondBody.Code != "222222" {
		t.Fatalf("second body = %+v, want 222222", secondBody)
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("batch sync calls = %d, want 1", got)
	}
}

func TestMailboxCodeWaiterSyncUsesRequestKeyword(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })
	oldDebounce := mailboxCodePollDebounce
	mailboxCodePollDebounce = 0
	t.Cleanup(func() { mailboxCodePollDebounce = oldDebounce })

	store := newTestStore(t)
	ownerID := "owner-code-keyword"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, "acc", "keyword-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, "acc", "keyword", "keyword@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		if keyword != "ChatGPT" {
			return map[string][]ICloudSyncedMessage{}, nil
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "chatgpt-keyword",
				UID:        "99",
				Subject:    "你的 ChatGPT 临时验证码",
				Body:       "验证码：864209",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/mailboxes/"+url.PathEscape(mailbox.Email)+"/code?key="+mailbox.APIToken+"&keyword=ChatGPT&wait_ms=1000", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code request = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool   `json:"success"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Code != "864209" {
		t.Fatalf("code body = %+v, want ChatGPT code 864209", body)
	}
}

func TestSyncMailboxCodeBatchStoresIMAPAccountCursor(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-imap-cursor"
	accountID := "acc-imap-cursor"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "cursor-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "cursor", "cursor.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatchWithCursor = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
		return iCloudIMAPSyncResult{
			LastUID: "789",
			MessagesByMailbox: map[string][]ICloudSyncedMessage{
				mailbox.ID: {{
					RemoteID:   "imap:789",
					UID:        "789",
					Subject:    "ChatGPT code",
					Body:       "Use 135790 to continue.",
					ReceivedAt: time.Now(),
				}},
			},
		}, nil
	}

	if _, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT"); err != nil {
		t.Fatal(err)
	}
	session, ok := store.ICloudSessionForOwnerAccount(ownerID, accountID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := iCloudIMAPLoginState(session)
	if !ok {
		t.Fatalf("imap state missing: %+v", session)
	}
	if state.IMAPLastSyncUID != "789" {
		t.Fatalf("IMAPLastSyncUID = %q, want 789", state.IMAPLastSyncUID)
	}
	if state.IMAPLastSyncAt.IsZero() {
		t.Fatal("IMAPLastSyncAt is zero")
	}
}

func TestSyncMailboxCodeBatchSkipsEmptyMailboxCursorWrites(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-imap-empty-cursor"
	accountID := "acc-imap-empty-cursor"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "empty-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "empty", "empty.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatchWithCursor = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
		return iCloudIMAPSyncResult{
			LastUID:           "999",
			MessagesByMailbox: map[string][]ICloudSyncedMessage{},
		}, nil
	}

	if _, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT"); err != nil {
		t.Fatal(err)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found")
	}
	if !updated.LastSyncAt.IsZero() {
		t.Fatalf("LastSyncAt = %s, want zero for empty mailbox sync", updated.LastSyncAt)
	}
	session, ok := store.ICloudSessionForOwnerAccount(ownerID, accountID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := iCloudIMAPLoginState(session)
	if !ok {
		t.Fatalf("imap state missing: %+v", session)
	}
	if state.IMAPLastSyncUID != "999" {
		t.Fatalf("IMAPLastSyncUID = %q, want 999", state.IMAPLastSyncUID)
	}
}

func TestSyncMailboxRespectsMessageRetentionSetting(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	for _, tt := range []struct {
		name      string
		storeAll  bool
		wantCount int
	}{
		{name: "verification only", storeAll: false, wantCount: 1},
		{name: "all messages", storeAll: true, wantCount: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			settings := store.SystemSettings()
			settings.StoreAllMessages = tt.storeAll
			if _, err := store.SaveSystemSettings(settings); err != nil {
				t.Fatal(err)
			}
			ownerID := "owner-retention-" + strings.ReplaceAll(tt.name, " ", "-")
			accountID := "acc-retention"
			if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "retention-owner@icloud.com")); err != nil {
				t.Fatal(err)
			}
			mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "retention", "retention.alias@icloud.com")
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			server := NewServer(Config{}, store, discardLogger()).(*Server)
			server.syncCodeMailboxBatchWithCursor = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (iCloudIMAPSyncResult, error) {
				wantKeyword := "ChatGPT"
				if tt.storeAll {
					wantKeyword = allMailboxMessagesKeyword
				}
				if keyword != wantKeyword {
					t.Fatalf("sync keyword = %q, want %q", keyword, wantKeyword)
				}
				return iCloudIMAPSyncResult{LastUID: "101", MessagesByMailbox: map[string][]ICloudSyncedMessage{
					mailbox.ID: {
						{RemoteID: "imap:100", UID: "100", Subject: "Your sign-in code", Body: "Use 246810 to continue.", ReceivedAt: now.Add(-time.Minute)},
						{RemoteID: "imap:101", UID: "101", Subject: "Security settings changed", Body: "This message has no one-time code.", ReceivedAt: now},
					},
				}}, nil
			}

			count, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT")
			if err != nil {
				t.Fatal(err)
			}
			if count != tt.wantCount {
				t.Fatalf("synced messages = %d, want %d", count, tt.wantCount)
			}
			messages := store.MessagesForMailbox(mailbox.ID)
			if len(messages) != tt.wantCount {
				t.Fatalf("stored messages = %+v, want %d", messages, tt.wantCount)
			}
			_, code, found := latestMailboxCode(messages, time.Time{}, "", now.Add(time.Minute))
			if !found || code != "246810" {
				t.Fatalf("latest code = %q found=%v, want 246810", code, found)
			}
		})
	}
}

func TestLegacyMailboxSyncKeepsOrdinaryMailWhenConfigured(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	settings := store.SystemSettings()
	settings.StoreAllMessages = true
	if _, err := store.SaveSystemSettings(settings); err != nil {
		t.Fatal(err)
	}
	ownerID := "legacy-retention-owner"
	accountID := "legacy-retention-account"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID, AccountID: accountID, AppleID: "legacy@example.test", DSID: "legacy-dsid",
		PremiumMailBaseURL: "https://mail.example.invalid", Cookies: []SessionCookie{{Name: "session", Value: "test"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "legacy", "legacy.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(Config{}, store, discardLogger()).(*Server)
	server.syncMailboxBatch = func(ctx context.Context, session ICloudSession, mailboxes []Mailbox, after time.Time, keyword string, maxThreads int) (map[string][]ICloudSyncedMessage, error) {
		if keyword != allMailboxMessagesKeyword {
			t.Fatalf("legacy sync keyword = %q, want all-message sentinel", keyword)
		}
		return map[string][]ICloudSyncedMessage{mailbox.ID: {{RemoteID: "icloud:ordinary", Subject: "Welcome newsletter", Body: "No verification code here.", ReceivedAt: time.Now()}}}, nil
	}
	if err := server.syncMailboxBatchForOwner(context.Background(), ownerID, []Mailbox{mailbox}, time.Time{}, "OpenAI"); err != nil {
		t.Fatal(err)
	}
	if messages := store.MessagesForMailbox(mailbox.ID); len(messages) != 1 || messages[0].Subject != "Welcome newsletter" {
		t.Fatalf("legacy stored messages = %+v, want ordinary message", messages)
	}
}

func TestEnsureMailWatcherIMAPBaselineStoresAccountUID(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-imap-baseline"
	accountID := "acc-imap-baseline"
	if err := store.SaveICloudSessionForOwner(ownerID, testIMAPSession(ownerID, accountID, "baseline-owner@icloud.com")); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(ownerID, accountID, "baseline", "baseline.alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	var calls int
	server.latestIMAPUID = func(ctx context.Context, state LoginState) (string, error) {
		calls++
		return "500", nil
	}
	groups := server.mailWatcherIMAPGroups()
	if len(groups) != 1 {
		t.Fatalf("IMAP groups = %d, want 1", len(groups))
	}
	if err := server.ensureMailWatcherIMAPBaseline(context.Background(), groups[0]); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("latest IMAP UID calls = %d, want 1", calls)
	}
	session, ok := store.ICloudSessionForOwnerAccount(ownerID, accountID)
	if !ok {
		t.Fatal("session not found")
	}
	state, ok := iCloudIMAPLoginState(session)
	if !ok {
		t.Fatal("imap state missing")
	}
	if state.IMAPLastSyncUID != "500" {
		t.Fatalf("IMAPLastSyncUID = %q, want 500", state.IMAPLastSyncUID)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok {
		t.Fatal("mailbox not found")
	}
	if !updated.LastSyncAt.IsZero() || updated.LastSyncUID != "" {
		t.Fatalf("mailbox cursor changed: LastSyncAt=%s LastSyncUID=%q", updated.LastSyncAt, updated.LastSyncUID)
	}
}

func TestMailWatcherIMAPGroupSignatureIgnoresMailboxSyncCursor(t *testing.T) {
	state := LoginState{
		Kind:            LoginStateICloudIMAP,
		IMAPEmail:       "receiver@icloud.com",
		IMAPUsername:    "receiver@icloud.com",
		IMAPHost:        defaultICloudIMAPHost,
		IMAPPort:        defaultICloudIMAPPort,
		IMAPAppPassword: "app-specific-password",
	}
	before := mailWatcherIMAPGroupSignature(state, []Mailbox{{
		ID:          "mbx_1",
		Email:       "alias@icloud.com",
		LastSyncUID: "100",
	}})
	after := mailWatcherIMAPGroupSignature(state, []Mailbox{{
		ID:          "mbx_1",
		Email:       "alias@icloud.com",
		LastSyncUID: "200",
	}})
	if before != after {
		t.Fatalf("signature changed after LastSyncUID update: %q vs %q", before, after)
	}
}

func TestLoginProtectsManagementAPI(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status without admin = %d, want 401", rr.Code)
	}

	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status with admin login = %d, want 200", rr.Code)
	}
}

func TestMailboxAPICanBeEnabledAfterDisable(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "api-toggle-owner", "toggle123")
	mailbox := createTestMailboxWithCookie(t, handler, cookie, "toggle", "toggle@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(mailbox.ID)+"/disable", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable mailbox API = %d body=%s", rr.Code, rr.Body.String())
	}
	disabled, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || disabled.APIActive || disabled.Status != StatusDisabled {
		t.Fatalf("disabled mailbox = %+v ok=%v", disabled, ok)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(mailbox.ID)+"/enable", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable mailbox API = %d body=%s", rr.Code, rr.Body.String())
	}
	enabled, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || !enabled.APIActive || enabled.Status != StatusAvailable || enabled.Note != "API 已启用" {
		t.Fatalf("enabled mailbox = %+v ok=%v", enabled, ok)
	}
}

func TestMailboxOutboundStatusAndListFilters(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "outbound-admin", "admin123")
	foreign := createTestMailboxWithCookie(t, handler, adminCookie, "foreign", "foreign@icloud.com")
	ownerCookie, _ := registerTestUser(t, handler, "outbound-owner", "owner123")
	inventory := createTestMailboxWithCookie(t, handler, ownerCookie, "inventory", "inventory@icloud.com")
	outbound := createTestMailboxWithCookie(t, handler, ownerCookie, "outbound", "outbound@icloud.com")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(outbound.ID)+"/status", strings.NewReader(`{"status":"outbound","note":"test outbound"}`))
	req.AddCookie(ownerCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("set outbound status = %d body=%s", rr.Code, rr.Body.String())
	}
	updated, ok := store.FindMailboxByID(outbound.ID)
	if !ok || updated.Status != StatusOutbound || updated.Note != "test outbound" || strings.TrimSpace(updated.OutboundBatch) == "" {
		t.Fatalf("outbound mailbox = %+v ok=%v", updated, ok)
	}
	outboundBatch := updated.OutboundBatch
	if !validMailboxStatus(StatusOutbound) {
		t.Fatal("outbound status should be valid")
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(outbound.ID)+"/disable", strings.NewReader(`{}`))
	req.AddCookie(ownerCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable outbound mailbox API = %d body=%s", rr.Code, rr.Body.String())
	}
	disabledOutbound, ok := store.FindMailboxByID(outbound.ID)
	if !ok || disabledOutbound.APIActive || disabledOutbound.Status != StatusOutbound || disabledOutbound.OutboundBatch != outboundBatch {
		t.Fatalf("disabled outbound mailbox = %+v ok=%v", disabledOutbound, ok)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(outbound.ID)+"/enable", strings.NewReader(`{}`))
	req.AddCookie(ownerCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable outbound mailbox API = %d body=%s", rr.Code, rr.Body.String())
	}
	enabledOutbound, ok := store.FindMailboxByID(outbound.ID)
	if !ok || !enabledOutbound.APIActive || enabledOutbound.Status != StatusOutbound || enabledOutbound.OutboundBatch != outboundBatch {
		t.Fatalf("enabled outbound mailbox = %+v ok=%v", enabledOutbound, ok)
	}

	list := func(query string) []publicMailbox {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?"+query, nil)
		req.AddCookie(ownerCookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list mailboxes %q = %d body=%s", query, rr.Code, rr.Body.String())
		}
		var body struct {
			Mailboxes  []publicMailbox  `json:"mailboxes"`
			Pagination publicPagination `json:"pagination"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Pagination.TotalAll != 1 {
			t.Fatalf("list mailboxes %q total_all = %d, want 1", query, body.Pagination.TotalAll)
		}
		return body.Mailboxes
	}
	outboundRows := list("status=outbound")
	if len(outboundRows) != 1 || outboundRows[0].ID != outbound.ID || outboundRows[0].Status != StatusOutbound || outboundRows[0].OutboundBatch != outboundBatch {
		t.Fatalf("outbound rows = %+v, want %s", outboundRows, outbound.ID)
	}
	inventoryRows := list("exclude_status=outbound")
	if len(inventoryRows) != 1 || inventoryRows[0].ID != inventory.ID {
		t.Fatalf("inventory rows = %+v, want %s", inventoryRows, inventory.ID)
	}
	for _, row := range append(outboundRows, inventoryRows...) {
		if row.ID == foreign.ID {
			t.Fatalf("foreign mailbox leaked into owner list: %+v", row)
		}
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(ownerCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner status = %d body=%s", rr.Code, rr.Body.String())
	}
	var statusBody struct {
		Mailboxes          int `json:"mailboxes"`
		InventoryMailboxes int `json:"inventory_mailboxes"`
		OutboundMailboxes  int `json:"outbound_mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &statusBody); err != nil {
		t.Fatal(err)
	}
	if statusBody.Mailboxes != 2 || statusBody.InventoryMailboxes != 1 || statusBody.OutboundMailboxes != 1 {
		t.Fatalf("status mailbox counts = %+v, want total=2 inventory=1 outbound=1", statusBody)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(foreign.ID)+"/status", strings.NewReader(`{"status":"outbound"}`))
	req.AddCookie(ownerCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("set foreign mailbox outbound = %d body=%s, want 404", rr.Code, rr.Body.String())
	}
}

func TestBatchOutboundMailboxesUsesSharedBatchAndTimestampFallback(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "batch-admin", "admin123")
	cookie, _ := registerTestUser(t, handler, "batch-owner", "batch123")
	first := createTestMailboxWithCookie(t, handler, cookie, "first", "batch-first@icloud.com")
	second := createTestMailboxWithCookie(t, handler, cookie, "second", "batch-second@icloud.com")

	postBatch := func(ids []string, batch string) (string, int) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"ids": ids, "batch": batch})
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/batch-outbound", bytes.NewReader(body))
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("batch outbound = %d body=%s", rr.Code, rr.Body.String())
		}
		var response struct {
			Batch string `json:"batch"`
			Count int    `json:"count"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Batch, response.Count
	}

	batch, count := postBatch([]string{first.ID, second.ID}, "客户A-0816")
	if batch != "客户A-0816" || count != 2 {
		t.Fatalf("explicit batch response = %q/%d", batch, count)
	}
	for _, id := range []string{first.ID, second.ID} {
		mailbox, ok := store.FindMailboxByID(id)
		if !ok || mailbox.Status != StatusOutbound || mailbox.OutboundBatch != batch {
			t.Fatalf("explicit batch mailbox %s = %+v ok=%v", id, mailbox, ok)
		}
	}

	third := createTestMailboxWithCookie(t, handler, cookie, "third", "batch-third@icloud.com")
	fourth := createTestMailboxWithCookie(t, handler, cookie, "fourth", "batch-fourth@icloud.com")
	timestampBatch, count := postBatch([]string{third.ID, fourth.ID}, "")
	if count != 2 || len(timestampBatch) != 13 || strings.Trim(timestampBatch, "0123456789") != "" {
		t.Fatalf("timestamp batch response = %q/%d, want 13 digit shared timestamp", timestampBatch, count)
	}
	for _, id := range []string{third.ID, fourth.ID} {
		mailbox, ok := store.FindMailboxByID(id)
		if !ok || mailbox.OutboundBatch != timestampBatch {
			t.Fatalf("timestamp batch mailbox %s = %+v ok=%v", id, mailbox, ok)
		}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(first.ID)+"/status", strings.NewReader(`{"status":"available"}`))
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("return outbound mailbox = %d body=%s", rr.Code, rr.Body.String())
	}
	returned, ok := store.FindMailboxByID(first.ID)
	if !ok || returned.Status != StatusAvailable || returned.OutboundBatch != "" {
		t.Fatalf("returned mailbox = %+v ok=%v, want cleared batch", returned, ok)
	}

	ownerInventory := createTestMailboxWithCookie(t, handler, cookie, "owner-inventory", "owner-inventory@icloud.com")
	foreign := createTestMailboxWithCookie(t, handler, adminCookie, "foreign", "batch-foreign@icloud.com")
	body, err := json.Marshal(map[string]any{"ids": []string{ownerInventory.ID, foreign.ID}, "batch": "should-not-apply"})
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/mailboxes/batch-outbound", bytes.NewReader(body))
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-owner batch outbound = %d body=%s, want 404", rr.Code, rr.Body.String())
	}
	unchanged, ok := store.FindMailboxByID(ownerInventory.ID)
	if !ok || unchanged.Status != StatusAvailable || unchanged.OutboundBatch != "" {
		t.Fatalf("batch outbound should be atomic on authorization failure: %+v ok=%v", unchanged, ok)
	}
}

func TestMailboxAdvancedSearchCombinesBatchAndHTMLState(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "search-owner", "search123")
	alphaActive := createTestMailboxWithCookie(t, handler, cookie, "alpha-active", "alpha-active@icloud.com")
	alphaPending := createTestMailboxWithCookie(t, handler, cookie, "alpha-pending", "alpha-pending@icloud.com")
	betaActive := createTestMailboxWithCookie(t, handler, cookie, "beta-active", "beta-active@icloud.com")
	if _, err := store.SetMailboxesOutbound([]string{alphaActive.ID, alphaPending.ID}, "alpha", "test batch"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetMailboxesOutbound([]string{betaActive.ID}, "beta", "test batch"); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?status=outbound&search=%5Balpha%5D&page=1&page_size=50", nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("batch overview = %d body=%s", rr.Code, rr.Body.String())
	}
	var batchResponse struct {
		Batches []publicMailboxBatch `json:"batches"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &batchResponse); err != nil {
		t.Fatal(err)
	}
	batchCounts := map[string]int{}
	for _, batch := range batchResponse.Batches {
		batchCounts[batch.Name] = batch.Count
	}
	if len(batchCounts) != 2 || batchCounts["alpha"] != 2 || batchCounts["beta"] != 1 {
		t.Fatalf("batch overview = %#v, want alpha=2 beta=1", batchResponse.Batches)
	}

	now := time.Now()
	store.mu.Lock()
	for i := range store.state.MailboxHTMLLinks {
		link := &store.state.MailboxHTMLLinks[i]
		if link.MailboxID == alphaActive.ID || link.MailboxID == betaActive.ID {
			link.ActivatedAt = now.Add(-time.Hour)
			link.ExpiresAt = now.Add(time.Hour)
		}
	}
	err := store.saveLocked()
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	search := func(query string) []string {
		t.Helper()
		values := url.Values{"status": {StatusOutbound}, "search": {query}, "page": {"1"}, "page_size": {"50"}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?"+values.Encode(), nil)
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("search %q = %d body=%s", query, rr.Code, rr.Body.String())
		}
		var response struct {
			Mailboxes []publicMailbox `json:"mailboxes"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(response.Mailboxes))
		for _, mailbox := range response.Mailboxes {
			ids = append(ids, mailbox.ID)
		}
		sort.Strings(ids)
		return ids
	}

	assertIDs := func(query string, want ...string) {
		t.Helper()
		sort.Strings(want)
		if got := search(query); !reflect.DeepEqual(got, want) {
			t.Fatalf("search %q = %v, want %v", query, got, want)
		}
	}
	assertIDs("[alpha]", alphaActive.ID, alphaPending.ID)
	assertIDs("![alpha]", betaActive.ID)
	assertIDs("[已激活]", alphaActive.ID, betaActive.ID)
	assertIDs("![已激活]", alphaPending.ID)
	assertIDs("[alpha]&&[已激活]", alphaActive.ID)
	assertIDs("【alpha】&&【已激活】", alphaActive.ID)
}

func TestMailboxOutboundHTMLStateFilters(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "html-filter-owner", "filter123")
	activated := createTestMailboxWithCookie(t, handler, cookie, "activated", "activated@icloud.com")
	unactivated := createTestMailboxWithCookie(t, handler, cookie, "unactivated", "unactivated@icloud.com")
	expired := createTestMailboxWithCookie(t, handler, cookie, "expired", "expired@icloud.com")
	inventoryExpired := createTestMailboxWithCookie(t, handler, cookie, "inventory-expired", "inventory-expired@icloud.com")
	for _, id := range []string{activated.ID, unactivated.ID, expired.ID} {
		if _, err := store.SetMailboxStatus(id, nil, nil, StatusOutbound, "test outbound"); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now()
	store.mu.Lock()
	for i := range store.state.MailboxHTMLLinks {
		link := &store.state.MailboxHTMLLinks[i]
		switch link.MailboxID {
		case activated.ID:
			link.ActivatedAt = now.Add(-time.Hour)
			link.ExpiresAt = now.Add(time.Hour)
		case expired.ID, inventoryExpired.ID:
			link.ActivatedAt = now.Add(-2 * time.Hour)
			link.ExpiresAt = now.Add(-time.Hour)
		}
	}
	err := store.saveLocked()
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	list := func(state string) ([]publicMailbox, publicPagination) {
		t.Helper()
		query := url.Values{"status": {StatusOutbound}, "html_state": {state}, "page": {"1"}, "page_size": {"1"}}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/mailboxes?"+query.Encode(), nil)
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("list HTML state %q = %d body=%s", state, rr.Code, rr.Body.String())
		}
		var body struct {
			Mailboxes  []publicMailbox  `json:"mailboxes"`
			Pagination publicPagination `json:"pagination"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Mailboxes, body.Pagination
	}

	for _, tt := range []struct {
		state string
		want  string
	}{
		{state: "activated", want: activated.ID},
		{state: "unactivated", want: unactivated.ID},
		{state: "expired", want: expired.ID},
	} {
		rows, pagination := list(tt.state)
		if len(rows) != 1 || rows[0].ID != tt.want || pagination.Total != 1 || pagination.TotalAll != 1 || pagination.TotalPages != 1 {
			t.Fatalf("HTML state %q rows=%+v pagination=%+v, want %s", tt.state, rows, pagination, tt.want)
		}
	}
	rows, pagination := list("all")
	if len(rows) != 1 || pagination.Total != 3 || pagination.TotalAll != 3 || pagination.TotalPages != 3 {
		t.Fatalf("all HTML states rows=%+v pagination=%+v, want three outbound rows over three pages", rows, pagination)
	}
}

func TestCleanupExpiredOutboundMailboxesEndpoint(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	adminCookie, admin := registerTestUser(t, handler, "cleanup-admin", "admin123")
	ownerCookie, owner := registerTestUser(t, handler, "cleanup-owner", "owner123")
	for _, user := range []publicUser{admin, owner} {
		if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
			OwnerID: user.ID, AppleID: user.Username + "@icloud.com", DSID: "dsid-" + user.ID,
			PremiumMailBaseURL: "https://mail.example.invalid", Cookies: []SessionCookie{{Name: "session", Value: "test"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	expired := createTestMailboxWithCookie(t, handler, ownerCookie, "expired", "cleanup-expired@icloud.com")
	active := createTestMailboxWithCookie(t, handler, ownerCookie, "active", "cleanup-active@icloud.com")
	inventory := createTestMailboxWithCookie(t, handler, ownerCookie, "inventory", "cleanup-inventory@icloud.com")
	foreign := createTestMailboxWithCookie(t, handler, adminCookie, "foreign", "cleanup-foreign@icloud.com")
	for _, id := range []string{expired.ID, active.ID, foreign.ID} {
		if _, err := store.SetMailboxStatus(id, nil, nil, StatusOutbound, "test outbound"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AddMessage(expired.ID, "saved", "sender@example.com", "code 123456", time.Now()); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	store.mu.Lock()
	for i := range store.state.MailboxHTMLLinks {
		link := &store.state.MailboxHTMLLinks[i]
		switch link.MailboxID {
		case expired.ID, inventory.ID, foreign.ID:
			link.ActivatedAt = now.Add(-2 * time.Hour)
			link.ExpiresAt = now.Add(-time.Hour)
		case active.ID:
			link.ActivatedAt = now.Add(-time.Hour)
			link.ExpiresAt = now.Add(time.Hour)
		}
	}
	err := store.saveLocked()
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	var remoteDeletes []string
	server.deletePrivacyMailbox = func(_ context.Context, session ICloudSession, email string) (ICloudMailboxDeleteResult, error) {
		if session.OwnerID != owner.ID {
			t.Fatalf("cleanup used owner %q, want %q", session.OwnerID, owner.ID)
		}
		remoteDeletes = append(remoteDeletes, email)
		return ICloudMailboxDeleteResult{Email: email, Found: true, Deleted: true}, nil
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/html-expired/cleanup", strings.NewReader(`{}`))
	req.AddCookie(ownerCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("cleanup expired mailboxes = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Matched int `json:"matched"`
		Deleted int `json:"deleted"`
		Skipped int `json:"skipped"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Matched != 1 || body.Deleted != 1 || body.Skipped != 0 || body.Failed != 0 || !reflect.DeepEqual(remoteDeletes, []string{expired.Email}) {
		t.Fatalf("cleanup response=%+v remote=%v body=%s", body, remoteDeletes, rr.Body.String())
	}
	if _, ok := store.FindMailboxByID(expired.ID); ok || len(store.MessagesForMailbox(expired.ID)) != 0 {
		t.Fatal("expired outbound mailbox or its messages remain after cleanup")
	}
	for _, id := range []string{active.ID, inventory.ID, foreign.ID} {
		if _, ok := store.FindMailboxByID(id); !ok {
			t.Fatalf("non-target mailbox %s was deleted", id)
		}
	}
}

func TestDeleteMailboxPermanentlyDeletesRemoteBeforeLocalData(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "delete-owner", "delete123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AppleID:            "delete-owner@icloud.com",
		PremiumMailBaseURL: "https://mail.example.invalid",
		DSID:               "delete-dsid",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "delete", "delete-me@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "code", "sender@example.com", "code 123456", time.Now()); err != nil {
		t.Fatal(err)
	}
	server.deletePrivacyMailbox = func(ctx context.Context, session ICloudSession, email string) (ICloudMailboxDeleteResult, error) {
		if session.DSID != "delete-dsid" || email != mailbox.Email {
			t.Fatalf("remote delete input = session:%+v email:%q", session, email)
		}
		return ICloudMailboxDeleteResult{Email: email, Found: true, Deactivated: true, Deleted: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+url.PathEscape(mailbox.ID), nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete mailbox = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		LocalDeleted bool                      `json:"local_deleted"`
		Remote       ICloudMailboxDeleteResult `json:"remote"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.LocalDeleted || !body.Remote.Deactivated || !body.Remote.Deleted {
		t.Fatalf("delete response = %+v body=%s", body, rr.Body.String())
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); ok {
		t.Fatal("mailbox still exists after remote deletion")
	}
	if messages := store.MessagesForMailbox(mailbox.ID); len(messages) != 0 {
		t.Fatalf("messages after deletion = %+v", messages)
	}
	for _, link := range store.Snapshot().MailboxHTMLLinks {
		if link.MailboxID == mailbox.ID {
			t.Fatalf("HTML link still exists after deletion: %+v", link)
		}
	}
}

func TestDeleteMailboxKeepsLocalDataWhenRemoteDeleteFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "delete-fail-owner", "delete123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		AppleID:            "delete-fail@icloud.com",
		PremiumMailBaseURL: "https://mail.example.invalid",
		DSID:               "delete-fail-dsid",
		Cookies:            []SessionCookie{{Name: "session", Value: "x", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, "", "keep", "keep-me@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	server.deletePrivacyMailbox = func(context.Context, ICloudSession, string) (ICloudMailboxDeleteResult, error) {
		return ICloudMailboxDeleteResult{}, errCode("icloud_mailbox_delete_failed", "远端永久删除失败", true)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+url.PathEscape(mailbox.ID), nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("failed remote delete = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("local mailbox was deleted after remote failure")
	}
	if link, ok := store.MailboxHTMLLinkForMailbox(mailbox.ID); !ok || link.Token == "" {
		t.Fatal("HTML link was deleted after remote failure")
	}
}

func TestDeleteMailboxKeepsLocalDataWhenAppleAccountRemoveFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "DELETE /account/manage/email/private/apple-fail-id/stop":
			w.WriteHeader(http.StatusNoContent)
		case "DELETE /account/manage/email/private/apple-fail-id/remove":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"still active"}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "delete-apple-fail", "delete123")
	now := time.Now()
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:   user.ID,
		AccountID: "acc-apple-fail",
		AppleID:   "delete-apple-fail@icloud.com",
		LoginStates: []LoginState{{
			Kind:            LoginStateAppleAccount,
			Origin:          ts.URL,
			Scnt:            "apple-fail-scnt",
			APIKey:          "apple-fail-key",
			LastCheckedAt:   now,
			ManageExpiresAt: now.Add(15 * time.Minute),
			LastCheckOK:     true,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailboxForOwner(user.ID, "acc-apple-fail", "keep", "keep-apple@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err = store.SetMailboxRemoteIdentity(mailbox.ID, "apple-fail-id", "APPLE_ACCOUNT")
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/mailboxes/"+url.PathEscape(mailbox.ID), nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("failed Apple Account delete = %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := store.FindMailboxByID(mailbox.ID); !ok {
		t.Fatal("local mailbox was deleted after Apple Account remove failure")
	}
	if link, ok := store.MailboxHTMLLinkForMailbox(mailbox.ID); !ok || link.Token == "" {
		t.Fatal("HTML link was deleted after Apple Account remove failure")
	}
}

func TestMailboxHTMLLinkAndSystemSettings(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "admin", "admin123")
	mailbox := createTestMailboxWithCookie(t, handler, adminCookie, "demo", "demo@icloud.com")
	if mailbox.HTMLLinkURL == "" {
		t.Fatal("mailbox HTML link was not generated during mailbox creation")
	}
	if mailbox.HTMLLinkActivated != "" || mailbox.HTMLLinkExpires != "" {
		t.Fatalf("new mailbox HTML link should be inactive: %+v", mailbox)
	}
	if mailbox.Label != "demo" || mailbox.HTMLLinkTTLSeconds != 604800 {
		t.Fatalf("new mailbox label/HTML TTL = %+v, want label demo and 604800 seconds", mailbox)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes/"+url.PathEscape(mailbox.ID)+"/html-link", strings.NewReader(`{}`))
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create html link = %d body=%s", rr.Code, rr.Body.String())
	}
	var linkBody struct {
		URL         string `json:"url"`
		ActivatedAt string `json:"activated_at"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &linkBody); err != nil || linkBody.URL == "" {
		t.Fatalf("invalid html link response: %s", rr.Body.String())
	}
	if linkBody.URL != mailbox.HTMLLinkURL {
		t.Fatalf("HTML link changed before activation: got %q want %q", linkBody.URL, mailbox.HTMLLinkURL)
	}
	if linkBody.ActivatedAt != "" || linkBody.ExpiresAt != "" {
		t.Fatalf("HTML link started expiring before first use: %s", rr.Body.String())
	}
	parsed, err := url.Parse(linkBody.URL)
	if err != nil {
		t.Fatal(err)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/system-settings", strings.NewReader(`{"registration_enabled":false,"admin_path":"/control-panel","html_link_ttl_seconds":93784}`))
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save system settings = %d body=%s", rr.Code, rr.Body.String())
	}

	htmlBody := `<!doctype html><html><head><style>.code{color:#2563eb}</style></head><body><h1>ChatGPT code</h1><strong class="code">246810</strong></body></html>`
	if _, err := store.AddMessageContent(mailbox.ID, "Your ChatGPT verification code", "noreply@example.test", normalizeMailBody(htmlBody), htmlBody, time.Now()); err != nil {
		t.Fatal(err)
	}
	activationStartedAt := time.Now()
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsed.Path, nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "最近邮件") || !strings.Contains(rr.Body.String(), "buildEmailDocument") || !strings.Contains(rr.Body.String(), "setAttribute('sandbox','')") {
		t.Fatalf("public html page = %d body=%s", rr.Code, rr.Body.String())
	}
	activatedLink, ok := store.MailboxHTMLLinkForMailbox(mailbox.ID)
	if !ok || activatedLink.ActivatedAt.IsZero() || activatedLink.ExpiresAt.IsZero() {
		t.Fatalf("HTML link was not activated on first use: %+v", activatedLink)
	}
	if activatedLink.ActivatedAt.Before(activationStartedAt) {
		t.Fatalf("HTML link activated before first request: %s < %s", activatedLink.ActivatedAt, activationStartedAt)
	}
	if want := activatedLink.ActivatedAt.Add(93784 * time.Second); !activatedLink.ExpiresAt.Equal(want) {
		t.Fatalf("HTML link expires at %s, want %s", activatedLink.ExpiresAt, want)
	}
	firstActivatedAt := activatedLink.ActivatedAt
	firstExpiresAt := activatedLink.ExpiresAt

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, parsed.Path+"/data", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("public html data = %d body=%s", rr.Code, rr.Body.String())
	}
	var publicBody struct {
		Messages []publicMessage `json:"messages"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &publicBody); err != nil || len(publicBody.Messages) != 1 || !strings.Contains(publicBody.Messages[0].HTMLBody, "246810") {
		t.Fatalf("public html body missing: %s", rr.Body.String())
	}
	activatedLink, ok = store.MailboxHTMLLinkForMailbox(mailbox.ID)
	if !ok || !activatedLink.ActivatedAt.Equal(firstActivatedAt) || !activatedLink.ExpiresAt.Equal(firstExpiresAt) {
		t.Fatalf("repeated use reset HTML link lifetime: got %+v", activatedLink)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/mailboxes", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list mailboxes = %d body=%s", rr.Code, rr.Body.String())
	}
	var mailboxList struct {
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &mailboxList); err != nil || len(mailboxList.Mailboxes) != 1 {
		t.Fatalf("invalid mailbox list: %s", rr.Body.String())
	}
	if mailboxList.Mailboxes[0].HTMLLinkActivated == "" || mailboxList.Mailboxes[0].HTMLLinkExpires == "" {
		t.Fatalf("mailbox list omitted HTML expiry fields: %+v", mailboxList.Mailboxes[0])
	}
	if mailboxList.Mailboxes[0].Label != "demo" || mailboxList.Mailboxes[0].HTMLLinkTTLSeconds != 93784 {
		t.Fatalf("mailbox list label/HTML TTL = %+v, want label demo and 93784 seconds", mailboxList.Mailboxes[0])
	}

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/control-panel", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "注册并登录") {
		t.Fatalf("custom login entry = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/control-panel", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "账号数据管理") {
		t.Fatalf("authenticated custom admin page = %d body=%s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/control-panel/register", strings.NewReader(`{"username":"new-user","password":"newpass"}`))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("registration disabled status = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestSystemSettingsMessageRetentionAndExpiryDeleteSwitches(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{}, store, discardLogger())
	adminCookie, _ := registerTestUser(t, handler, "settings-admin", "admin123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/system-settings", nil)
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get default settings = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Settings struct {
			VerificationOnly         bool `json:"verification_only"`
			HTMLLinkLifecycleEnabled bool `json:"html_link_lifecycle_enabled"`
			HTMLExpiryDeleteMailbox  bool `json:"html_expiry_delete_mailbox"`
			HTMLPageMessageLimit     int  `json:"html_page_message_limit"`
			HTMLPageRefreshSeconds   int  `json:"html_page_refresh_seconds"`
			HTMLLinkTTLSeconds       int  `json:"html_link_ttl_seconds"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Settings.VerificationOnly || !body.Settings.HTMLLinkLifecycleEnabled || body.Settings.HTMLExpiryDeleteMailbox || body.Settings.HTMLPageMessageLimit != 50 || body.Settings.HTMLPageRefreshSeconds != 20 || body.Settings.HTMLLinkTTLSeconds != 604800 {
		t.Fatalf("default settings = %+v, want verification-only on, expiry-delete off, limit 50, refresh 20 seconds and TTL 604800 seconds", body.Settings)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/system-settings", strings.NewReader(`{"registration_enabled":true,"verification_only":false,"admin_path":"/manage","html_link_ttl_seconds":5,"html_page_message_limit":120,"html_page_refresh_seconds":35,"html_link_lifecycle_enabled":false,"html_expiry_delete_mailbox":true}`))
	req.AddCookie(adminCookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save settings switches = %d body=%s", rr.Code, rr.Body.String())
	}
	settings := store.SystemSettings()
	if !settings.StoreAllMessages || !settings.HTMLLinkLifecycleDisabled || !settings.HTMLExpiryDeleteMailbox || settings.HTMLPageMessageLimit != 120 || settings.HTMLPageRefreshSeconds != 35 || settings.HTMLLinkTTLSeconds != 5 {
		t.Fatalf("stored settings = %+v, want all messages, expiry deletion, limit 120, refresh 35 seconds and TTL 5 seconds", settings)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Settings.VerificationOnly || body.Settings.HTMLLinkLifecycleEnabled || !body.Settings.HTMLExpiryDeleteMailbox || body.Settings.HTMLPageMessageLimit != 120 || body.Settings.HTMLPageRefreshSeconds != 35 || body.Settings.HTMLLinkTTLSeconds != 5 {
		t.Fatalf("saved public settings = %+v", body.Settings)
	}

	for _, invalid := range []int{4, 3601} {
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/api/system-settings", strings.NewReader(fmt.Sprintf(`{"registration_enabled":true,"admin_path":"/manage","html_page_refresh_seconds":%d}`, invalid)))
		req.AddCookie(adminCookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("save refresh %d seconds = %d body=%s, want 400", invalid, rr.Code, rr.Body.String())
		}
	}
}

func TestSystemSettingsCanConfigureDomainSMTPFromAdmin(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{DomainSMTPHost: "127.0.0.1"}, store, discardLogger())
	panel, ok := handler.(*Server)
	if !ok {
		t.Fatal("NewServer did not return *Server")
	}
	defer panel.StopDomainSMTP()
	adminCookie, _ := registerTestUser(t, handler, "smtp-settings-admin", "admin123")
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/system-settings", strings.NewReader(fmt.Sprintf(`{"registration_enabled":true,"admin_path":"/manage","domain_smtp_enabled":true,"domain_smtp_host":"127.0.0.1","domain_smtp_port":%d,"domain_smtp_max_message_bytes":1048576}`, port)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save SMTP settings = %d body=%s", rr.Code, rr.Body.String())
	}
	settings := store.SystemSettings()
	if !settings.DomainSMTPEnabled || settings.DomainSMTPHost != "127.0.0.1" || settings.DomainSMTPPort != port || settings.DomainSMTPMaxMessageBytes != 1048576 {
		t.Fatalf("stored SMTP settings = %+v", settings)
	}
	if !strings.Contains(rr.Body.String(), `"enabled":true`) {
		t.Fatalf("SMTP runtime status missing from save response: %s", rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/system-settings", strings.NewReader(fmt.Sprintf(`{"registration_enabled":true,"admin_path":"/manage","domain_smtp_enabled":false,"domain_smtp_host":"127.0.0.1","domain_smtp_port":%d,"domain_smtp_max_message_bytes":1048576}`, port)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(adminCookie)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), `"enabled":true`) {
		t.Fatalf("disable SMTP settings = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMailboxHTMLDataUsesConfiguredMessageLimit(t *testing.T) {
	store := newTestStore(t)
	settings := store.SystemSettings()
	settings.HTMLPageMessageLimit = 1
	settings.HTMLPageRefreshSeconds = 37
	if _, err := store.SaveSystemSettings(settings); err != nil {
		t.Fatal(err)
	}
	mailbox, err := store.AddMailbox("", "limited", "limited@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	link, ok := store.MailboxHTMLLinkForMailbox(mailbox.ID)
	if !ok {
		t.Fatal("mailbox HTML link missing")
	}
	now := time.Now()
	if _, err := store.AddMessage(mailbox.ID, "Verification code", "codes@example.test", "Use 246810 to continue.", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMessage(mailbox.ID, "Newest notification", "alerts@example.test", "Your settings were updated.", now); err != nil {
		t.Fatal(err)
	}

	handler := NewServer(Config{}, store, discardLogger())
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mailbox/"+link.Token+"/data", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("mailbox HTML data = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Messages       []publicMessage `json:"messages"`
		MessageLimit   int             `json:"message_limit"`
		RefreshSeconds int             `json:"refresh_seconds"`
		Latest         struct {
			Code string `json:"code"`
		} `json:"latest"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.MessageLimit != 1 || len(body.Messages) != 1 || body.Messages[0].Subject != "Newest notification" {
		t.Fatalf("limited HTML messages = %+v limit=%d", body.Messages, body.MessageLimit)
	}
	if body.RefreshSeconds != 37 {
		t.Fatalf("HTML refresh seconds = %d, want 37", body.RefreshSeconds)
	}
	if body.Latest.Code != "246810" {
		t.Fatalf("latest verification code = %q, want 246810 from messages outside display limit", body.Latest.Code)
	}
}

func TestExpiredMailboxHTMLLinksAreRetainedUntilExplicitRegeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now()
	state := State{
		NextID: 2,
		Mailboxes: []Mailbox{{
			ID: "mbx_1", Email: "keep-api@icloud.com", APIToken: "api-stays-valid",
			APIActive: true, ICloudActive: true, Status: StatusAvailable, CreatedAt: now, UpdatedAt: now,
		}},
		MailboxHTMLLinks: []MailboxHTMLLink{{Token: "expired-html", MailboxID: "mbx_1", CreatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour)}},
		SystemSettings:   SystemSettings{RegistrationEnabled: true, AdminPath: "/manage", HTMLLinkTTLDays: 7, UpdatedAt: now},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if snapshot.SystemSettings.HTMLLinkTTLSeconds != 604800 || snapshot.SystemSettings.HTMLLinkTTLDays != 0 {
		t.Fatalf("legacy HTML TTL migration = %+v, want 604800 seconds", snapshot.SystemSettings)
	}
	if len(snapshot.MailboxHTMLLinks) != 1 {
		t.Fatalf("HTML links after reload = %d, want one retained link", len(snapshot.MailboxHTMLLinks))
	}
	retained := snapshot.MailboxHTMLLinks[0]
	if retained.Token != "expired-html" || retained.MailboxID != "mbx_1" || retained.ActivatedAt.IsZero() || !retained.ExpiresAt.Equal(state.MailboxHTMLLinks[0].ExpiresAt) {
		t.Fatalf("invalid retained HTML link: %+v", retained)
	}
	if _, ok := store.FindMailboxHTMLLink("expired-html"); ok {
		t.Fatal("expired HTML link should return gone instead of remaining accessible")
	}
	if links := store.ExpiredMailboxHTMLLinks(time.Now()); len(links) != 1 || links[0].Token != "expired-html" {
		t.Fatalf("expired HTML links = %+v, want retained link while auto-delete is off", links)
	}
	if len(snapshot.Mailboxes) != 1 || snapshot.Mailboxes[0].APIToken != "api-stays-valid" || !snapshot.Mailboxes[0].APIActive {
		t.Fatalf("mailbox API changed while retaining expiry state: %+v", snapshot.Mailboxes)
	}
	replacement, err := store.CreateMailboxHTMLLink("mbx_1", false)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Token == "" || replacement.Token == "expired-html" || !replacement.ActivatedAt.IsZero() || !replacement.ExpiresAt.IsZero() {
		t.Fatalf("explicit regeneration did not create a new inactive HTML link: %+v", replacement)
	}
}

func TestDisabledHTMLLinkLifecycleKeepsLinksPermanent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now()
	state := State{
		NextID: 2,
		Mailboxes: []Mailbox{{
			ID: "mbx_permanent", Email: "permanent@example.com", APIToken: "api-permanent",
			APIActive: true, ICloudActive: true, Status: StatusAvailable, CreatedAt: now, UpdatedAt: now,
		}},
		MailboxHTMLLinks: []MailboxHTMLLink{{
			Token: "permanent-html", MailboxID: "mbx_permanent", CreatedAt: now.Add(-48 * time.Hour),
			ActivatedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(-time.Hour),
		}},
		SystemSettings: SystemSettings{
			RegistrationEnabled: true, AdminPath: "/manage", HTMLLinkTTLSeconds: 60,
			HTMLLinkLifecycleDisabled: true, UpdatedAt: now,
		},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if link, ok := store.FindMailboxHTMLLink("permanent-html"); !ok || link.Token != "permanent-html" {
		t.Fatalf("disabled lifecycle link lookup = %+v, ok=%v", link, ok)
	}
	if links := store.ExpiredMailboxHTMLLinks(now); len(links) != 0 {
		t.Fatalf("disabled lifecycle should not expose expired links: %+v", links)
	}
	if link, ok, err := store.ActivateMailboxHTMLLink("permanent-html", now); err != nil || !ok || !link.ExpiresAt.IsZero() {
		t.Fatalf("disabled lifecycle activation = %+v, ok=%v, err=%v; want permanent link", link, ok, err)
	}
}

func TestExpiredHTMLMailboxAutoDeleteWaitsForRemoteSuccess(t *testing.T) {
	for _, tt := range []struct {
		name       string
		remoteErr  error
		wantExists bool
	}{
		{name: "remote success", wantExists: false},
		{name: "remote failure", remoteErr: errors.New("temporary remote failure"), wantExists: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, mailbox, expiredLink := newExpiredHTMLAutoDeleteStore(t)
			if links := store.ExpiredMailboxHTMLLinks(time.Now()); len(links) != 1 || links[0].Token != expiredLink.Token {
				t.Fatalf("expired links = %+v, want preserved link %q", links, expiredLink.Token)
			}
			if _, ok, err := store.ActivateMailboxHTMLLink(expiredLink.Token, time.Now()); err != nil || ok {
				t.Fatalf("activate expired link ok=%v err=%v, want gone", ok, err)
			}
			if link, ok := store.MailboxHTMLLinkForMailbox(mailbox.ID); !ok || link.Token != expiredLink.Token {
				t.Fatalf("pending-delete HTML link = %+v ok=%v, want original expired link", link, ok)
			}

			server := NewServer(Config{}, store, discardLogger()).(*Server)
			rr := httptest.NewRecorder()
			server.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mailbox/"+expiredLink.Token, nil))
			if rr.Code != http.StatusGone {
				t.Fatalf("expired public HTML status = %d body=%s, want 410", rr.Code, rr.Body.String())
			}
			var calls int
			server.deletePrivacyMailbox = func(ctx context.Context, session ICloudSession, email string) (ICloudMailboxDeleteResult, error) {
				calls++
				if session.AccountID != mailbox.AccountID || email != mailbox.Email {
					t.Fatalf("remote delete input = session:%+v email:%q", session, email)
				}
				if tt.remoteErr != nil {
					return ICloudMailboxDeleteResult{}, tt.remoteErr
				}
				return ICloudMailboxDeleteResult{Email: email, Found: true, Deleted: true}, nil
			}
			server.cleanupExpiredHTMLMailboxes(context.Background(), time.Now())
			if calls != 1 {
				t.Fatalf("remote delete calls = %d, want 1", calls)
			}
			_, exists := store.FindMailboxByID(mailbox.ID)
			if exists != tt.wantExists {
				t.Fatalf("mailbox exists = %v, want %v", exists, tt.wantExists)
			}
			if tt.wantExists {
				if len(store.MessagesForMailbox(mailbox.ID)) != 1 || len(store.ExpiredMailboxHTMLLinks(time.Now())) != 1 {
					t.Fatalf("local data was changed after remote failure: %+v", store.Snapshot())
				}
				return
			}
			if len(store.MessagesForMailbox(mailbox.ID)) != 0 {
				t.Fatalf("messages remain after auto delete: %+v", store.MessagesForMailbox(mailbox.ID))
			}
			for _, link := range store.Snapshot().MailboxHTMLLinks {
				if link.MailboxID == mailbox.ID {
					t.Fatalf("HTML link remains after auto delete: %+v", link)
				}
			}
		})
	}
}

func newExpiredHTMLAutoDeleteStore(t *testing.T) (*FileStore, Mailbox, MailboxHTMLLink) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now()
	mailbox := Mailbox{
		ID: "mbx_expired", OwnerID: "usr_expired", AccountID: "acc_expired", Email: "expired@icloud.com",
		APIToken: "test-api-token", APIActive: true, ICloudActive: true, Status: StatusAvailable, CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now,
	}
	link := MailboxHTMLLink{
		Token: "expired-auto-delete", MailboxID: mailbox.ID, OwnerID: mailbox.OwnerID,
		CreatedAt: now.Add(-48 * time.Hour), ActivatedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}
	state := State{
		NextID:    20,
		Mailboxes: []Mailbox{mailbox},
		Messages:  []Message{{ID: "msg_expired", OwnerID: mailbox.OwnerID, MailboxID: mailbox.ID, Subject: "Saved message", Body: "saved", CreatedAt: now.Add(-2 * time.Hour)}},
		ICloudSessions: []ICloudSession{{
			OwnerID: mailbox.OwnerID, AccountID: mailbox.AccountID, AppleID: "expired-owner@example.test", DSID: "expired-dsid",
			PremiumMailBaseURL: "https://mail.example.invalid", Cookies: []SessionCookie{{Name: "session", Value: "test"}},
		}},
		MailboxHTMLLinks: []MailboxHTMLLink{link},
		SystemSettings: SystemSettings{
			RegistrationEnabled: true, AdminPath: "/manage", HTMLLinkTTLDays: 1, HTMLExpiryDeleteMailbox: true, UpdatedAt: now,
		},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return store, mailbox, link
}

func TestStoreMigratesLegacyMailboxesToSoleOwnerAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now()
	state := State{
		NextID: 10,
		Users: []User{{
			ID:        "usr_1",
			Username:  "owner@example.com",
			Status:    StatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		}},
		Accounts: []Account{{
			ID:           "acc_1",
			OwnerID:      "usr_1",
			Label:        "main",
			AppleID:      "owner@example.com",
			Status:       StatusActive,
			ICloudStatus: ICloudStatusActive,
			CreatedAt:    now,
			UpdatedAt:    now,
		}},
		Mailboxes: []Mailbox{{
			ID:           "mbx_1",
			OwnerID:      "usr_1",
			Label:        "legacy",
			Email:        "alias@icloud.com",
			APIToken:     "token",
			APIActive:    true,
			ICloudActive: true,
			Status:       StatusAvailable,
			CreatedAt:    now,
			UpdatedAt:    now,
		}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if got := snapshot.Mailboxes[0].AccountID; got != "acc_1" {
		t.Fatalf("legacy mailbox account_id = %q, want acc_1", got)
	}
}

func TestClaimMailboxRequiresGlobalAPIKeyAndMarksUsed(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-key", PublicBaseURL: "https://mail.example"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{"project":"openai","purpose":"register"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("claim without key = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/claim", strings.NewReader(`{"project":"openai","purpose":"register"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer global-key")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("claim with key = %d, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool          `json:"success"`
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Mailbox.ID != mailbox.ID || body.Mailbox.Status != StatusUsed {
		t.Fatalf("claim body = %+v", body)
	}
	if !strings.HasPrefix(body.Mailbox.APIURL, "https://mail.example/") {
		t.Fatalf("api_url = %q", body.Mailbox.APIURL)
	}
	updated, ok := store.FindMailboxByID(mailbox.ID)
	if !ok || updated.Status != StatusUsed {
		t.Fatalf("stored mailbox = %+v ok=%v", updated, ok)
	}
}

func TestLookupMailboxesRequiresGlobalAPIKeyAndKeepsStatus(t *testing.T) {
	store := newTestStore(t)
	mailbox, err := store.AddMailbox("", "UPI-1", "alias@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{APIKey: "global-key", PublicBaseURL: "https://mail.example"}, store, discardLogger())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/lookup", strings.NewReader(`{"emails":["alias@icloud.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("lookup without key = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/mailboxes/lookup", strings.NewReader(`{"emails":["ALIAS@icloud.com","missing@icloud.com"]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer global-key")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup with key = %d, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool            `json:"success"`
		Mailboxes []publicMailbox `json:"mailboxes"`
		Missing   []string        `json:"missing"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || len(body.Mailboxes) != 1 || body.Mailboxes[0].ID != mailbox.ID {
		t.Fatalf("lookup body = %+v", body)
	}
	if len(body.Missing) != 1 || body.Missing[0] != "missing@icloud.com" {
		t.Fatalf("missing = %+v", body.Missing)
	}
	if !strings.HasPrefix(body.Mailboxes[0].APIURL, "https://mail.example/") {
		t.Fatalf("api_url = %q", body.Mailboxes[0].APIURL)
	}
	updated, ok := store.FindMailboxByEmail("alias@icloud.com")
	if !ok || updated.Status != StatusAvailable {
		t.Fatalf("lookup changed mailbox status: %+v ok=%v", updated, ok)
	}
}

func TestMailboxSchedulerStartsCreatesAndStops(t *testing.T) {
	withDefaultMailboxSchedulerRoundInterval(t, 10*time.Millisecond)
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-user", "timer123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		SavedAt:            time.Now(),
		DSID:               "dsid-1",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}

	var seq int64
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		select {
		case <-ctx.Done():
			return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
		default:
		}
		n := atomic.AddInt64(&seq, 1)
		if n > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("sched-%d@icloud.com", n))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(`{"batch_size":200,"interval_seconds":60,"label":"SCH"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}

	var status struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/icloud/scheduler/status", nil)
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("scheduler status = %d body=%s", rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Scheduler.Success >= 2 && status.Scheduler.Failed >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.Scheduler.BatchSize != 1 {
		t.Fatalf("scheduler batch size = %d, want hidden request batch_size ignored as 1", status.Scheduler.BatchSize)
	}
	if status.Scheduler.Success != 2 || status.Scheduler.Failed != 1 || len(status.Scheduler.Events) == 0 {
		t.Fatalf("scheduler did not create until account failed: %+v", status.Scheduler)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Scheduler.Running {
		t.Fatalf("scheduler still running after stop: %+v", status.Scheduler)
	}
}

func withDefaultMailboxSchedulerRoundInterval(t *testing.T, interval time.Duration) {
	t.Helper()
	old := defaultMailboxSchedulerRoundInterval
	defaultMailboxSchedulerRoundInterval = interval
	t.Cleanup(func() {
		defaultMailboxSchedulerRoundInterval = old
	})
}

func TestMailboxSchedulerStatusDefaultsRoundInterval(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, _ := registerTestUser(t, handler, "timer-default-round", "timer123")

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/icloud/scheduler/status", nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("scheduler status = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Scheduler.RoundIntervalSeconds != 5 {
		t.Fatalf("default round interval = %d, want 5", body.Scheduler.RoundIntervalSeconds)
	}
}

func TestMailboxSchedulerStartAcceptsRoundIntervalSeconds(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-custom-round", "timer123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:            user.ID,
		SavedAt:            time.Now(),
		DSID:               "dsid-round",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		<-ctx.Done()
		return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(`{"interval_minutes":60,"round_interval_seconds":7,"label":"SCH"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	defer func() {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
	}()
	var body struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Scheduler.RoundIntervalSeconds != 7 {
		t.Fatalf("round interval = %d, want 7", body.Scheduler.RoundIntervalSeconds)
	}
}

func TestMailboxSchedulerClearLogsKeepsCounters(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-clear", "timer123")

	job := &mailboxSchedulerJob{
		nextEventID: 2,
		state: mailboxSchedulerState{
			OwnerID:         user.ID,
			Owner:           user.Username,
			BatchSize:       1,
			IntervalSeconds: int(time.Hour.Seconds()),
			Status:          "running",
			Success:         3,
			Failed:          1,
		},
		events: []mailboxSchedulerEvent{
			{ID: 2, At: time.Now(), Type: "failed", Message: "失败记录", Batch: 1, Error: "额度已用完"},
			{ID: 1, At: time.Now(), Type: "created", Message: "创建成功", Batch: 1, Email: "created@icloud.com"},
		},
	}
	server.schedulerMu.Lock()
	server.mailboxSchedulers[user.ID] = job
	server.schedulerMu.Unlock()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/logs/clear", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear scheduler logs = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Scheduler.Events) != 0 {
		t.Fatalf("scheduler events after clear = %+v, want empty", body.Scheduler.Events)
	}
	if body.Scheduler.Success != 3 || body.Scheduler.Failed != 1 {
		t.Fatalf("scheduler counters changed after clear: %+v", body.Scheduler)
	}
}

func TestMailboxSchedulerRunsUntilAllAccountsFailWithOnlyInterval(t *testing.T) {
	withDefaultMailboxSchedulerRoundInterval(t, 10*time.Millisecond)
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "timer-until-fail", "timer123")
	for _, session := range []ICloudSession{
		{
			OwnerID:            user.ID,
			AppleID:            "limit@example.com",
			DSID:               "dsid-limit",
			PremiumMailBaseURL: "https://example.invalid",
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie-1", Domain: ".icloud.com", Path: "/"}},
		},
		{
			OwnerID:            user.ID,
			AppleID:            "worker@example.com",
			DSID:               "dsid-worker",
			PremiumMailBaseURL: "https://example.invalid",
			IsICloudPlus:       true,
			CanCreateHME:       true,
			Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie-2", Domain: ".icloud.com", Path: "/"}},
		},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	limitAccountID := sessions[0].AccountID
	workerAccountID := sessions[1].AccountID
	accountIDs := []string{limitAccountID, workerAccountID}

	var mu sync.Mutex
	attempts := map[string]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		select {
		case <-ctx.Done():
			return Mailbox{}, ICloudRemoteMailbox{}, ctx.Err()
		default:
		}
		mu.Lock()
		attempts[accountID]++
		n := attempts[accountID]
		mu.Unlock()
		if accountID == limitAccountID {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "第一个账号额度已用完", true)
		}
		if n > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "第二个账号额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("%s-%d@icloud.com", accountID, n))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	body := fmt.Sprintf(`{"account_ids":["%s","%s"],"interval_seconds":60,"label":"SCH"}`, accountIDs[0], accountIDs[1])
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("start scheduler = %d body=%s", rr.Code, rr.Body.String())
	}
	defer func() {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/icloud/scheduler/stop", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
	}()

	var status struct {
		Scheduler publicMailboxScheduler `json:"scheduler"`
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/icloud/scheduler/status", nil)
		req.AddCookie(cookie)
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("scheduler status = %d body=%s", rr.Code, rr.Body.String())
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status.Scheduler.Success >= 2 && status.Scheduler.Failed >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status.Scheduler.BatchSize != 1 {
		t.Fatalf("scheduler batch size = %d, want 1", status.Scheduler.BatchSize)
	}
	if status.Scheduler.Success != 2 || status.Scheduler.Failed != 2 {
		t.Fatalf("scheduler state = success %d failed %d, want success=2 failed=2: %+v", status.Scheduler.Success, status.Scheduler.Failed, status.Scheduler)
	}
	mu.Lock()
	if attempts[limitAccountID] != 1 {
		mu.Unlock()
		t.Fatalf("limited account attempts = %d, want 1; attempts=%+v", attempts[limitAccountID], attempts)
	}
	if attempts[workerAccountID] != 3 {
		mu.Unlock()
		t.Fatalf("worker account attempts = %d, want 3; attempts=%+v", attempts[workerAccountID], attempts)
	}
	mu.Unlock()
}

func TestMailboxSchedulerBatchWaitsBetweenCreateRounds(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-round-wait"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "round@example.com",
		DSID:               "dsid-round-wait",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	var attemptTimes []time.Time
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		attemptsMu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		attempt := len(attemptTimes)
		attemptsMu.Unlock()
		if attempt > 2 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("round-%d@icloud.com", attempt))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	roundInterval := 40 * time.Millisecond
	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs:    []string{accountID},
		Label:         "SCH",
		BatchSize:     1,
		RoundInterval: roundInterval,
	}, 1)
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if len(attemptTimes) != 3 {
		t.Fatalf("attempts = %d, want 3", len(attemptTimes))
	}
	for i := 1; i < len(attemptTimes); i++ {
		if got := attemptTimes[i].Sub(attemptTimes[i-1]); got < roundInterval-5*time.Millisecond {
			t.Fatalf("attempt %d delay = %s, want at least %s", i+1, got, roundInterval)
		}
	}
}

func TestMailboxSchedulerSkipsFailedAccountWithinCurrentBatch(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-skip"
	for _, session := range []ICloudSession{
		{OwnerID: ownerID, AppleID: "bad@example.com", DSID: "dsid-bad", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: ownerID, AppleID: "good@example.com", DSID: "dsid-good", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	badAccountID := sessions[0].AccountID
	goodAccountID := sessions[1].AccountID
	var attemptsMu sync.Mutex
	attempts := map[string]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		attemptsMu.Lock()
		attempts[accountID]++
		attempt := attempts[accountID]
		attemptsMu.Unlock()
		if accountID == badAccountID {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
		}
		if attempt > 3 {
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "好账号本轮也已用完", true)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, fmt.Sprintf("good-%d@icloud.com", attempt))
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{badAccountID, goodAccountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts[badAccountID] != 1 {
		t.Fatalf("bad account attempts = %d, want 1; attempts=%+v", attempts[badAccountID], attempts)
	}
	if attempts[goodAccountID] != 4 {
		t.Fatalf("good account attempts = %d, want 4; attempts=%+v", attempts[goodAccountID], attempts)
	}
	if state.Success != 3 || state.Failed != 2 {
		t.Fatalf("scheduler state = %+v, want success=3 failed=2", state)
	}
	if len(events) != 6 {
		t.Fatalf("events = %d, want 6: %+v", len(events), events)
	}
}

func TestMailboxSchedulerFallsBackToOldInterfaceAfterNewInterfaceFails(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-fallback"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "fallback@example.com",
		DSID:               "dsid-fallback",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt", SessionID: "sid"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	attempts := map[mailboxCreateChannel]int{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := mailboxCreateChannelFromContext(ctx)
		attemptsMu.Lock()
		attempts[channel]++
		attempt := attempts[channel]
		attemptsMu.Unlock()
		switch channel {
		case mailboxCreateChannelAppleAccount:
			if attempt > 2 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_limit", "新接口当前小时额度已用完", true)
			}
		case mailboxCreateChannelICloudWeb:
			if attempt > 1 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "旧接口当前小时额度已用完", true)
			}
		default:
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("unexpected_channel", "定时创建没有指定接口", false)
		}
		email := fmt.Sprintf("%s-%d@icloud.com", channel, attempt)
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, email)
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{accountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	if attempts[mailboxCreateChannelAppleAccount] != 3 {
		t.Fatalf("new interface attempts = %d, want 3; attempts=%+v", attempts[mailboxCreateChannelAppleAccount], attempts)
	}
	if attempts[mailboxCreateChannelICloudWeb] != 2 {
		t.Fatalf("old interface attempts = %d, want 2; attempts=%+v", attempts[mailboxCreateChannelICloudWeb], attempts)
	}
	if state.Success != 3 || state.Failed != 1 {
		t.Fatalf("scheduler state = %+v, want success=3 failed=1", state)
	}
	var sawSwitch, sawNewCreated, sawOldCreated, sawOldFailed, sawAccountLabel bool
	for _, event := range events {
		if event.Type == "channel_failed" && strings.Contains(event.Message, "切换旧接口继续尝试") {
			sawSwitch = true
		}
		if event.Type == "created" && strings.Contains(event.Message, "新接口创建成功") {
			sawNewCreated = true
		}
		if event.Type == "created" && strings.Contains(event.Message, "旧接口创建成功") {
			sawOldCreated = true
		}
		if event.Type == "failed" && strings.Contains(event.Message, "旧接口创建失败") {
			sawOldFailed = true
		}
		if strings.Contains(event.Message, "fallback@example.com") {
			sawAccountLabel = true
		}
	}
	if !sawSwitch {
		t.Fatalf("events did not include old-interface fallback: %+v", events)
	}
	if !sawNewCreated || !sawOldCreated || !sawOldFailed {
		t.Fatalf("events did not include create channel labels: newCreated=%v oldCreated=%v oldFailed=%v events=%+v", sawNewCreated, sawOldCreated, sawOldFailed, events)
	}
	if !sawAccountLabel {
		t.Fatalf("events did not include login account label: %+v", events)
	}
}

func TestMailboxSchedulerRetriesNewInterfaceAfterTransientEmptyResponse(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-scheduler-transient-new"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "transient@example.com",
		DSID:               "dsid-transient",
		PremiumMailBaseURL: "https://example.invalid",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "X-APPLE-WEBAUTH", Value: "cookie", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt", SessionID: "sid"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID

	var attemptsMu sync.Mutex
	attempts := map[mailboxCreateChannel]int{}
	var sequence []mailboxCreateChannel
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := mailboxCreateChannelFromContext(ctx)
		attemptsMu.Lock()
		attempts[channel]++
		attempt := attempts[channel]
		sequence = append(sequence, channel)
		attemptsMu.Unlock()
		switch channel {
		case mailboxCreateChannelAppleAccount:
			switch attempt {
			case 1:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_generate_empty", "Apple Account 未返回候选隐私邮箱；阶段：生成候选隐私邮箱；HTTP 200；原始返回：空响应", true)
			case 2:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_generate_empty", "Apple Account 未返回候选隐私邮箱；阶段：生成候选隐私邮箱；HTTP 200；原始返回：空响应", true)
			default:
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("apple_account_hme_limit", "新接口当前小时额度已用完", true)
			}
		case mailboxCreateChannelICloudWeb:
			if attempt > 1 {
				return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "旧接口当前小时额度已用完", true)
			}
		default:
			return Mailbox{}, ICloudRemoteMailbox{}, errCode("unexpected_channel", "定时创建没有指定接口", false)
		}
		email := fmt.Sprintf("%s-%d@icloud.com", channel, attempt)
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, email)
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	job := &mailboxSchedulerJob{state: mailboxSchedulerState{Running: true, BatchSize: 1}}
	server.runMailboxSchedulerBatch(context.Background(), ownerID, job, mailboxSchedulerConfig{
		AccountIDs: []string{accountID},
		Label:      "SCH",
		BatchSize:  1,
	}, 1)
	state, events := job.snapshot()
	attemptsMu.Lock()
	defer attemptsMu.Unlock()
	wantSequence := []mailboxCreateChannel{
		mailboxCreateChannelAppleAccount,
		mailboxCreateChannelAppleAccount,
		mailboxCreateChannelICloudWeb,
		mailboxCreateChannelICloudWeb,
	}
	if !reflect.DeepEqual(sequence, wantSequence) {
		t.Fatalf("channel sequence = %+v, want %+v", sequence, wantSequence)
	}
	if state.Success != 1 || state.Failed != 1 {
		t.Fatalf("scheduler state = %+v, want success=1 failed=1", state)
	}
	var sawTransientRetry bool
	var sawTransientFallback bool
	for _, event := range events {
		if event.Type == "channel_failed" && strings.Contains(event.Message, "HTTP 200") && strings.Contains(event.Message, "下轮重试新接口") {
			sawTransientRetry = true
		}
		if event.Type == "channel_failed" && strings.Contains(event.Message, "HTTP 200") && strings.Contains(event.Message, "切换旧接口继续尝试") {
			sawTransientFallback = true
		}
	}
	if !sawTransientRetry || !sawTransientFallback {
		t.Fatalf("events did not include transient retry and fallback: retry=%v fallback=%v events=%+v", sawTransientRetry, sawTransientFallback, events)
	}
}

func TestCreateAppleAccountMailboxKeepsRefreshedStateWhenCreateFails(t *testing.T) {
	oldBaseURL := appleAccountManageBaseURL
	defer func() { appleAccountManageBaseURL = oldBaseURL }()

	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	ownerID := "owner-apple-refresh-fail"
	if err := store.SaveICloudSessionForOwner(ownerID, ICloudSession{
		OwnerID: ownerID,
		AppleID: "refresh-fail@example.com",
		LoginStates: []LoginState{{
			Kind:      LoginStateAppleAccount,
			Host:      "appleid.apple.com",
			Origin:    "https://account.apple.com",
			Scnt:      "stale-scnt",
			SessionID: "sid",
			APIKey:    "stale-key",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	session := sessions[0]

	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /account/manage/gs/ws/token":
			if r.Header.Get("scnt") != "stale-scnt" {
				t.Fatalf("token scnt header = %q, want stale-scnt", r.Header.Get("scnt"))
			}
			w.Header().Set("scnt", "fresh-token-scnt")
			http.SetCookie(w, &http.Cookie{Name: "token-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"timeOutInterval":15}`))
		case "GET /account/manage":
			if r.Header.Get("scnt") != "fresh-token-scnt" {
				t.Fatalf("manage scnt header = %q, want fresh-token-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "token-cookie=ok") {
				t.Fatalf("manage cookie header = %q, want token response cookie", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "fresh-manage-scnt")
			http.SetCookie(w, &http.Cookie{Name: "manage-cookie", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`{"apiKey":"fresh-key"}`))
		case "POST /account/manage/email/private/add":
			if r.Header.Get("X-Apple-Api-Key") != "fresh-key" {
				t.Fatalf("add api key header = %q, want fresh-key", r.Header.Get("X-Apple-Api-Key"))
			}
			if r.Header.Get("scnt") != "fresh-manage-scnt" {
				t.Fatalf("add scnt header = %q, want fresh-manage-scnt", r.Header.Get("scnt"))
			}
			if !strings.Contains(r.Header.Get("Cookie"), "manage-cookie=ok") {
				t.Fatalf("add cookie header = %q, want refreshed cookies", r.Header.Get("Cookie"))
			}
			w.Header().Set("scnt", "fresh-failed-scnt")
			http.SetCookie(w, &http.Cookie{Name: "fail-cookie", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`You have reached the limit of addresses you can create right now. Please try again later.`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()
	appleAccountManageBaseURL = ts.URL

	accountKey := mailboxCreateAccountKey(ownerID, session)
	_, err := server.createICloudMailboxRemoteAppleAccount(context.Background(), ownerID, session, "LAB", "", accountKey)
	if err == nil {
		t.Fatal("create error = nil, want Apple Account limit error")
	}
	got := store.ICloudSessionsForOwner(ownerID)[0]
	state, ok := appleAccountLoginState(got)
	if !ok || state.Scnt != "fresh-failed-scnt" || state.APIKey != "fresh-key" {
		t.Fatalf("saved apple account state = %+v ok=%v, want rotated state from failed create response", state, ok)
	}
	cookie := cookieHeader(state.Cookies, ts.URL+"/account/manage/email/private/add")
	if !strings.Contains(cookie, "fail-cookie=ok") {
		t.Fatalf("saved cookie header = %q, want failed response cookie preserved", cookie)
	}
	if !strings.Contains(cookie, "manage-cookie=ok") {
		t.Fatalf("saved cookie header = %q, want last successful manage cookie", cookie)
	}
	if remaining := server.mailboxCreateCooldownRemaining(mailboxCreateChannelCooldownKey(accountKey, mailboxCreateChannelAppleAccount)); remaining <= 0 {
		t.Fatalf("apple account cooldown remaining = %v, want positive", remaining)
	}
	if remaining := server.mailboxCreateCooldownRemaining(mailboxCreateChannelCooldownKey(accountKey, mailboxCreateChannelICloudWeb)); remaining > 0 {
		t.Fatalf("icloud web cooldown remaining = %v, want zero when only Apple Account hit limit", remaining)
	}
	wantPaths := []string{
		"GET /account/manage/gs/ws/token",
		"GET /account/manage",
		"POST /account/manage/email/private/add",
	}
	if strings.Join(paths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, wantPaths)
	}
}

func TestSaveICloudSessionForOwnerKeepsMultipleAppleAccounts(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-multi"
	for _, session := range []ICloudSession{
		{OwnerID: ownerID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: ownerID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2: %+v", len(sessions), sessions)
	}
	if sessions[0].AccountID == "" || sessions[1].AccountID == "" || sessions[0].AccountID == sessions[1].AccountID {
		t.Fatalf("account ids not separated: %+v", sessions)
	}
	state := store.SnapshotForOwner(ownerID)
	if len(state.Accounts) != 2 {
		t.Fatalf("accounts = %d, want 2: %+v", len(state.Accounts), state.Accounts)
	}
}

func TestSaveICloudSessionForOwnerMergesLoginStates(t *testing.T) {
	store := newTestStore(t)
	ownerID := "owner-merge"
	icloudSession := ICloudSession{
		OwnerID:            ownerID,
		AppleID:            "same@example.com",
		DSID:               "dsid-same",
		ClientID:           "client",
		PremiumMailBaseURL: "https://p-maildomainws.icloud.com",
		Host:               "www.icloud.com",
		IsICloudPlus:       true,
		CanCreateHME:       true,
		Cookies:            []SessionCookie{{Name: "icloud", Value: "ok", Domain: ".icloud.com", Path: "/"}},
		LoginStates: []LoginState{{
			Kind:    LoginStateICloudWeb,
			Host:    "www.icloud.com",
			Cookies: []SessionCookie{{Name: "icloud", Value: "ok", Domain: ".icloud.com", Path: "/"}},
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, icloudSession); err != nil {
		t.Fatal(err)
	}
	appleAccountSession := ICloudSession{
		OwnerID: ownerID,
		AppleID: "same@example.com",
		LoginStates: []LoginState{{
			Kind:   LoginStateAppleAccount,
			Host:   "appleid.apple.com",
			Scnt:   "scnt",
			APIKey: "api-key",
		}},
	}
	if err := store.SaveICloudSessionForOwner(ownerID, appleAccountSession); err != nil {
		t.Fatal(err)
	}

	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1: %+v", len(sessions), sessions)
	}
	got := sessions[0]
	if got.DSID != icloudSession.DSID || got.PremiumMailBaseURL != icloudSession.PremiumMailBaseURL || len(got.Cookies) != 1 {
		t.Fatalf("iCloud state was not preserved: %+v", got)
	}
	if _, ok := appleAccountLoginState(got); !ok {
		t.Fatalf("apple account login state missing after merge: %+v", got.LoginStates)
	}
	if !hasLoginStateKind(got.LoginStates, LoginStateICloudWeb) {
		t.Fatalf("iCloud login state missing after merge: %+v", got.LoginStates)
	}
}

func TestSyncICloudMailboxesIsolatesSlowAccounts(t *testing.T) {
	oldTimeout := iCloudMailboxListAccountTimeout
	iCloudMailboxListAccountTimeout = 120 * time.Millisecond
	defer func() { iCloudMailboxListAccountTimeout = oldTimeout }()

	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "sync-isolate", "sync123")

	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer slowServer.Close()
	fastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"success": true,
			"timestamp": 1,
			"result": {
				"forwardToEmails": ["main@example.com"],
				"hmeEmails": [
					{"anonymousId":"fast1","hme":"Fast.Sync@iCloud.com","label":"FAST","isActive":true,"forwardToEmail":"main@example.com","origin":"ON_DEMAND"}
				]
			}
		}`))
	}))
	defer fastServer.Close()

	for _, session := range []ICloudSession{
		{
			OwnerID:            user.ID,
			AppleID:            "slow@example.com",
			DSID:               "slow-dsid",
			ClientID:           "slow-client",
			PremiumMailBaseURL: slowServer.URL,
			Host:               "www.icloud.com",
			Cookies:            []SessionCookie{{Name: "session", Value: "slow", Domain: "127.0.0.1", Path: "/"}},
		},
		{
			OwnerID:            user.ID,
			AppleID:            "fast@example.com",
			DSID:               "fast-dsid",
			ClientID:           "fast-client",
			PremiumMailBaseURL: fastServer.URL,
			Host:               "www.icloud.com",
			Cookies:            []SessionCookie{{Name: "session", Value: "fast", Domain: "127.0.0.1", Path: "/"}},
		},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/sync", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	started := time.Now()
	handler.ServeHTTP(rr, req)
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("sync took %s, want isolated timeout under 1s", elapsed)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("sync = %d body=%s", rr.Code, rr.Body.String())
	}
	var data struct {
		Success   bool                      `json:"success"`
		Total     int                       `json:"total"`
		Created   int                       `json:"created"`
		Failed    int                       `json:"failed"`
		Results   []syncICloudMailboxResult `json:"results"`
		Mailboxes []publicMailbox           `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if !data.Success || data.Total != 1 || data.Created != 1 || data.Failed != 1 {
		t.Fatalf("response = %+v", data)
	}
	if len(data.Mailboxes) != 1 || data.Mailboxes[0].Email != "fast.sync@icloud.com" {
		t.Fatalf("mailboxes = %+v", data.Mailboxes)
	}
	if len(data.Results) != 2 {
		t.Fatalf("results len = %d, want 2", len(data.Results))
	}
	var sawTimeout, sawFast bool
	for _, result := range data.Results {
		if result.AppleID == "slow@example.com" && !strings.Contains(result.Error, "超时") {
			t.Fatalf("slow result = %+v, want timeout error", result)
		}
		if result.AppleID == "slow@example.com" {
			sawTimeout = true
		}
		if result.AppleID == "fast@example.com" && result.Created == 1 && result.Source == string(mailboxCreateChannelICloudWeb) {
			sawFast = true
		}
	}
	if !sawTimeout || !sawFast {
		t.Fatalf("results = %+v, want timeout and fast success", data.Results)
	}
}

func TestCreateICloudMailboxCreatesForEachSavedSession(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "multi-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	wantAccounts := map[string]bool{}
	for _, session := range sessions {
		wantAccounts[session.AccountID] = false
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		if ownerID != user.ID {
			t.Fatalf("ownerID = %q, want %q", ownerID, user.ID)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, accountID+"@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"LAB"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success   bool            `json:"success"`
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Created != 2 || len(body.Mailboxes) != 2 {
		t.Fatalf("body = %+v, want two mailboxes", body)
	}
	for _, mailbox := range body.Mailboxes {
		if _, ok := wantAccounts[mailbox.AccountID]; !ok {
			t.Fatalf("unexpected account id %q in mailbox %+v; want %+v", mailbox.AccountID, mailbox, wantAccounts)
		}
		wantAccounts[mailbox.AccountID] = true
	}
	for accountID, seen := range wantAccounts {
		if !seen {
			t.Fatalf("account %s did not create mailbox", accountID)
		}
	}
}

func TestCreateICloudMailboxUsesSelectedSavedSessions(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "selected-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "broken@example.com", DSID: "dsid-broken", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
		{OwnerID: user.ID, AppleID: "third@example.com", DSID: "dsid-third", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "c", Value: "3"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	selected := []string{sessions[0].AccountID, sessions[2].AccountID}
	var createdMu sync.Mutex
	createdAccounts := map[string]bool{}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		if accountID == sessions[1].AccountID {
			t.Fatalf("broken account %q should not be used", accountID)
		}
		createdMu.Lock()
		createdAccounts[accountID] = true
		createdMu.Unlock()
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, accountID+"@icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true}, nil
	}

	bodyJSON := fmt.Sprintf(`{"label":"SEL","account_ids":["%s","%s"]}`, selected[0], selected[1])
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Created != 2 || len(body.Mailboxes) != 2 {
		t.Fatalf("body = %+v, want two selected mailboxes", body)
	}
	createdMu.Lock()
	defer createdMu.Unlock()
	for _, accountID := range selected {
		if !createdAccounts[accountID] {
			t.Fatalf("selected account %q was not used; created=%+v", accountID, createdAccounts)
		}
	}
	if createdAccounts[sessions[1].AccountID] {
		t.Fatalf("unselected account %q was used", sessions[1].AccountID)
	}
}

func TestCreateICloudMailboxResponseIncludesCreateChannel(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "create-channel", "multi123")
	session := ICloudSession{
		OwnerID:      user.ID,
		AppleID:      "channel@example.com",
		DSID:         "dsid-channel",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "a", Value: "1"}},
	}
	if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
		t.Fatal(err)
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, "created@example.icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: "APPLE_ACCOUNT"}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"SOURCE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Created   int             `json:"created"`
		Mailboxes []publicMailbox `json:"mailboxes"`
		Remotes   []struct {
			Origin       string `json:"origin"`
			Channel      string `json:"channel"`
			ChannelLabel string `json:"channel_label"`
		} `json:"remotes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Created != 1 || len(body.Mailboxes) != 1 || len(body.Remotes) != 1 {
		t.Fatalf("body = %+v, want one created mailbox and remote", body)
	}
	if body.Mailboxes[0].CreateChannel != string(mailboxCreateChannelAppleAccount) || body.Mailboxes[0].CreateChannelLabel != "新接口" {
		t.Fatalf("mailbox channel = %q/%q, want apple_account/新接口", body.Mailboxes[0].CreateChannel, body.Mailboxes[0].CreateChannelLabel)
	}
	if body.Remotes[0].Origin != "APPLE_ACCOUNT" || body.Remotes[0].Channel != string(mailboxCreateChannelAppleAccount) || body.Remotes[0].ChannelLabel != "新接口" {
		t.Fatalf("remote channel = %+v, want APPLE_ACCOUNT apple_account 新接口", body.Remotes[0])
	}
}

func TestCreateICloudMailboxUsesRequestedCreateChannel(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "create-requested-channel", "multi123")
	if err := store.SaveICloudSessionForOwner(user.ID, ICloudSession{
		OwnerID:      user.ID,
		AppleID:      "requested-channel@example.com",
		DSID:         "dsid-requested-channel",
		IsICloudPlus: true,
		CanCreateHME: true,
		Cookies:      []SessionCookie{{Name: "a", Value: "1"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	sessions := store.ICloudSessionsForOwner(user.ID)
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	accountID := sessions[0].AccountID
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		channel := mailboxCreateChannelFromContext(ctx)
		if channel != mailboxCreateChannelICloudWeb {
			t.Fatalf("create channel = %q, want icloud_web", channel)
		}
		mailbox, err := store.AddMailboxForOwner(ownerID, accountID, label, "requested-old@example.icloud.com")
		if err != nil {
			return Mailbox{}, ICloudRemoteMailbox{}, err
		}
		return mailbox, ICloudRemoteMailbox{Email: mailbox.Email, Label: mailbox.Label, IsActive: true, Origin: string(channel)}, nil
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(fmt.Sprintf(`{"account_id":%q,"label":"REQ","create_channel":"icloud_web"}`, accountID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSettingsAreSavedServerSide(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	cookie, user := registerTestUser(t, handler, "create-settings", "multi123")
	account, err := store.AddAccountForOwner(user.ID, "A", "a@example.com", "")
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/create-settings", strings.NewReader(fmt.Sprintf(`{
		"label":"UPI",
		"note":"server side",
		"account_ids":[%q],
		"create_channel":"apple_account",
		"scheduler_create_channel":"icloud_web",
		"apple_account_two_factor_method":"phone",
		"icloud_web_two_factor_method":"trusted_device",
		"scheduler_interval_minutes":30,
		"scheduler_round_interval_seconds":8,
		"mailbox_page_size":25
	}`, account.ID)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("save settings = %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/create-settings", nil)
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get settings = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Settings struct {
			Label                         string   `json:"label"`
			Note                          string   `json:"note"`
			AccountIDs                    []string `json:"account_ids"`
			CreateChannel                 string   `json:"create_channel"`
			SchedulerCreateChannel        string   `json:"scheduler_create_channel"`
			AppleAccountTwoFactorMethod   string   `json:"apple_account_two_factor_method"`
			ICloudWebTwoFactorMethod      string   `json:"icloud_web_two_factor_method"`
			SchedulerIntervalMinutes      int      `json:"scheduler_interval_minutes"`
			SchedulerRoundIntervalSeconds int      `json:"scheduler_round_interval_seconds"`
			MailboxPageSize               int      `json:"mailbox_page_size"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Settings.Label != "UPI" ||
		body.Settings.Note != "server side" ||
		!reflect.DeepEqual(body.Settings.AccountIDs, []string{account.ID}) ||
		body.Settings.CreateChannel != string(mailboxCreateChannelAppleAccount) ||
		body.Settings.SchedulerCreateChannel != string(mailboxCreateChannelICloudWeb) ||
		body.Settings.AppleAccountTwoFactorMethod != appleTwoFactorMethodPhone ||
		body.Settings.ICloudWebTwoFactorMethod != appleTwoFactorMethodTrustedDevice ||
		body.Settings.SchedulerIntervalMinutes != 30 ||
		body.Settings.SchedulerRoundIntervalSeconds != 8 ||
		body.Settings.MailboxPageSize != 25 {
		t.Fatalf("settings = %+v, want saved server config", body.Settings)
	}
}

func TestSchedulerCreateChannelsRespectRequestedChannel(t *testing.T) {
	session := ICloudSession{
		Cookies: []SessionCookie{{Name: "a", Value: "1"}},
		LoginStates: []LoginState{
			{Kind: LoginStateAppleAccount, Host: "appleid.apple.com", Origin: "https://account.apple.com", Scnt: "scnt"},
			{Kind: LoginStateICloudWeb, Host: "www.icloud.com", Origin: "https://www.icloud.com", Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		},
	}
	if got := schedulerCreateChannelsForSession(session, mailboxCreateChannelICloudWeb); !reflect.DeepEqual(got, []mailboxCreateChannel{mailboxCreateChannelICloudWeb}) {
		t.Fatalf("old-only channels = %+v", got)
	}
	if got := schedulerCreateChannelsForSession(session, mailboxCreateChannelAppleAccount); !reflect.DeepEqual(got, []mailboxCreateChannel{mailboxCreateChannelAppleAccount}) {
		t.Fatalf("new-only channels = %+v", got)
	}
	if got := schedulerCreateChannelsForSession(session, mailboxCreateChannelAuto); !reflect.DeepEqual(got, []mailboxCreateChannel{mailboxCreateChannelAppleAccount, mailboxCreateChannelICloudWeb}) {
		t.Fatalf("auto channels = %+v", got)
	}
}

func TestCreateICloudMailboxReturnsAccountFailuresWhenAllSelectedSessionsFail(t *testing.T) {
	store := newTestStore(t)
	handler := NewServer(Config{PublicBaseURL: "https://mail.example"}, store, discardLogger())
	server := handler.(*Server)
	cookie, user := registerTestUser(t, handler, "all-fail-create", "multi123")
	for _, session := range []ICloudSession{
		{OwnerID: user.ID, AppleID: "first@example.com", DSID: "dsid-first", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "a", Value: "1"}}},
		{OwnerID: user.ID, AppleID: "second@example.com", DSID: "dsid-second", IsICloudPlus: true, CanCreateHME: true, Cookies: []SessionCookie{{Name: "b", Value: "2"}}},
	} {
		if err := store.SaveICloudSessionForOwner(user.ID, session); err != nil {
			t.Fatal(err)
		}
	}
	server.createMailboxForOwner = func(ctx context.Context, ownerID, accountID, label, note string) (Mailbox, ICloudRemoteMailbox, error) {
		return Mailbox{}, ICloudRemoteMailbox{}, errCode("icloud_hme_limit", "当前小时额度已用完", true)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/icloud/mailboxes/create", strings.NewReader(`{"label":"FAIL"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("create = %d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success  bool                   `json:"success"`
		Created  int                    `json:"created"`
		Failures []createMailboxFailure `json:"failures"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Success || body.Created != 0 || len(body.Failures) != 2 {
		t.Fatalf("body = %+v, want two account failures", body)
	}
}

func TestSyncMailboxUsesMailboxAccountSession(t *testing.T) {
	oldInterval := mailboxMailSyncMinInterval
	mailboxMailSyncMinInterval = 0
	t.Cleanup(func() { mailboxMailSyncMinInterval = oldInterval })

	store := newTestStore(t)
	ownerID := "owner-account-sync"
	for _, session := range []ICloudSession{
		testIMAPSession(ownerID, "", "first@example.com"),
		testIMAPSession(ownerID, "", "second@example.com"),
	} {
		if err := store.SaveICloudSessionForOwner(ownerID, session); err != nil {
			t.Fatal(err)
		}
	}
	sessions := store.ICloudSessionsForOwner(ownerID)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	targetAccountID := sessions[1].AccountID
	mailbox, err := store.AddMailboxForOwner(ownerID, targetAccountID, "target", "target@icloud.com")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewServer(Config{}, store, discardLogger())
	server := handler.(*Server)
	server.syncCodeMailboxBatch = func(ctx context.Context, state LoginState, mailboxes []Mailbox, after time.Time, keyword string, maxMessages int) (map[string][]ICloudSyncedMessage, error) {
		if state.IMAPEmail != "second@example.com" {
			t.Fatalf("sync used IMAP email %q, want second@example.com", state.IMAPEmail)
		}
		if len(mailboxes) != 1 || mailboxes[0].AccountID != targetAccountID {
			t.Fatalf("sync mailboxes = %+v, want account %q", mailboxes, targetAccountID)
		}
		return map[string][]ICloudSyncedMessage{
			mailbox.ID: {{
				RemoteID:   "m1",
				UID:        "1",
				Subject:    "ChatGPT code",
				Body:       "Use 123456 to continue.",
				ReceivedAt: time.Now(),
			}},
		}, nil
	}
	count, err := server.syncMailbox(context.Background(), mailbox, time.Time{}, "ChatGPT")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("synced = %d, want 1", count)
	}
}

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := NewFileStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func registerTestUser(t *testing.T, handler http.Handler, username, password string) (*http.Cookie, publicUser) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/manage/register", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("register user %s = %d body=%s", username, rr.Code, rr.Body.String())
	}
	var body struct {
		User publicUser `json:"user"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			return cookie, body.User
		}
	}
	t.Fatalf("register user %s did not set session cookie", username)
	return nil, publicUser{}
}

func createTestMailboxWithCookie(t *testing.T, handler http.Handler, cookie *http.Cookie, label, email string) publicMailbox {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mailboxes", strings.NewReader(`{"label":"`+label+`","email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create mailbox %s = %d body=%s", email, rr.Code, rr.Body.String())
	}
	var body struct {
		Mailbox publicMailbox `json:"mailbox"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Mailbox
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func zeroTime() time.Time {
	return time.Time{}
}
