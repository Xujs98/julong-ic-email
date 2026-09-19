package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const imapAuthRetryDelay = 15 * time.Minute
const imapTransientRetryDelay = 30 * time.Second

// Share authentication backoff across polling, IDLE, baseline and manual checks.
// Only credential digests are retained, and changed credentials have a fresh gate.
var iCloudIMAPAuth = imapAuthGate{}

type imapAuthAttempt struct {
	done    chan struct{}
	retryAt time.Time
	auth    bool
}

type imapAuthGate struct {
	mu       sync.Mutex
	attempts map[[32]byte]*imapAuthAttempt
}

func imapAuthKey(state LoginState) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%q|%d|%q|%q",
		strings.ToLower(strings.TrimSuffix(state.IMAPHost, ".")), state.IMAPPort,
		strings.ToLower(state.IMAPUsername), state.IMAPAppPassword)))
}

func (g *imapAuthGate) begin(ctx context.Context, state LoginState) (func(error), error) {
	key := imapAuthKey(state)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		g.mu.Lock()
		now := time.Now()
		if a := g.attempts[key]; a != nil {
			if a.done != nil {
				done := a.done
				g.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-done:
					continue
				}
			}
			if now.Before(a.retryAt) {
				code, reason := "imap_retry_cooldown", "上次 IMAP 连接暂时失败"
				if a.auth {
					code, reason = "imap_auth_cooldown", "Apple 已拒绝这组 IMAP 凭据"
				}
				err := errCode(code, fmt.Sprintf("%s；已暂停重复登录，将于 %s 后重试。更新 App 专用密码可立即重新验证", reason, a.retryAt.Format(time.RFC3339)), true)
				g.mu.Unlock()
				return nil, err
			}
		}
		if g.attempts == nil {
			g.attempts = make(map[[32]byte]*imapAuthAttempt)
		}
		for k, a := range g.attempts {
			if a.done == nil && !now.Before(a.retryAt) {
				delete(g.attempts, k)
			}
		}
		if len(g.attempts) >= 1024 {
			g.mu.Unlock()
			return nil, errCode("imap_retry_cooldown", "IMAP 登录繁忙，请稍后重试", true)
		}
		a := &imapAuthAttempt{done: make(chan struct{})}
		g.attempts[key] = a
		g.mu.Unlock()
		return func(err error) {
			g.mu.Lock()
			defer g.mu.Unlock()
			close(a.done)
			a.done = nil
			if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				delete(g.attempts, key)
				return
			}
			delay := imapTransientRetryDelay
			a.auth = isCodedError(err, "imap_auth_rejected")
			if a.auth {
				delay = imapAuthRetryDelay
			}
			a.retryAt = time.Now().Add(delay)
		}, nil
	}
}

func isIMAPCooldown(err error) bool {
	return isCodedError(err, "imap_auth_cooldown") || isCodedError(err, "imap_retry_cooldown")
}

func openICloudIMAPSession(ctx context.Context, state LoginState) (net.Conn, *bufio.Reader, error) {
	return iCloudIMAPAuth.open(ctx, state, dialICloudIMAPTLS)
}

func (g *imapAuthGate) open(ctx context.Context, state LoginState, dial func(context.Context, string, int) (net.Conn, error)) (conn net.Conn, reader *bufio.Reader, err error) {
	state, err = normalizeICloudIMAPState(state)
	if err != nil {
		return nil, nil, err
	}
	finish, err := g.begin(ctx, state)
	if err != nil {
		return nil, nil, err
	}
	defer func() { finish(err) }()
	loginCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	conn, err = dial(loginCtx, state.IMAPHost, state.IMAPPort)
	if err != nil {
		return nil, nil, errCode("imap_connect_failed", "连接 iCloud IMAP 失败："+err.Error(), true)
	}
	opened := conn
	stop := context.AfterFunc(loginCtx, func() { _ = opened.Close() })
	defer func() {
		stop()
		if err != nil {
			_ = opened.Close()
		}
	}()
	deadline, _ := loginCtx.Deadline()
	_ = conn.SetDeadline(deadline)
	reader = bufio.NewReader(conn)
	greeting, readErr := reader.ReadString('\n')
	if readErr != nil {
		return nil, nil, errCode("imap_greeting_failed", "读取 iCloud IMAP 欢迎信息失败："+readErr.Error(), true)
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(greeting)), "* OK") {
		return nil, nil, errCode("imap_greeting_failed", "iCloud IMAP 未就绪："+imapResponseSummary([]string{greeting}), true)
	}
	plain := "\x00" + state.IMAPUsername + "\x00" + state.IMAPAppPassword
	lines, loginErr := imapCommand(conn, reader, "A001", "AUTHENTICATE PLAIN "+base64.StdEncoding.EncodeToString([]byte(plain)))
	if loginErr != nil {
		return nil, nil, errCode("imap_login_failed", "iCloud IMAP 登录请求失败："+loginErr.Error(), true)
	}
	if !imapTaggedOK(lines, "A001") {
		summary := imapResponseSummary(lines)
		upper := strings.ToUpper(strings.Join(lines, " "))
		if strings.Contains(upper, "[AUTHENTICATIONFAILED]") || strings.Contains(upper, "[AUTHORIZATIONFAILED]") {
			return nil, nil, errCode("imap_auth_rejected", "Apple 拒绝 IMAP 认证，不能仅凭此判断密码输入错误；请核对主 iCloud 邮箱、专用密码所属账号及是否已撤销，或稍后重试。已暂停这组凭据的重复登录 15 分钟："+summary, false)
		}
		return nil, nil, errCode("imap_login_failed", "iCloud IMAP 暂未接受登录，将退避重试："+summary, true)
	}
	if loginCtx.Err() != nil {
		return nil, nil, loginCtx.Err()
	}
	// IDLE may live for hours; only its handshake uses the short deadline.
	deadline, _ = ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	return conn, reader, nil
}

func preferredICloudIMAPUsername(email string) string {
	email = normalizeICloudIMAPEmail(email)
	parts := strings.Split(email, "@")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return email
	}
	switch strings.ToLower(parts[1]) {
	case "icloud.com", "me.com", "mac.com":
		return parts[0]
	default:
		return email
	}
}
