package app

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func imapAuthTestState() LoginState {
	return LoginState{IMAPEmail: "test@example.test", IMAPUsername: "test@example.test", IMAPAppPassword: "test-password", IMAPHost: "imap.example.test", IMAPPort: 993}
}

func imapAuthTestDial(t *testing.T, calls *atomic.Int32, response string) func(context.Context, string, int) (net.Conn, error) {
	t.Helper()
	return func(context.Context, string, int) (net.Conn, error) {
		calls.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = fmt.Fprint(server, "* OK IMAP ready\r\n")
			line, err := bufio.NewReader(server).ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(line)
			if len(fields) != 4 || fields[0] != "A001" || fields[1] != "AUTHENTICATE" || fields[2] != "PLAIN" {
				t.Errorf("expected SASL PLAIN command, got %q", strings.TrimSpace(line))
				return
			}
			plain, err := base64.StdEncoding.DecodeString(fields[3])
			parts := strings.Split(string(plain), "\x00")
			if err != nil || len(parts) != 3 || parts[0] != "" || parts[1] == "" || parts[2] == "" {
				t.Errorf("invalid SASL PLAIN initial response")
				return
			}
			_, _ = fmt.Fprintf(server, "A001 %s\r\n", response)
			_, _ = io.Copy(io.Discard, server)
		}()
		return client, nil
	}
}

func TestIMAPAuthConcurrentRejectionDialsOnce(t *testing.T) {
	var gate imapAuthGate
	var calls atomic.Int32
	dial := imapAuthTestDial(t, &calls, "BAD [AUTHENTICATIONFAILED] Authentication Failed")
	start := make(chan struct{})
	var wg sync.WaitGroup
	var rejected, cooled atomic.Int32
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := gate.open(context.Background(), imapAuthTestState(), dial)
			if isCodedError(err, "imap_auth_rejected") {
				rejected.Add(1)
			} else if isCodedError(err, "imap_auth_cooldown") {
				cooled.Add(1)
			} else {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 || rejected.Load() != 1 || cooled.Load() != 23 {
		t.Fatalf("dials/rejected/cooled = %d/%d/%d", calls.Load(), rejected.Load(), cooled.Load())
	}
	entry := gate.attempts[imapAuthKey(imapAuthTestState())]
	if remaining := time.Until(entry.retryAt); remaining < 14*time.Minute || remaining > imapAuthRetryDelay {
		t.Fatalf("auth cooldown = %s", remaining)
	}
}

func TestIMAPAuthChangedCredentialsAndExpiryCanRecover(t *testing.T) {
	var gate imapAuthGate
	var calls atomic.Int32
	state := imapAuthTestState()
	_, _, err := gate.open(context.Background(), state, imapAuthTestDial(t, &calls, "NO [AUTHENTICATIONFAILED] rejected"))
	if !isCodedError(err, "imap_auth_rejected") {
		t.Fatal(err)
	}
	changed := state
	changed.IMAPAppPassword = "replacement-password"
	other := state
	other.IMAPUsername = "other@example.test"
	for _, candidate := range []LoginState{changed, other} {
		conn, _, err := gate.open(context.Background(), candidate, imapAuthTestDial(t, &calls, "OK authenticated"))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	_, _, err = gate.open(context.Background(), state, imapAuthTestDial(t, &calls, "OK authenticated"))
	if !isCodedError(err, "imap_auth_cooldown") || calls.Load() != 3 {
		t.Fatalf("old credentials escaped cooldown: %v, calls=%d", err, calls.Load())
	}
	gate.attempts[imapAuthKey(state)].retryAt = time.Now().Add(-time.Second)
	conn, _, err := gate.open(context.Background(), state, imapAuthTestDial(t, &calls, "OK authenticated"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A long-lived IDLE connection must not block a polling connection.
	second, _, err := gate.open(context.Background(), state, imapAuthTestDial(t, &calls, "OK authenticated"))
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	if calls.Load() != 5 || len(gate.attempts) != 0 {
		t.Fatalf("recovery did not clear gate: calls=%d entries=%d", calls.Load(), len(gate.attempts))
	}
}

func TestIMAPAuthTransientFailureIsNotPasswordRejection(t *testing.T) {
	for _, reply := range []string{"NO [UNAVAILABLE] Try later", "BAD Server is not OK"} {
		t.Run(reply, func(t *testing.T) {
			var gate imapAuthGate
			var calls atomic.Int32
			state := imapAuthTestState()
			dial := imapAuthTestDial(t, &calls, reply)
			_, _, err := gate.open(context.Background(), state, dial)
			if !isCodedError(err, "imap_login_failed") {
				t.Fatalf("unexpected classification: %v", err)
			}
			_, _, err = gate.open(context.Background(), state, dial)
			if !isCodedError(err, "imap_retry_cooldown") || calls.Load() != 1 {
				t.Fatalf("transient retry was not suppressed: %v", err)
			}
			remaining := time.Until(gate.attempts[imapAuthKey(state)].retryAt)
			if remaining <= 0 || remaining > imapTransientRetryDelay {
				t.Fatalf("transient cooldown = %s", remaining)
			}
		})
	}
}

func TestIMAPAuthNetworkFailureBacksOff(t *testing.T) {
	var gate imapAuthGate
	calls := 0
	dial := func(context.Context, string, int) (net.Conn, error) {
		calls++
		return nil, errors.New("connection refused")
	}
	_, _, err := gate.open(context.Background(), imapAuthTestState(), dial)
	if !isCodedError(err, "imap_connect_failed") {
		t.Fatal(err)
	}
	_, _, err = gate.open(context.Background(), imapAuthTestState(), dial)
	if !isCodedError(err, "imap_retry_cooldown") || calls != 1 {
		t.Fatalf("network retry not suppressed: calls=%d err=%v", calls, err)
	}
}

func TestIMAPAuthWaitingCallerCanCancel(t *testing.T) {
	var gate imapAuthGate
	state := imapAuthTestState()
	finish, err := gate.begin(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer finish(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = gate.begin(ctx, state)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait ignored context: %v", err)
	}
}

func TestIMAPAuthCanceledHandshakeReleasesGate(t *testing.T) {
	var gate imapAuthGate
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err := gate.open(ctx, imapAuthTestState(), func(context.Context, string, int) (net.Conn, error) { return client, nil })
	if err == nil || len(gate.attempts) != 0 {
		t.Fatalf("canceled handshake retained gate: err=%v entries=%d", err, len(gate.attempts))
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	_, err = server.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("canceled connection not closed: %v", err)
	}
}

func TestIMAPTaggedOKRequiresSuccessStatus(t *testing.T) {
	for _, reply := range []string{"A001 NO password not OK", "A001 BAD not OK", "* OK greeting", "A001 OKAY invalid"} {
		if imapTaggedOK([]string{reply}, "A001") {
			t.Fatalf("accepted non-success status: %s", reply)
		}
	}
	if !imapTaggedOK([]string{"* OK greeting", "A001 OK done"}, "A001") {
		t.Fatal("rejected successful tagged response")
	}
}

func TestPreferredICloudIMAPUsernameUsesAppleDocumentedAccountName(t *testing.T) {
	for input, want := range map[string]string{
		"xujs98@icloud.com":  "xujs98",
		"legacy@me.com":      "legacy",
		"classic@mac.com":    "classic",
		"other@example.test": "other@example.test",
	} {
		if got := preferredICloudIMAPUsername(input); got != want {
			t.Fatalf("preferredICloudIMAPUsername(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeICloudIMAPStateMigratesFullAppleUsername(t *testing.T) {
	state, err := normalizeICloudIMAPState(LoginState{
		IMAPEmail:       "User@iCloud.com",
		IMAPUsername:    "user@icloud.com",
		IMAPAppPassword: "abcd-efgh-ijkl-mnop",
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.IMAPUsername != "user" {
		t.Fatalf("username = %q, want local account name", state.IMAPUsername)
	}
}
