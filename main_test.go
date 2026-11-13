package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(t *testing.T, upstream string) config {
	t.Helper()
	c := config{Listen: "127.0.0.1:0", Upstream: upstream, PublicURL: "https://code.example.com", TrustedPeers: []string{"127.0.0.1/32"}, T3Binary: "t3", StateDir: t.TempDir(), TokenTTL: "720h", RenewBefore: "168h", Subject: "test-proxy"}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func testSession(token string) session {
	return session{ID: token + "-id", Token: token, ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
}

func TestProxyAuthenticationAndRotation(t *testing.T) {
	seen := make(chan http.Header, 4)
	queries := make(chan string, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		queries <- r.URL.RawQuery
		w.Header().Add("Set-Cookie", "t3_session_test=private; HttpOnly")
		w.Header().Add("Set-Cookie", "theme=dark")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	p := newProxy(testConfig(t, upstream.URL), testSession("old"))
	for _, token := range []string{"old", "new"} {
		if token == "new" {
			s := testSession(token)
			p.current.Store(&s)
		}
		r := httptest.NewRequest("GET", "https://code.example.com/ws?wsTicket=stale&dpop=old&keep=yes", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Origin", "https://code.example.com")
		r.Header.Set("Authorization", "Bearer client-token")
		r.Header.Set("DPoP", "client-proof")
		r.Header.Set("Cookie", "t3_session_test=stale; theme=light; t3_session=legacy")
		r.Header.Set("X-Forwarded-Host", "attacker.example")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("HTTP %d", w.Code)
		}
		h := <-seen
		if h.Get("Authorization") != "Bearer "+token || h.Get("Cookie") != "theme=light" || h.Get("DPoP") != "" {
			t.Fatal("client credentials were not replaced")
		}
		if h.Get("X-Forwarded-Host") != "code.example.com" || h.Get("X-Forwarded-Proto") != "https" {
			t.Fatal("incorrect forwarding headers")
		}
		if q := <-queries; q != "keep=yes" {
			t.Fatalf("unexpected query %q", q)
		}
		if cookies := w.Header().Values("Set-Cookie"); len(cookies) != 1 || cookies[0] != "theme=dark" {
			t.Fatal("T3 cookie leaked")
		}
	}
}

func TestProxyRefusesUntrustedExpiredAndCrossOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, peer, origin string
		expired            bool
		status             int
	}{
		{"untrusted", "192.0.2.1:1000", "", false, 403},
		{"cross-origin", "127.0.0.1:1000", "https://attacker.example", false, 403},
		{"null-origin", "127.0.0.1:1000", "null", false, 403},
		{"expired", "127.0.0.1:1000", "", true, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSession("token")
			if tc.expired {
				s.ExpiresAt = time.Now().Add(-time.Second)
			}
			p := newProxy(testConfig(t, "http://127.0.0.1:1"), s)
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d", w.Code, tc.status)
			}
		})
	}
}

func TestWebSocketUpgradeSurvivesTokenSwitch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer old" {
			http.Error(w, "bad auth", 401)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw)
	}))
	defer upstream.Close()
	p := newProxy(testConfig(t, upstream.URL), testSession("old"))
	front := httptest.NewServer(p)
	defer front.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: code.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	rd := bufio.NewReader(conn)
	res, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 101 {
		t.Fatalf("HTTP %d", res.StatusCode)
	}
	next := testSession("new")
	p.current.Store(&next)
	// A real masked WebSocket ping frame must pass unchanged in both directions.
	frame := []byte{0x89, 0x81, 1, 2, 3, 4, 'x' ^ 1}
	if _, err = conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(frame))
	if _, err = io.ReadFull(rd, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(frame) {
		t.Fatal("upgrade stream corrupted")
	}
}

func mockCLI(t *testing.T, c *config, next session) {
	t.Helper()
	b, _ := json.Marshal(next)
	path := filepath.Join(t.TempDir(), "t3")
	script := "#!/bin/sh\ncat <<'JSON'\n" + string(b) + "\nJSON\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	c.T3Binary = path
}

func TestRenewalRetainsWorkingStateOnFailure(t *testing.T) {
	var acceptNew atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		valid := r.Header.Get("Authorization") == "Bearer old" || acceptNew.Load()
		json.NewEncoder(w).Encode(map[string]bool{"authenticated": valid})
	}))
	defer upstream.Close()
	c := testConfig(t, upstream.URL)
	old := testSession("old")
	if err := writeState(c.StateDir, state{Current: old}); err != nil {
		t.Fatal(err)
	}
	mockCLI(t, &c, testSession("new"))
	if err := ensureToken(context.Background(), c, true); err == nil {
		t.Fatal("expected failed candidate validation")
	}
	s, err := readState(c.StateDir)
	if err != nil || s.Current.Token != "old" {
		t.Fatal("old state lost")
	}
	// No request is in flight when changing the test endpoint's behavior.
	acceptNew.Store(true)
	if err = ensureToken(context.Background(), c, true); err != nil {
		t.Fatal(err)
	}
	s, err = readState(c.StateDir)
	if err != nil || s.Current.Token != "new" || len(s.Retired) != 1 || s.Retired[0].ID != old.ID {
		t.Fatal("rotation did not retain previous session")
	}
	info, _ := os.Stat(filepath.Join(c.StateDir, "session.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("state is not private")
	}
}

func TestRenewalSkipsValidTokenAndRejectsRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"authenticated":true}`) }))
	defer upstream.Close()
	c := testConfig(t, upstream.URL)
	c.T3Binary = "/nonexistent"
	if err := writeState(c.StateDir, state{Current: testSession("current")}); err != nil {
		t.Fatal(err)
	}
	if err := ensureToken(context.Background(), c, false); err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, upstream.URL, 302) }))
	defer redirect.Close()
	c.Upstream = redirect.URL
	if _, err := checkToken(context.Background(), c, "current"); err == nil {
		t.Fatal("redirect was followed")
	}
}

func TestRevokeOwnedSessions(t *testing.T) {
	c := testConfig(t, "http://127.0.0.1:1")
	if err := writeState(c.StateDir, state{Current: testSession("current"), Retired: []retiredSession{{ID: "previous-id", ExpiresAt: time.Now()}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.StateDir, "renew.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(t.TempDir(), "t3")
	c.T3Binary = cli
	if err := os.WriteFile(cli, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := revokeOwned(context.Background(), c); err == nil {
		t.Fatal("expected failed revocation")
	}
	if _, err := readState(c.StateDir); err != nil {
		t.Fatal("lost state on failed revocation")
	}
	logPath := filepath.Join(t.TempDir(), "calls")
	t.Setenv("T3_TEST_LOG", logPath)
	if err := os.WriteFile(cli, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$T3_TEST_LOG\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := revokeOwned(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.StateDir, "session.json")); !os.IsNotExist(err) {
		t.Fatal("token state was not removed")
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(calls) != "auth\nsession\nrevoke\ncurrent-id\nauth\nsession\nrevoke\nprevious-id\n" {
		t.Fatal("unexpected sessions revoked")
	}
	if err := revokeOwned(context.Background(), c); err != nil {
		t.Fatal("repeat cleanup failed", err)
	}
}
