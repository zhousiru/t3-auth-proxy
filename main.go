// t3-auth-proxy runs behind an authenticating reverse proxy and supplies a
// locally managed T3 Code session to HTTP and WebSocket requests.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var version = "dev"

type config struct {
	Listen       string   `json:"listen"`
	Upstream     string   `json:"upstream"`
	PublicURL    string   `json:"public_url"`
	TrustedPeers []string `json:"trusted_peers"`
	T3Binary     string   `json:"t3_binary"`
	T3Home       string   `json:"t3_home"`
	StateDir     string   `json:"state_dir"`
	TokenTTL     string   `json:"token_ttl"`
	RenewBefore  string   `json:"renew_before"`
	Subject      string   `json:"subject"`
	upstream     *url.URL
	public       *url.URL
	peers        []netip.Prefix
	ttl, renew   time.Duration
}

type session struct {
	ID        string    `json:"sessionId"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type retiredSession struct {
	ID        string    `json:"sessionId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type state struct {
	Current session          `json:"current"`
	Retired []retiredSession `json:"retired,omitempty"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run(args []string) error {
	f := flag.NewFlagSet("t3-auth-proxy", flag.ContinueOnError)
	path := f.String("config", "/etc/t3-auth-proxy.conf", "configuration file (JSON)")
	force := f.Bool("force", false, "issue a new token even if renewal is not due")
	showVersion := f.Bool("version", false, "print version")
	f.Usage = func() {
		fmt.Fprintln(f.Output(), "Usage: t3-auth-proxy [options] serve|ensure-token|status")
		f.PrintDefaults()
	}
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if f.NArg() != 1 {
		f.Usage()
		return errors.New("expected one command")
	}
	c, err := loadConfig(*path)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	switch f.Arg(0) {
	case "ensure-token":
		return ensureToken(ctx, c, *force)
	case "serve":
		return serve(ctx, c)
	case "status":
		s, err := readState(c.StateDir)
		if err != nil {
			return err
		}
		valid, err := checkToken(ctx, c, s.Current.Token)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{
			"version": version, "session_id": s.Current.ID, "expires_at": s.Current.ExpiresAt,
			"authenticated": valid, "renewal_due": time.Until(s.Current.ExpiresAt) <= c.renew,
		})
	default:
		return fmt.Errorf("unknown command %q", f.Arg(0))
	}
}

func loadConfig(path string) (config, error) {
	c := config{Listen: "127.0.0.1:3773", Upstream: "http://127.0.0.1:3774",
		T3Binary: "t3", TokenTTL: "720h", RenewBefore: "168h", Subject: "t3-auth-proxy",
		StateDir: os.Getenv("STATE_DIRECTORY"), TrustedPeers: []string{"127.0.0.1/32", "::1/128"}}
	if c.StateDir == "" {
		c.StateDir = "/var/lib/t3-auth-proxy"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = c.validate(); err != nil {
		return c, err
	}
	return c, nil
}

func (c *config) validate() error {
	var err error
	for _, item := range []struct {
		raw string
		dst **url.URL
	}{{c.Upstream, &c.upstream}, {c.PublicURL, &c.public}} {
		u, e := url.Parse(item.raw)
		if e != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("upstream and public_url must be HTTP(S) origins")
		}
		*item.dst = u
	}
	if c.ttl, err = time.ParseDuration(c.TokenTTL); err != nil {
		return fmt.Errorf("token_ttl: %w", err)
	}
	if c.renew, err = time.ParseDuration(c.RenewBefore); err != nil {
		return fmt.Errorf("renew_before: %w", err)
	}
	if c.renew <= 0 || c.ttl <= c.renew {
		return errors.New("require token_ttl > renew_before > 0")
	}
	if c.Subject == "" || c.T3Binary == "" || !filepath.IsAbs(c.StateDir) {
		return errors.New("subject, t3_binary and an absolute state_dir are required")
	}
	if len(c.TrustedPeers) == 0 {
		return errors.New("trusted_peers must contain an ingress address")
	}
	for _, raw := range c.TrustedPeers {
		p, e := netip.ParsePrefix(raw)
		if e != nil {
			return fmt.Errorf("trusted_peers: %w", e)
		}
		c.peers = append(c.peers, p)
	}
	return nil
}

func readState(dir string) (state, error) {
	var s state
	b, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return s, errors.New("invalid session state")
	}
	if s.Current.Token == "" || s.Current.ID == "" || s.Current.ExpiresAt.IsZero() {
		return s, errors.New("incomplete session state")
	}
	return s, nil
}

func writeState(dir string, s state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".session-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, "session.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func t3Command(ctx context.Context, c config, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if c.T3Home != "" {
		args = append(args, "--base-dir", c.T3Home)
	}
	cmd := exec.CommandContext(ctx, c.T3Binary, args...)
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("t3 CLI failed: %w", err)
	}
	return b, nil
}

// Do not follow redirects: a configuration error must never send the token elsewhere.
var authClient = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func checkToken(ctx context.Context, c config, token string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(c.Upstream, "/")+"/api/auth/session", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := authClient.Do(req)
	if err != nil {
		return false, errors.New("cannot reach T3 session endpoint")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return false, nil
	}
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("T3 session endpoint returned HTTP %d", res.StatusCode)
	}
	var result struct {
		Authenticated bool `json:"authenticated"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&result); err != nil {
		return false, errors.New("invalid T3 session response")
	}
	return result.Authenticated, nil
}

func ensureToken(ctx context.Context, c config, force bool) error {
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(c.StateDir, "renew.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("token renewal is already running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	s, err := readState(c.StateDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	valid := false
	if s.Current.Token != "" && time.Now().Before(s.Current.ExpiresAt) {
		valid, err = checkToken(ctx, c, s.Current.Token)
		if err != nil {
			return err
		}
	}
	if !force && valid && time.Until(s.Current.ExpiresAt) > c.renew {
		log.Printf("token valid until %s", s.Current.ExpiresAt.Format(time.RFC3339))
		return nil
	}
	b, err := t3Command(ctx, c, "auth", "session", "issue", "--subject", c.Subject, "--label", c.Subject, "--ttl", c.TokenTTL, "--json")
	if err != nil {
		return err
	}
	var next session
	if json.Unmarshal(b, &next) != nil || next.ID == "" || next.Token == "" || !time.Now().Before(next.ExpiresAt) {
		return errors.New("invalid issued session")
	}
	valid, err = checkToken(ctx, c, next.Token)
	if err != nil || !valid {
		_, _ = t3Command(ctx, c, "auth", "session", "revoke", next.ID)
		return errors.New("new session validation failed; current token retained")
	}
	if s.Current.ID != "" {
		s.Retired = append(s.Retired, retiredSession{s.Current.ID, s.Current.ExpiresAt})
	}
	s.Current = next
	if err = writeState(c.StateDir, s); err != nil {
		// A rename may have succeeded before a directory fsync failure. Keep the
		// issued session valid rather than revoking a potentially installed token.
		return err
	}
	kept := make([]retiredSession, 0, len(s.Retired))
	for _, old := range s.Retired {
		if time.Now().Before(old.ExpiresAt) {
			kept = append(kept, old)
			continue
		}
		if _, e := t3Command(ctx, c, "auth", "session", "revoke", old.ID); e != nil {
			kept = append(kept, old)
			log.Print("old session cleanup failed; will retry on rotation")
		}
	}
	s.Retired = kept
	if err = writeState(c.StateDir, s); err != nil {
		return err
	}
	log.Printf("installed session %s, expires %s", next.ID, next.ExpiresAt.Format(time.RFC3339))
	return nil
}

type proxy struct {
	c       config
	current atomic.Pointer[session]
	forward *httputil.ReverseProxy
}

func newProxy(c config, s session) *proxy {
	p := &proxy{c: c}
	p.current.Store(&s)
	p.forward = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(c.upstream)
			r.Out.Host = c.public.Host
			r.SetXForwarded()
			r.Out.Header.Set("X-Forwarded-Host", c.public.Host)
			r.Out.Header.Set("X-Forwarded-Proto", c.public.Scheme)
			r.Out.Header.Set("Authorization", "Bearer "+p.current.Load().Token)
			r.Out.Header.Del("DPoP")
			// T3 cookies and WS tickets take precedence over the injected bearer.
			r.Out.Header.Del("Cookie")
			for _, cookie := range r.In.Cookies() {
				if !isT3Cookie(cookie.Name) {
					r.Out.AddCookie(cookie)
				}
			}
			q := r.Out.URL.Query()
			if q.Has("wsTicket") || q.Has("dpop") {
				q.Del("wsTicket")
				q.Del("dpop")
				r.Out.URL.RawQuery = q.Encode()
			}
		},
		ModifyResponse: func(r *http.Response) error {
			cookies := r.Header.Values("Set-Cookie")
			r.Header.Del("Set-Cookie")
			for _, raw := range cookies {
				name, _, _ := strings.Cut(raw, "=")
				if !isT3Cookie(strings.TrimSpace(name)) {
					r.Header.Add("Set-Cookie", raw)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Print("upstream connection failed")
			http.Error(w, "T3 Code is unavailable", http.StatusBadGateway)
		},
	}
	return p
}

func isT3Cookie(name string) bool {
	return name == "t3_session" || strings.HasPrefix(name, "t3_session_")
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, e := netip.ParseAddr(host)
	allowed := false
	if err == nil && e == nil {
		for _, prefix := range p.c.peers {
			if prefix.Contains(ip.Unmap()) {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != strings.TrimRight(p.c.PublicURL, "/") {
		http.Error(w, "Forbidden origin", http.StatusForbidden)
		return
	}
	if !time.Now().Before(p.current.Load().ExpiresAt) {
		http.Error(w, "T3 session renewal required", http.StatusServiceUnavailable)
		return
	}
	p.forward.ServeHTTP(w, r)
}

func serve(ctx context.Context, c config) error {
	if err := ensureToken(ctx, c, false); err != nil {
		return err
	}
	s, err := readState(c.StateDir)
	if err != nil {
		return err
	}
	p := newProxy(c, s.Current)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				updated, e := readState(c.StateDir)
				if e != nil {
					log.Print("cannot reload token state; retaining current token")
					continue
				}
				if updated.Current.ID != p.current.Load().ID && time.Now().Before(updated.Current.ExpiresAt) {
					p.current.Store(&updated.Current)
					log.Printf("loaded session %s", updated.Current.ID)
				}
			}
		}
	}()
	srv := &http.Server{Addr: c.Listen, Handler: p, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("t3-auth-proxy %s listening on %s", version, c.Listen)
	if err = srv.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
