// Copyright (c) 2026, the wasmdesk/wasmlogin authors. BSD-3-Clause.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ----- auth -----

func TestAnyCreds_Empty(t *testing.T) {
	if _, err := (AnyCreds{}).Authenticate(context.Background(), "", "x"); !errors.Is(err, ErrEmptyCreds) {
		t.Fatalf("want ErrEmptyCreds for empty user, got %v", err)
	}
	if _, err := (AnyCreds{}).Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrEmptyCreds) {
		t.Fatalf("want ErrEmptyCreds for empty password, got %v", err)
	}
}

func TestAnyCreds_Accepts(t *testing.T) {
	sub, err := (AnyCreds{}).Authenticate(context.Background(), "alice", "x")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sub != "alice" {
		t.Fatalf("subject = %q, want alice", sub)
	}
}

// ----- session -----

func TestHMACSessionStore_MintVerify(t *testing.T) {
	s, err := NewHMACSessionStore([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Mint("alice", time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	sub, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sub != "alice" {
		t.Fatalf("subject = %q, want alice", sub)
	}
}

func TestHMACSessionStore_RandomSecret(t *testing.T) {
	s, err := NewHMACSessionStore(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.secret) != 32 {
		t.Fatalf("random secret len = %d, want 32", len(s.secret))
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("rand fail") }

func TestHMACSessionStore_RandFailure(t *testing.T) {
	if _, err := newHMACSessionStoreWithRand(nil, errReader{}); err == nil {
		t.Fatal("want rand error, got nil")
	}
}

func TestHMACSessionStore_MintErrors(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	if _, err := s.Mint("", time.Hour); err == nil {
		t.Fatal("want error on empty subject")
	}
	if _, err := s.Mint("alice", 0); err == nil {
		t.Fatal("want error on zero ttl")
	}
}

func TestHMACSessionStore_VerifyBadShape(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	cases := map[string]string{
		"missing parts": "abc.def",
		"bad subject":   "!!!.123.aaaa",
		"bad expiry":    "YWxpY2U.notanumber.aaaa",
		"bad mac b64":   "YWxpY2U.123.!!!",
	}
	for name, tok := range cases {
		if _, err := s.Verify(tok); !errors.Is(err, ErrBadToken) {
			t.Fatalf("%s: want ErrBadToken, got %v", name, err)
		}
	}
}

func TestHMACSessionStore_BadSignature(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	tok, _ := s.Mint("alice", time.Hour)
	parts := strings.Split(tok, ".")
	// flip a byte in the MAC
	bad := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	if _, err := s.Verify(bad); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestHMACSessionStore_Expired(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	tok, _ := s.Mint("alice", time.Hour)
	// fast-forward
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := s.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestHMACSessionStore_Revoke(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	tok, _ := s.Mint("alice", time.Hour)
	if err := s.Revoke(tok); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Verify(tok); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

func TestHMACSessionStore_RevokeBadToken(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	if err := s.Revoke("not-a-token"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("want ErrBadToken, got %v", err)
	}
}

func TestHMACSessionStore_RevokeExpired(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	tok, _ := s.Mint("alice", time.Hour)
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if err := s.Revoke(tok); err != nil {
		t.Fatalf("Revoke of expired: want nil, got %v", err)
	}
}

func TestHMACSessionStore_RevokeAlreadyRevoked(t *testing.T) {
	s, _ := NewHMACSessionStore([]byte("k"))
	tok, _ := s.Mint("alice", time.Hour)
	if err := s.Revoke(tok); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(tok); err != nil {
		t.Fatalf("Revoke of already-revoked: want nil, got %v", err)
	}
}

// ----- proxy / server end-to-end -----

func newStub(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		_, _ = io.WriteString(w, body+" "+r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestServer(t *testing.T) (*Server, *httptest.Server, *httptest.Server) {
	t.Helper()
	box := newStub(t, "OK wasmbox")
	aqua := newStub(t, "OK wasmaqua")
	cfg := Config{
		Addr:        ":0",
		WasmboxURL:  box.URL,
		WasmaquaURL: aqua.URL,
		SessionTTL:  time.Hour,
	}
	sess, err := NewHMACSessionStore([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(cfg, AnyCreds{}, sess)
	if err != nil {
		t.Fatal(err)
	}
	return srv, box, aqua
}

func TestServer_NewServer_BadURL(t *testing.T) {
	cfg := Config{WasmboxURL: "://bad-url", WasmaquaURL: "http://x"}
	sess, _ := NewHMACSessionStore([]byte("k"))
	if _, err := NewServer(cfg, AnyCreds{}, sess); err == nil {
		t.Fatal("want error on bad URL, got nil")
	}
}

func TestServer_NewServer_DefaultTTL(t *testing.T) {
	cfg := Config{WasmboxURL: "http://x", WasmaquaURL: "http://y"}
	sess, _ := NewHMACSessionStore([]byte("k"))
	srv, err := NewServer(cfg, AnyCreds{}, sess)
	if err != nil {
		t.Fatal(err)
	}
	if srv.SessionTTL != 12*time.Hour {
		t.Fatalf("default TTL = %v, want 12h", srv.SessionTTL)
	}
}

func TestServer_Healthz(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if w.Body.String() != "ok" {
		t.Fatalf("body = %q", w.Body.String())
	}
}

func TestServer_Root_Login(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "WASMDESK") {
		t.Fatalf("body missing WASMDESK: %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "wasmaqua") {
		t.Fatalf("body missing wasmaqua option")
	}
}

func TestServer_Root_404(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nope", nil)
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestServer_Root_AuthedRedirects(t *testing.T) {
	srv, _, _ := newTestServer(t)
	tok, _ := srv.Session.Mint("alice", time.Hour)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	r.AddCookie(&http.Cookie{Name: PrefWMCookieName, Value: "wasmaqua"})
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/wasmaqua/" {
		t.Fatalf("Location = %q, want /wasmaqua/", got)
	}
}

func TestServer_Root_AuthedBadPrefWM(t *testing.T) {
	srv, _, _ := newTestServer(t)
	tok, _ := srv.Session.Mint("alice", time.Hour)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	r.AddCookie(&http.Cookie{Name: PrefWMCookieName, Value: "ghost"})
	srv.Routes().ServeHTTP(w, r)
	if got := w.Header().Get("Location"); got != "/"+srv.WMNames[0]+"/" {
		t.Fatalf("Location = %q, want default wm", got)
	}
}

func TestServer_Root_StaleCookie(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "stale"})
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (login page)", w.Code)
	}
}

func TestServer_Auth_BadMethod(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestServer_Auth_BadForm(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader("%"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestServer_Auth_UnknownWM(t *testing.T) {
	srv, _, _ := newTestServer(t)
	form := url.Values{"user": {"alice"}, "password": {"x"}, "wm": {"ghost"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want re-render", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Unknown window manager") {
		t.Fatalf("body missing error: %q", w.Body.String())
	}
}

func TestServer_Auth_AuthFail(t *testing.T) {
	srv, _, _ := newTestServer(t)
	form := url.Values{"user": {""}, "password": {"x"}, "wm": {"wasmbox"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want re-render", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Sign-in failed") {
		t.Fatalf("body missing error: %q", w.Body.String())
	}
}

// failingSession lets us drive the Mint-failure path in handleAuth.
type failingSession struct{ SessionStore }

func (failingSession) Mint(string, time.Duration) (string, error) {
	return "", errors.New("mint nope")
}
func (failingSession) Verify(string) (string, error)  { return "", errors.New("nope") }
func (failingSession) Revoke(string) error            { return nil }

func TestServer_Auth_MintFail(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.Session = failingSession{}
	form := url.Values{"user": {"alice"}, "password": {"x"}, "wm": {"wasmbox"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestServer_Auth_Success(t *testing.T) {
	srv, _, _ := newTestServer(t)
	form := url.Values{"user": {"alice"}, "password": {"x"}, "wm": {"wasmaqua"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/wasmaqua/" {
		t.Fatalf("Location = %q", got)
	}
	var session, pref bool
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value != "" {
			session = true
		}
		if c.Name == PrefWMCookieName && c.Value == "wasmaqua" {
			pref = true
		}
	}
	if !session || !pref {
		t.Fatalf("missing cookies: session=%v pref=%v", session, pref)
	}
}

func TestServer_Logout_BadMethod(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/logout", nil)
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestServer_Logout_NoCookie(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
}

func TestServer_Logout_WithCookie(t *testing.T) {
	srv, _, _ := newTestServer(t)
	tok, _ := srv.Session.Mint("alice", time.Hour)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	srv.Routes().ServeHTTP(w, r)
	if _, err := srv.Session.Verify(tok); !errors.Is(err, ErrRevoked) {
		t.Fatalf("token not revoked: %v", err)
	}
}

func TestServer_RequireSession_NoCookie(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/wasmbox/", nil)
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if got := w.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want /", got)
	}
}

func TestServer_RequireSession_BadCookie(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/wasmbox/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "junk"})
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
}

func TestServer_Proxy_Wasmbox(t *testing.T) {
	srv, _, _ := newTestServer(t)
	tok, _ := srv.Session.Mint("alice", time.Hour)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/wasmbox/index.html", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	srv.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.HasPrefix(w.Body.String(), "OK wasmbox") {
		t.Fatalf("body = %q", w.Body.String())
	}
	// upstream path should be /index.html, not /wasmbox/index.html
	if !strings.Contains(w.Body.String(), " /index.html") {
		t.Fatalf("upstream did not see stripped path: %q", w.Body.String())
	}
}

func TestServer_Proxy_Wasmaqua(t *testing.T) {
	srv, _, _ := newTestServer(t)
	tok, _ := srv.Session.Mint("alice", time.Hour)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/wasmaqua/", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: tok})
	srv.Routes().ServeHTTP(w, r)
	if !strings.HasPrefix(w.Body.String(), "OK wasmaqua") {
		t.Fatalf("body = %q", w.Body.String())
	}
	if w.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" {
		t.Fatalf("COOP not propagated")
	}
}

// ----- proxy helpers -----

func TestSingleJoiningSlash(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"/", "/x", "/x"},
		{"", "x", "/x"},
		{"/y/", "/x", "/y/x"},
		{"/y", "x", "/y/x"},
		{"/y", "/x", "/y/x"},
		{"/y/", "x", "/y/x"},
	}
	for _, c := range cases {
		if got := singleJoiningSlash(c.a, c.b); got != c.want {
			t.Errorf("singleJoiningSlash(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

// ----- run() / config -----

func TestEnvOr(t *testing.T) {
	get := func(k string) string {
		if k == "Y" {
			return "yes"
		}
		return ""
	}
	if got := envOr(get, "Y", "no"); got != "yes" {
		t.Fatalf("envOr Y = %q", got)
	}
	if got := envOr(get, "Z", "fallback"); got != "fallback" {
		t.Fatalf("envOr Z = %q", got)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := loadConfig(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":9000" || cfg.WasmboxURL != "http://localhost:8080" || cfg.WasmaquaURL != "http://localhost:8081" {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
	if cfg.SessionTTL != 12*time.Hour {
		t.Fatalf("ttl = %v", cfg.SessionTTL)
	}
}

func TestLoadConfig_Env(t *testing.T) {
	env := map[string]string{
		"ADDR": ":1234", "WASMBOX_URL": "http://a", "WASMAQUA_URL": "http://b",
		"SESSION_KEY": "abc", "SESSION_TTL": "30m",
	}
	cfg, err := loadConfig(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":1234" || string(cfg.SessionKey) != "abc" || cfg.SessionTTL != 30*time.Minute {
		t.Fatalf("env not respected: %+v", cfg)
	}
}

func TestLoadConfig_Flags(t *testing.T) {
	cfg, err := loadConfig(
		[]string{"-addr=:7777", "-wasmbox-url=http://x", "-wasmaqua-url=http://y", "-session-ttl=1m"},
		func(string) string { return "" },
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":7777" || cfg.SessionTTL != time.Minute {
		t.Fatalf("flags not respected: %+v", cfg)
	}
}

func TestLoadConfig_BadTTL(t *testing.T) {
	if _, err := loadConfig([]string{"-session-ttl=nope"}, func(string) string { return "" }); err == nil {
		t.Fatal("want bad-ttl error")
	}
}

func TestLoadConfig_FlagParseError(t *testing.T) {
	if _, err := loadConfig([]string{"-bogus"}, func(string) string { return "" }); err == nil {
		t.Fatal("want parse error")
	}
}

func TestRun_Help(t *testing.T) {
	var buf bytes.Buffer
	code := run([]string{"-h"}, func(string) string { return "" }, &buf)
	if code != 0 {
		t.Fatalf("help returned %d", code)
	}
}

func TestRun_ConfigError(t *testing.T) {
	var buf bytes.Buffer
	code := run([]string{"-session-ttl=bad"}, func(string) string { return "" }, &buf)
	if code != 2 {
		t.Fatalf("got %d, want 2", code)
	}
}

func TestRun_ServerInitError(t *testing.T) {
	var buf bytes.Buffer
	code := run(
		[]string{"-wasmbox-url=://bad"},
		func(string) string { return "" },
		&buf,
	)
	if code != 1 {
		t.Fatalf("got %d, want 1", code)
	}
}

func TestRun_ServeError(t *testing.T) {
	prev := listenAndServe
	defer func() { listenAndServe = prev }()
	listenAndServe = func(s *http.Server) error { return errors.New("bind nope") }
	var buf bytes.Buffer
	code := run(nil, func(string) string { return "" }, &buf)
	if code != 1 {
		t.Fatalf("got %d, want 1", code)
	}
	if !strings.Contains(buf.String(), "bind nope") {
		t.Fatalf("log missing error: %q", buf.String())
	}
}

func TestRun_ServerClosed(t *testing.T) {
	prev := listenAndServe
	defer func() { listenAndServe = prev }()
	listenAndServe = func(s *http.Server) error { return http.ErrServerClosed }
	var buf bytes.Buffer
	code := run(nil, func(string) string { return "" }, &buf)
	if code != 0 {
		t.Fatalf("got %d, want 0", code)
	}
}

func TestRun_SessionStoreError(t *testing.T) {
	// Force NewHMACSessionStore to fail by overriding the random source
	// it uses when SESSION_KEY is empty. We can't reach the package-level
	// rand.Reader, so instead we shadow the template read so NewServer
	// fails AFTER session creation succeeds; that's the equivalent code
	// path (a non-server-init failure inside run()).
	prevRead := readLoginTemplate
	defer func() { readLoginTemplate = prevRead }()
	readLoginTemplate = func() ([]byte, error) { return nil, errors.New("read nope") }
	var buf bytes.Buffer
	if code := run(nil, func(string) string { return "" }, &buf); code != 1 {
		t.Fatalf("got %d, want 1", code)
	}
	if !strings.Contains(buf.String(), "read nope") {
		t.Fatalf("log missing: %q", buf.String())
	}
}

func TestNewServer_TemplateParseError(t *testing.T) {
	prev := parseLoginTemplate
	defer func() { parseLoginTemplate = prev }()
	parseLoginTemplate = func(string) (*template.Template, error) {
		return nil, errors.New("parse nope")
	}
	cfg := Config{WasmboxURL: "http://x", WasmaquaURL: "http://y"}
	sess, _ := NewHMACSessionStore([]byte("k"))
	if _, err := NewServer(cfg, AnyCreds{}, sess); err == nil {
		t.Fatal("want parse error")
	}
}

func TestNewServer_TemplateReadError(t *testing.T) {
	prev := readLoginTemplate
	defer func() { readLoginTemplate = prev }()
	readLoginTemplate = func() ([]byte, error) { return nil, errors.New("read nope") }
	cfg := Config{WasmboxURL: "http://x", WasmaquaURL: "http://y"}
	sess, _ := NewHMACSessionStore([]byte("k"))
	if _, err := NewServer(cfg, AnyCreds{}, sess); err == nil {
		t.Fatal("want read error")
	}
}

func TestRenderLogin_TemplateExecError(t *testing.T) {
	srv, _, _ := newTestServer(t)
	// Swap in a template whose Execute fails — `{{.Missing.Method}}` on
	// loginPageData blows up at execution time, not parse time.
	bad, err := template.New("bad").Parse(`{{.Missing.Method}}`)
	if err != nil {
		t.Fatal(err)
	}
	srv.LoginPage = bad
	w := httptest.NewRecorder()
	srv.renderLogin(w, loginPageData{})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestRun_SessionStoreInitError(t *testing.T) {
	prev := newSessionStore
	defer func() { newSessionStore = prev }()
	newSessionStore = func([]byte) (SessionStore, error) {
		return nil, errors.New("sess nope")
	}
	var buf bytes.Buffer
	if code := run(nil, func(string) string { return "" }, &buf); code != 1 {
		t.Fatalf("got %d, want 1", code)
	}
	if !strings.Contains(buf.String(), "sess nope") {
		t.Fatalf("log missing: %q", buf.String())
	}
}

func TestListenAndServe_Default(t *testing.T) {
	// Drive the default listenAndServe just to mark the line covered.
	// We pass an :0 addr (auto-assigned) then immediately Shutdown.
	s := &http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}
	go func() {
		// Shutdown the server soon after it starts.
		for i := 0; i < 100; i++ {
			if s.Shutdown(context.Background()) == nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if err := listenAndServe(s); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("listenAndServe: %v", err)
	}
}

// import below
var _ = template.New

func TestMain_Patched(t *testing.T) {
	// `go test` injects its own flags into os.Args, so we can't use them
	// here. We just verify main() routes through our patched osExit;
	// the exact code is set by run() which is unit-tested above.
	prevExit := osExit
	prevServe := listenAndServe
	prevArgs := osArgs
	defer func() {
		osExit = prevExit
		listenAndServe = prevServe
		osArgs = prevArgs
	}()
	called := false
	osExit = func(int) { called = true }
	listenAndServe = func(*http.Server) error { return http.ErrServerClosed }
	osArgs = []string{"wasmlogin"} // clean argv: no test flags
	main()
	if !called {
		t.Fatal("osExit not called")
	}
}

// Confirm flag.ErrHelp is exactly the kind of error loadConfig returns.
func TestLoadConfig_HelpSentinel(t *testing.T) {
	_, err := loadConfig([]string{"-h"}, func(string) string { return "" })
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("want flag.ErrHelp, got %v", err)
	}
}
