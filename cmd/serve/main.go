// Copyright (c) 2026, the wasmdesk/wasmlogin authors. BSD-3-Clause.
//
// wasmlogin serve — login portal that gates access to the wasmbox /
// wasmaqua desktops. The user enters a username + password and picks a
// window manager from the combo box; this binary mints a signed session
// cookie and reverse-proxies the user into the chosen desktop.

package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// SessionCookieName is the name of the cookie that carries the HMAC
// session token.
const SessionCookieName = "wasmdesk_session"

// PrefWMCookieName remembers the user's last WM selection so the combo
// box lands on it next time.
const PrefWMCookieName = "wasmdesk_pref_wm"

//go:embed static/*
var staticFS embed.FS

// Config bundles the runtime parameters of the server.
type Config struct {
	Addr        string
	WasmboxURL  string
	WasmaquaURL string
	SessionKey  []byte
	SessionTTL  time.Duration
}

// Server is the HTTP surface of wasmlogin.
type Server struct {
	Auth       Authenticator
	Session    SessionStore
	WMs        map[string]http.Handler // name → reverse-proxy handler
	WMNames    []string                // sorted, for stable combo-box order
	LoginPage  *template.Template
	SessionTTL time.Duration
}

// loginPageData is the template payload for static/index.html.
type loginPageData struct {
	WMs    []string
	PrefWM string
	User   string
	Error  string
}

// readLoginTemplate is patched in tests to drive the read-error path.
var readLoginTemplate = func() ([]byte, error) {
	return fs.ReadFile(staticFS, "static/index.html")
}

// parseLoginTemplate is patched in tests to drive the parse-error path.
var parseLoginTemplate = func(src string) (*template.Template, error) {
	return template.New("login").Parse(src)
}

// NewServer wires the dependencies. The reverse-proxy backends are
// resolved from the *URL fields of Config.
func NewServer(cfg Config, auth Authenticator, sess SessionStore) (*Server, error) {
	tmplBytes, err := readLoginTemplate()
	if err != nil {
		return nil, fmt.Errorf("read embedded login page: %w", err)
	}
	tmpl, err := parseLoginTemplate(string(tmplBytes))
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}

	wms := map[string]http.Handler{}
	for name, raw := range map[string]string{
		"wasmbox":  cfg.WasmboxURL,
		"wasmaqua": cfg.WasmaquaURL,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s URL %q: %w", name, raw, err)
		}
		wms[name] = newReverseProxy(u, "/"+name)
	}
	names := make([]string, 0, len(wms))
	for k := range wms {
		names = append(names, k)
	}
	sort.Strings(names)

	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}

	return &Server{
		Auth:       auth,
		Session:    sess,
		WMs:        wms,
		WMNames:    names,
		LoginPage:  tmpl,
		SessionTTL: ttl,
	}, nil
}

// Routes returns the HTTP handler for the configured server.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))
	mux.HandleFunc("/auth", s.handleAuth)
	mux.HandleFunc("/logout", s.handleLogout)
	for name, h := range s.WMs {
		mux.Handle("/"+name+"/", s.requireSession(h))
	}
	mux.HandleFunc("/", s.handleRoot)
	return mux
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	pref := readCookie(r, PrefWMCookieName)
	if pref == "" || s.WMs[pref] == nil {
		pref = s.WMNames[0]
	}
	if tok := readCookie(r, SessionCookieName); tok != "" {
		if _, err := s.Session.Verify(tok); err == nil {
			http.Redirect(w, r, "/"+pref+"/", http.StatusFound)
			return
		}
	}
	s.renderLogin(w, loginPageData{WMs: s.WMNames, PrefWM: pref})
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	password := r.FormValue("password")
	wm := strings.TrimSpace(r.FormValue("wm"))
	if _, ok := s.WMs[wm]; !ok {
		s.renderLogin(w, loginPageData{
			WMs: s.WMNames, PrefWM: s.WMNames[0], User: user,
			Error: "Unknown window manager: " + wm,
		})
		return
	}
	subject, err := s.Auth.Authenticate(r.Context(), user, password)
	if err != nil {
		s.renderLogin(w, loginPageData{
			WMs: s.WMNames, PrefWM: wm, User: user,
			Error: "Sign-in failed: " + err.Error(),
		})
		return
	}
	tok, err := s.Session.Mint(subject, s.SessionTTL)
	if err != nil {
		http.Error(w, "session mint failed", http.StatusInternalServerError)
		return
	}
	setCookie(w, SessionCookieName, tok, int(s.SessionTTL.Seconds()))
	setCookie(w, PrefWMCookieName, wm, int(s.SessionTTL.Seconds()))
	http.Redirect(w, r, "/"+wm+"/", http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if tok := readCookie(r, SessionCookieName); tok != "" {
		_ = s.Session.Revoke(tok)
	}
	clearCookie(w, SessionCookieName)
	http.Redirect(w, r, "/", http.StatusFound)
}

// requireSession is the middleware guarding the WM reverse-proxy
// handlers. Unauthenticated requests are bounced back to `/`.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := readCookie(r, SessionCookieName)
		if tok == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if _, err := s.Session.Verify(tok); err != nil {
			clearCookie(w, SessionCookieName)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) renderLogin(w http.ResponseWriter, data loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.LoginPage.Execute(w, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func readCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func setCookie(w http.ResponseWriter, name, value string, maxAgeSeconds int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAgeSeconds,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// loadConfig parses flags + env vars. Flags override env vars.
func loadConfig(args []string, getenv func(string) string) (Config, error) {
	fs := flag.NewFlagSet("wasmlogin", flag.ContinueOnError)
	addr := fs.String("addr", envOr(getenv, "ADDR", ":9000"), "listen address")
	wasmbox := fs.String("wasmbox-url", envOr(getenv, "WASMBOX_URL", "http://localhost:8080"), "wasmbox upstream URL")
	wasmaqua := fs.String("wasmaqua-url", envOr(getenv, "WASMAQUA_URL", "http://localhost:8081"), "wasmaqua upstream URL")
	sessionKey := fs.String("session-key", getenv("SESSION_KEY"), "HMAC key for session cookies; random if empty")
	ttlStr := fs.String("session-ttl", envOr(getenv, "SESSION_TTL", "12h"), "session lifetime, e.g. 12h, 30m")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	ttl, err := time.ParseDuration(*ttlStr)
	if err != nil {
		return Config{}, fmt.Errorf("invalid session-ttl: %w", err)
	}
	return Config{
		Addr:        *addr,
		WasmboxURL:  *wasmbox,
		WasmaquaURL: *wasmaqua,
		SessionKey:  []byte(*sessionKey),
		SessionTTL:  ttl,
	}, nil
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

// osExit and osArgs are patched in tests so we can exercise main()
// without `go test`'s own flags leaking into our flag set.
var (
	osExit = os.Exit
	osArgs = os.Args
)

// newSessionStore is patched in tests so we can drive the
// session-store error path in run().
var newSessionStore = func(secret []byte) (SessionStore, error) {
	return NewHMACSessionStore(secret)
}

func main() {
	osExit(run(osArgs[1:], os.Getenv, os.Stderr))
}

// run is the testable entry point. It returns a process exit code.
func run(args []string, getenv func(string) string, stderr interface {
	Write(p []byte) (n int, err error)
}) int {
	logger := log.New(stderr, "wasmlogin: ", log.LstdFlags)
	cfg, err := loadConfig(args, getenv)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		logger.Printf("config: %v", err)
		return 2
	}
	sess, err := newSessionStore(cfg.SessionKey)
	if err != nil {
		logger.Printf("session store: %v", err)
		return 1
	}
	srv, err := NewServer(cfg, AnyCreds{}, sess)
	if err != nil {
		logger.Printf("server: %v", err)
		return 1
	}
	logger.Printf("listening on %s (wasmbox=%s wasmaqua=%s)",
		cfg.Addr, cfg.WasmboxURL, cfg.WasmaquaURL)
	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := listenAndServe(httpServer); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Printf("listen: %v", err)
		return 1
	}
	return 0
}

// listenAndServe is patched in tests so we can drive `run()` without
// actually binding a port.
var listenAndServe = func(s *http.Server) error {
	return s.ListenAndServe()
}

// silence unused warning if the embed.FS shape changes; the compiler
// already references staticFS via go:embed.
var _ = context.Background
