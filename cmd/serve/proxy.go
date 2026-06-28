// Copyright (c) 2026, the wasmdesk/wasmlogin authors. BSD-3-Clause.

package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// newReverseProxy returns a reverse proxy that strips `prefix` from the
// request path before forwarding to `target`. The default Director and
// ModifyResponse preserve any COOP/COEP headers the upstream sets,
// which wasmbox/wasmaqua need so that SharedArrayBuffer is enabled in
// the iframe.
func newReverseProxy(target *url.URL, prefix string) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(target)
	defaultDirector := rp.Director
	rp.Director = func(req *http.Request) {
		defaultDirector(req)
		// Strip the routing prefix so the upstream sees `/...` not
		// `/wasmbox/...`. URL.Path was already rewritten by the
		// default director to target.Path + req.URL.Path, undo that.
		req.URL.Path = singleJoiningSlash(target.Path, strings.TrimPrefix(req.URL.Path, prefix))
		req.Host = target.Host
	}
	return rp
}

// singleJoiningSlash mirrors httputil's unexported helper.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
