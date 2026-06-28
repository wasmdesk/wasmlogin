// Copyright (c) 2026, the wasmdesk/wasmlogin authors. BSD-3-Clause.
//
// stubs is a tiny helper binary used by the Playwright end-to-end
// harness. It serves "OK wasmbox" on :7081 and "OK wasmaqua" on :7082
// so we can drive wasmlogin without bringing up the real desktops.

//go:build ignore

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: stubs <addr> <body>")
	}
	addr, body := os.Args[1], os.Args[2]
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><html><body><h1>%s</h1><p>%s</p></body></html>", body, r.URL.Path)
		}),
	}
	log.Printf("stub %s → %q", addr, body)
	log.Fatal(srv.ListenAndServe())
}
