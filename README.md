# wasmlogin

<!-- BANNER PLACEHOLDER: wasmdesk family brand banner goes here -->

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](LICENSE)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](https://golang.org)
[![Family: wasmdesk](https://img.shields.io/badge/family-wasmdesk-7C3AED)](https://github.com/wasmdesk)

A pure-Go (CGO=0) login portal that gates access to the wasmdesk family of
in-browser desktops. The user signs in, picks a window manager from the
combo box (`wasmbox`, `wasmaqua`), and is reverse-proxied to that desktop
with their session cookie attached.

Designed so that swapping the v0 "any non-empty creds" authenticator for
real OIDC is a one-interface change (`Authenticator`).

## Features

- Single static binary, `cmd/serve`, no CGO, no external assets — login
  page is embedded with `//go:embed`.
- HMAC-signed session cookies (`wasmdesk_session=<subject>.<expiry>.<mac>`).
- Reverse proxies `/wasmbox/*` and `/wasmaqua/*` to the configured backends,
  passing through the COOP/COEP headers wasmbox/wasmaqua need for
  SharedArrayBuffer.
- Adwaita-blue login card with `prefers-color-scheme` light/dark support.
- 100% statement coverage on the touched non-tamago, non-wasm code.
- End-to-end verified with headless Chromium via Playwright.

## Build & run

```sh
task build         # go build -o bin/wasmlogin ./cmd/serve
task serve         # build + run on :9000 against the default wasmbox/wasmaqua URLs
task test          # go test -cover ./...
```

Environment variables:

| Var            | Default                  | Meaning                                            |
| -------------- | ------------------------ | -------------------------------------------------- |
| `ADDR`         | `:9000`                  | listen address                                     |
| `WASMBOX_URL`  | `http://localhost:8080`  | upstream `wasmbox` desktop                         |
| `WASMAQUA_URL` | `http://localhost:8081`  | upstream `wasmaqua` desktop                        |
| `SESSION_KEY`  | (random per process)     | HMAC key for session cookies; set to share keys    |
| `SESSION_TTL`  | `12h`                    | session lifetime                                   |

## OIDC roadmap

The v0 authenticator (`AnyCreds`) accepts any non-empty username + password
and returns the username as the session subject. The `Authenticator`
interface is intentionally OIDC-shaped — the real implementation will:

1. Redirect to the OIDC provider's `/authorize` endpoint (PKCE).
2. Exchange the code at `/token`, validate the ID token.
3. Return the `sub` claim as the session subject.

The `SessionStore` interface (Mint / Verify / Revoke) is compatible with
moving from in-process HMAC to a Redis-backed store without touching the
HTTP layer.

## Wiring with wasmbox + wasmaqua

```
                ┌───────────────────────┐
   browser ───► │  wasmlogin :9000      │
                │  /  → login.html      │
                │  /auth → mint cookie  │
                │  /wasmbox/* ─────────┐│
                │  /wasmaqua/* ────────┼┼──► wasmbox :8080
                └─────────────────────┼┼──► wasmaqua :8081
                                      ││
                            (COOP/COEP passed through)
```

## License

BSD-3-Clause — see [LICENSE](LICENSE).
