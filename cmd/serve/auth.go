// Copyright (c) 2026, the wasmdesk/wasmlogin authors. BSD-3-Clause.

package main

import (
	"context"
	"errors"
)

// Authenticator validates a username + password and returns a stable
// subject identifier for the session. The interface is intentionally
// OIDC-shaped: the real provider implementation will run the
// authorization-code-with-PKCE dance against an identity provider and
// return the `sub` claim from the validated ID token.
type Authenticator interface {
	Authenticate(ctx context.Context, user, password string) (subject string, err error)
}

// ErrEmptyCreds is returned by AnyCreds when either credential is empty.
var ErrEmptyCreds = errors.New("wasmlogin: empty username or password")

// AnyCreds is the v0 placeholder authenticator: it accepts any
// non-empty username + password pair and returns the username as the
// session subject. Production deployments must replace it with an OIDC
// (or other federated) Authenticator.
type AnyCreds struct{}

// Authenticate implements Authenticator. The context is part of the
// interface so that real implementations can carry deadlines for the
// federated round-trip; AnyCreds does not consult it.
func (AnyCreds) Authenticate(_ context.Context, user, password string) (string, error) {
	if user == "" || password == "" {
		return "", ErrEmptyCreds
	}
	return user, nil
}
