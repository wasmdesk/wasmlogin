// Copyright (c) 2026, the wasmdesk/wasmlogin authors. BSD-3-Clause.

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SessionStore mints and verifies opaque session tokens. The interface
// is split so we can swap the in-process HMAC implementation for a
// Redis-backed store without touching the HTTP handlers.
type SessionStore interface {
	Mint(subject string, ttl time.Duration) (token string, err error)
	Verify(token string) (subject string, err error)
	Revoke(token string) error
}

// Errors returned by HMACSessionStore.
var (
	ErrBadToken     = errors.New("wasmlogin: malformed session token")
	ErrBadSignature = errors.New("wasmlogin: session token signature mismatch")
	ErrExpired      = errors.New("wasmlogin: session token expired")
	ErrRevoked      = errors.New("wasmlogin: session token revoked")
)

// HMACSessionStore signs tokens with HMAC-SHA-256 over `subject|expiry`
// using an in-process secret. Revocation is tracked in-memory so a
// process restart effectively clears all sessions — acceptable for v0
// where the secret is also per-process.
type HMACSessionStore struct {
	secret []byte

	mu      sync.Mutex
	revoked map[string]struct{}
	now     func() time.Time // injectable for tests
}

// NewHMACSessionStore returns a store keyed by `secret`. If secret is
// nil or empty, a random 32-byte key is generated via crypto/rand.
func NewHMACSessionStore(secret []byte) (*HMACSessionStore, error) {
	return newHMACSessionStoreWithRand(secret, rand.Reader)
}

// newHMACSessionStoreWithRand is the test-injectable variant.
func newHMACSessionStoreWithRand(secret []byte, r io.Reader) (*HMACSessionStore, error) {
	if len(secret) == 0 {
		buf := make([]byte, 32)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		secret = buf
	}
	return &HMACSessionStore{
		secret:  secret,
		revoked: make(map[string]struct{}),
		now:     time.Now,
	}, nil
}

// Mint returns a token of the form `<b64(subject)>.<expiryUnix>.<b64(mac)>`.
func (s *HMACSessionStore) Mint(subject string, ttl time.Duration) (string, error) {
	if subject == "" {
		return "", errors.New("wasmlogin: empty subject")
	}
	if ttl <= 0 {
		return "", errors.New("wasmlogin: non-positive ttl")
	}
	expiry := s.now().Add(ttl).Unix()
	subB64 := base64.RawURLEncoding.EncodeToString([]byte(subject))
	payload := subB64 + "." + strconv.FormatInt(expiry, 10)
	mac := s.sign(payload)
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// Verify validates the MAC, the expiry, and the revocation list.
func (s *HMACSessionStore) Verify(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrBadToken
	}
	subBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrBadToken
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", ErrBadToken
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrBadToken
	}
	want := s.sign(parts[0] + "." + parts[1])
	if !hmac.Equal(gotMAC, want) {
		return "", ErrBadSignature
	}
	if s.now().Unix() >= expiry {
		return "", ErrExpired
	}
	s.mu.Lock()
	_, gone := s.revoked[token]
	s.mu.Unlock()
	if gone {
		return "", ErrRevoked
	}
	return string(subBytes), nil
}

// Revoke marks the token as revoked. Verifying a known-malformed
// token first (so we don't keep junk around) is intentional.
func (s *HMACSessionStore) Revoke(token string) error {
	if _, err := s.Verify(token); err != nil && !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrExpired) {
		return err
	}
	s.mu.Lock()
	s.revoked[token] = struct{}{}
	s.mu.Unlock()
	return nil
}

func (s *HMACSessionStore) sign(payload string) []byte {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(payload))
	return h.Sum(nil)
}
