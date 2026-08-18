package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

// secretBox encrypts small secrets (e.g. generated database passwords)
// before they are persisted, using AES-256-GCM with a key that is never
// itself stored in the SQLite database. This is a symmetric envelope, not
// per-record key derivation or an HSM/KMS integration — the threat model it
// covers is "the SQLite file alone, exfiltrated, must not hand over
// plaintext credentials," matching agentCA's own documented scope (ca.go):
// a functional Phase 1/2 implementation, with a dedicated KMS/HSM called
// out as the production hardening step, same as the CA's signing key.
type secretBox struct {
	aead cipher.AEAD
}

func newSecretBoxFromKey(key []byte) (*secretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secretBox{aead: aead}, nil
}

// loadOrCreateSecretKey persists a random 256-bit key to keyPath (0600) and
// reuses it across restarts — the same durability pattern
// loadOrCreateAgentCA uses for the CA's signing key (ca.go). Without this, a
// control-plane restart would make every already-encrypted secret
// permanently undecryptable, which is strictly worse than not encrypting at
// all (silent, irrecoverable data loss vs. a known, documented trade-off).
func loadOrCreateSecretKey(keyPath string) (*secretBox, error) {
	if raw, err := os.ReadFile(keyPath); err == nil {
		key, decErr := base64.StdEncoding.DecodeString(string(raw))
		if decErr != nil {
			return nil, fmt.Errorf("parse existing secret key at %s: %w", keyPath, decErr)
		}
		return newSecretBoxFromKey(key)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		return nil, fmt.Errorf("persist secret key: %w", err)
	}
	return newSecretBoxFromKey(key)
}

// encrypt returns a base64-encoded nonce||ciphertext blob suitable for
// storing directly in a TEXT column.
func (b *secretBox) encrypt(plaintext string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := b.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// decrypt reverses encrypt. GCM's authentication tag means a tampered or
// truncated blob fails closed with an error rather than returning corrupted
// plaintext.
func (b *secretBox) decrypt(blob string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := b.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(pt), nil
}

// randomPassword returns a URL-safe base64 string decoded from n random
// bytes — used for control-plane-generated database owner passwords
// (handleCreateDatabase), never for anything the caller supplies.
func randomPassword(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
