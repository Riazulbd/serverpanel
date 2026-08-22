package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// secretBox provides authenticated symmetric encryption (AES-256-GCM) for
// values the control plane must store reversibly rather than only as
// one-way hashes — currently just generated database owner passwords (see
// databases.go), so an operator can retrieve connection info again later
// without the agent re-generating a new credential. Session/user passwords
// remain bcrypt-hashed one-way (auth.go) and never pass through this type;
// secretBox is only for secrets the control plane must be able to read back.
type secretBox struct {
	gcm cipher.AEAD
}

func newSecretBox(key []byte) (*secretBox, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("secret key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &secretBox{gcm: gcm}, nil
}

// loadOrCreateSecretKey persists a random 32-byte AES-256 key to path,
// reusing it across restarts — mirroring loadOrCreateAgentCA's rationale in
// ca.go: without persistence, every control-plane restart would silently
// make every previously encrypted secret permanently undecryptable.
func loadOrCreateSecretKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("secret key at %s is %d bytes, expected 32 (corrupt or foreign file?)", path, len(b))
		}
		return b, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("persist secret key: %w", err)
	}
	return key, nil
}

// Encrypt returns a base64-encoded nonce||ciphertext. GCM's authentication
// tag means any tampering with the stored value — including someone editing
// the SQLite file directly — is detected on Decrypt rather than silently
// producing garbage plaintext.
func (b *secretBox) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, b.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := b.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (b *secretBox) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
	}
	nonceSize := b.gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := b.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt failed (wrong key or tampered data): %w", err)
	}
	return string(plaintext), nil
}
