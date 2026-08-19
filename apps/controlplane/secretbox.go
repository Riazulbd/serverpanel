package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// secretKeySize is 32 bytes: AES-256.
const secretKeySize = 32

// loadOrCreateSecretKey loads the control plane's at-rest secret-encryption
// key from path, generating and persisting a new random one on first run —
// the same "generate once, persist, reuse forever" pattern loadOrCreateAgentCA
// uses for the agent CA's signing key (ca.go). This key never leaves the
// control plane process and is never transmitted to an agent or a browser;
// it exists solely to encrypt secrets this control plane itself must be able
// to decrypt later (e.g. a database owner password shown again on request —
// see databases.go), as distinct from bootstrap tokens/session tokens, which
// are only ever stored as one-way hashes because nothing needs to recover
// their plaintext.
//
// Losing this file makes every secret encrypted with it permanently
// unrecoverable; rotating it requires re-encrypting existing secrets (not
// implemented here — see docs/SECURITY.md's key-rotation section for the
// documented gap).
func loadOrCreateSecretKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, fmt.Errorf("secret key file %s is corrupt: %w", path, err)
		}
		if len(decoded) != secretKeySize {
			return nil, fmt.Errorf("secret key file %s has wrong length (%d, want %d)", path, len(decoded), secretKeySize)
		}
		return decoded, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read secret key: %w", err)
	}

	key := make([]byte, secretKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secret key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	// 0600: this key must never be readable by anything but the control
	// plane process's own user.
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return nil, fmt.Errorf("persist secret key: %w", err)
	}
	return key, nil
}

// encryptSecret seals plaintext with AES-256-GCM under key, returning a
// base64-encoded nonce||ciphertext blob suitable for storing in a TEXT
// column. Each call uses a fresh random nonce, so encrypting the same
// plaintext twice never produces the same ciphertext.
func encryptSecret(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptSecret reverses encryptSecret. It fails closed: any tampering with
// the stored ciphertext (or use of the wrong key) returns an error rather
// than corrupted plaintext, since GCM authenticates the ciphertext.
func decryptSecret(key []byte, encoded string) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(sealed) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plaintext), nil
}
