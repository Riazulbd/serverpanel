package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

// secretKeySize is 32 bytes (AES-256).
const secretKeySize = 32

// loadOrCreateSecretKey loads the control plane's at-rest secret-encryption
// key from path, generating and persisting a fresh random one on first run
// — the same pattern ca.go uses for the agent CA's private key. This key
// never leaves the control plane process and is used only to encrypt
// values the dashboard must be able to show back to an operator on demand
// (e.g. a database owner password — see databases.go); it is not used for
// anything that only ever needs to be verified, never re-displayed (those,
// like session tokens and bootstrap tokens, are hashed, not encrypted).
func loadOrCreateSecretKey(path string) ([secretKeySize]byte, error) {
	var key [secretKeySize]byte

	if raw, err := os.ReadFile(path); err == nil {
		if len(raw) != secretKeySize {
			return key, fmt.Errorf("secret key file %s has unexpected length %d (want %d)", path, len(raw), secretKeySize)
		}
		copy(key[:], raw)
		return key, nil
	} else if !os.IsNotExist(err) {
		return key, fmt.Errorf("read secret key: %w", err)
	}

	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("generate secret key: %w", err)
	}
	if err := os.WriteFile(path, key[:], 0600); err != nil {
		return key, fmt.Errorf("persist secret key: %w", err)
	}
	return key, nil
}

// encryptSecret encrypts plaintext with AES-256-GCM under key, returning a
// base64-encoded blob (12-byte nonce prefix + ciphertext + auth tag). Each
// call uses a fresh random nonce, so encrypting the same plaintext twice
// never produces the same ciphertext.
func encryptSecret(key [secretKeySize]byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key[:])
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

// decryptSecret reverses encryptSecret. It fails closed: any tampering,
// truncation, or wrong key produces an error, never a garbage plaintext.
func decryptSecret(key [secretKeySize]byte, encoded string) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
