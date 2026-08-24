package main

import (
	"path/filepath"
	"testing"
)

func TestEncryptDecryptSecretRoundTrip(t *testing.T) {
	var key [secretKeySize]byte
	for i := range key {
		key[i] = byte(i)
	}

	ciphertext, err := encryptSecret(key, "correct horse battery staple")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	if ciphertext == "correct horse battery staple" {
		t.Fatal("ciphertext must not equal the plaintext")
	}

	plaintext, err := decryptSecret(key, ciphertext)
	if err != nil {
		t.Fatalf("decryptSecret: %v", err)
	}
	if plaintext != "correct horse battery staple" {
		t.Fatalf("plaintext = %q, want original value to round-trip", plaintext)
	}
}

func TestDecryptSecretFailsClosedUnderTampering(t *testing.T) {
	var key [secretKeySize]byte
	for i := range key {
		key[i] = byte(i)
	}
	ciphertext, err := encryptSecret(key, "sensitive value")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}

	// Flipping the last character corrupts the GCM auth tag; decryption
	// must fail rather than return a garbage plaintext.
	tampered := ciphertext[:len(ciphertext)-1] + "x"
	if _, err := decryptSecret(key, tampered); err == nil {
		t.Fatal("expected decryptSecret to reject a tampered ciphertext")
	}

	var wrongKey [secretKeySize]byte
	for i := range wrongKey {
		wrongKey[i] = byte(255 - i)
	}
	if _, err := decryptSecret(wrongKey, ciphertext); err == nil {
		t.Fatal("expected decryptSecret to reject the wrong key")
	}
}

func TestLoadOrCreateSecretKeyPersistsAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")

	k1, err := loadOrCreateSecretKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey (create): %v", err)
	}

	k2, err := loadOrCreateSecretKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey (reload): %v", err)
	}
	if k1 != k2 {
		t.Fatal("expected reloading an existing key file to return the same key")
	}
}
