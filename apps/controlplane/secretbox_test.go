package main

import (
	"path/filepath"
	"testing"
)

func TestEncryptDecryptSecretRoundTrip(t *testing.T) {
	key, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}

	cipher, err := encryptSecret(key, "super-secret-database-password")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	if cipher == "super-secret-database-password" {
		t.Fatal("encryptSecret returned the plaintext unchanged")
	}

	got, err := decryptSecret(key, cipher)
	if err != nil {
		t.Fatalf("decryptSecret: %v", err)
	}
	if got != "super-secret-database-password" {
		t.Fatalf("decryptSecret = %q, want original plaintext", got)
	}
}

func TestEncryptSecretNoncesDiffer(t *testing.T) {
	key, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	a, err := encryptSecret(key, "same-plaintext")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	b, err := encryptSecret(key, "same-plaintext")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	if a == b {
		t.Fatal("encrypting the same plaintext twice produced identical ciphertext (nonce reuse)")
	}
}

func TestDecryptSecretRejectsTampering(t *testing.T) {
	key, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	cipher, err := encryptSecret(key, "original-password")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	tampered := []byte(cipher)
	tampered[len(tampered)-1] ^= 0x01 // flip a bit inside the base64 payload
	if _, err := decryptSecret(key, string(tampered)); err == nil {
		t.Fatal("decryptSecret accepted tampered ciphertext")
	}
}

func TestDecryptSecretRejectsWrongKey(t *testing.T) {
	keyA, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	keyB, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	cipher, err := encryptSecret(keyA, "password")
	if err != nil {
		t.Fatalf("encryptSecret: %v", err)
	}
	if _, err := decryptSecret(keyB, cipher); err == nil {
		t.Fatal("decryptSecret accepted ciphertext under the wrong key")
	}
}

func TestLoadOrCreateSecretKeyPersistsAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	key1, err := loadOrCreateSecretKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey (create): %v", err)
	}
	key2, err := loadOrCreateSecretKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey (load): %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatal("loadOrCreateSecretKey returned a different key on the second call against the same path")
	}
}
