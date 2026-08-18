package main

import (
	"path/filepath"
	"testing"
)

func TestSecretBoxRoundTripsAcrossReload(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "secrets.key")

	box1, err := loadOrCreateSecretKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	ct, err := box1.encrypt("s3cret-db-password-value")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if ct == "s3cret-db-password-value" {
		t.Fatal("ciphertext must not equal the plaintext")
	}
	pt, err := box1.decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != "s3cret-db-password-value" {
		t.Fatalf("decrypt = %q, want original plaintext", pt)
	}

	// Simulate a control-plane restart: a fresh secretBox loaded from the
	// same on-disk key file must still decrypt ciphertext sealed by the
	// first instance, the same way loadOrCreateAgentCA must survive a
	// restart without invalidating already-issued certificates.
	box2, err := loadOrCreateSecretKey(keyPath)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey (reload): %v", err)
	}
	pt2, err := box2.decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt after reload: %v", err)
	}
	if pt2 != "s3cret-db-password-value" {
		t.Fatalf("decrypt after reload = %q, want original plaintext", pt2)
	}
}

func TestSecretBoxRejectsTamperedCiphertext(t *testing.T) {
	box, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secrets.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	ct, err := box.encrypt("another-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	tampered := []byte(ct)
	// Flip a byte inside the base64 alphabet so the string still decodes
	// but the underlying ciphertext/tag no longer authenticates.
	for i := len(tampered) - 1; i >= 0; i-- {
		if tampered[i] != '=' {
			if tampered[i] == 'A' {
				tampered[i] = 'B'
			} else {
				tampered[i] = 'A'
			}
			break
		}
	}
	if _, err := box.decrypt(string(tampered)); err == nil {
		t.Fatal("expected decrypt to reject tampered ciphertext, got nil error")
	}
}

func TestSecretBoxTwoInstancesUseIndependentKeysWithoutAPersistedFile(t *testing.T) {
	box1, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secrets.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	box2, err := loadOrCreateSecretKey(filepath.Join(t.TempDir(), "secrets.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	ct, err := box1.encrypt("cross-instance-secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := box2.decrypt(ct); err == nil {
		t.Fatal("expected a differently-keyed secretBox to fail decrypting another instance's ciphertext")
	}
}
