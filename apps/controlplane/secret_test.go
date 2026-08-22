package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSecretBoxEncryptDecryptRoundTrip(t *testing.T) {
	box, err := newSecretBox(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("newSecretBox: %v", err)
	}

	ct, err := box.Encrypt("s3cret-db-password")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ct == "s3cret-db-password" {
		t.Fatal("Encrypt returned the plaintext unchanged")
	}

	pt, err := box.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "s3cret-db-password" {
		t.Fatalf("Decrypt = %q, want the original plaintext", pt)
	}
}

func TestSecretBoxDecryptDetectsTampering(t *testing.T) {
	box, err := newSecretBox(bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("newSecretBox: %v", err)
	}
	ct, err := box.Encrypt("original")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := []byte(ct)
	tampered[len(tampered)-1] ^= 0xFF // flip bits in the trailing base64 chars
	if _, err := box.Decrypt(string(tampered)); err == nil {
		t.Fatal("expected Decrypt to reject a tampered ciphertext")
	}
}

func TestSecretBoxWrongKeyCannotDecrypt(t *testing.T) {
	boxA, _ := newSecretBox(bytes.Repeat([]byte{0x03}, 32))
	boxB, _ := newSecretBox(bytes.Repeat([]byte{0x04}, 32))

	ct, err := boxA.Encrypt("secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := boxB.Decrypt(ct); err == nil {
		t.Fatal("expected Decrypt with the wrong key to fail")
	}
}

func TestNewSecretBoxRejectsWrongKeyLength(t *testing.T) {
	if _, err := newSecretBox([]byte("too-short")); err == nil {
		t.Fatal("expected newSecretBox to reject a non-32-byte key")
	}
}

func TestLoadOrCreateSecretKeyPersistsAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret-key.bin")

	key1, err := loadOrCreateSecretKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey (create): %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("generated key length = %d, want 32", len(key1))
	}

	key2, err := loadOrCreateSecretKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey (reload): %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("expected loadOrCreateSecretKey to return the same key on a second call against the same path")
	}
}

func TestLoadOrCreateSecretKeyRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret-key.bin")
	if err := os.WriteFile(path, []byte("not-32-bytes"), 0600); err != nil {
		t.Fatalf("seed corrupt key file: %v", err)
	}
	if _, err := loadOrCreateSecretKey(path); err == nil {
		t.Fatal("expected loadOrCreateSecretKey to reject a key file of the wrong length")
	}
}
