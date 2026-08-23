package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedCertPEM builds a throwaway self-signed certificate with the
// given NotAfter, for exercising certExpiringSoon without needing the
// control-plane CA.
func selfSignedCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "srv-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCertExpiringSoon(t *testing.T) {
	cases := []struct {
		name       string
		notAfter   time.Time
		window     time.Duration
		wantExpiry bool
	}{
		{"far in the future, outside window", time.Now().Add(30 * 24 * time.Hour), 7 * 24 * time.Hour, false},
		{"inside the renewal window", time.Now().Add(3 * 24 * time.Hour), 7 * 24 * time.Hour, true},
		{"already expired", time.Now().Add(-time.Hour), 7 * 24 * time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM := selfSignedCertPEM(t, tc.notAfter)
			soon, notAfter, err := certExpiringSoon(certPEM, tc.window)
			if err != nil {
				t.Fatalf("certExpiringSoon: %v", err)
			}
			if soon != tc.wantExpiry {
				t.Fatalf("certExpiringSoon = %v, want %v", soon, tc.wantExpiry)
			}
			if notAfter.Unix() != tc.notAfter.Unix() {
				t.Fatalf("returned NotAfter = %s, want %s", notAfter, tc.notAfter)
			}
		})
	}
}

func TestCertExpiringSoonRejectsInvalidPEM(t *testing.T) {
	if _, _, err := certExpiringSoon([]byte("not a certificate"), 7*24*time.Hour); err == nil {
		t.Fatal("expected an error for invalid certificate PEM, got nil")
	}
}
