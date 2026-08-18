package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// certRenewalWindow controls how far ahead of a certificate's expiry the
// agent proactively requests a replacement. The control plane issues
// 30-day certificates (apps/controlplane/ca.go's agentCertTTL); renewing
// with 10 days left gives a wide safety margin — the renewal loop retries
// hourly (see renewalLoop in connect.go), so a transient failure has dozens
// of chances to succeed before the current certificate actually expires.
const certRenewalWindow = 10 * 24 * time.Hour

// leafExpiry parses the NotAfter of a PEM-encoded leaf certificate.
func leafExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// dueForRenewal reports whether the current identity's certificate expires
// within certRenewalWindow. A certificate that fails to parse is treated as
// due, so a renewal attempt (with its own error handling and next-hour
// retry) gets a chance to recover rather than the agent silently running
// out an identity it cannot even inspect.
func dueForRenewal(certPEM []byte) bool {
	expiry, err := leafExpiry(certPEM)
	if err != nil {
		return true
	}
	return time.Until(expiry) < certRenewalWindow
}

// buildRenewalCSR generates a fresh key pair and CSR for certificate
// renewal. A new key on every renewal (rather than reusing the old one) is
// deliberate: it bounds the blast radius of a leaked private key to that
// one certificate's lifetime — the same reasoning register.go applies to
// the original registration CSR.
func buildRenewalCSR(serverID string) (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: serverID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM, nil
}

// persistRenewedIdentity replaces the on-disk certificate and key with the
// newly issued pair. Before touching disk at all, the caller must already
// have verified certPEM and keyPEM form a matching pair (connect.go does
// this with tls.X509KeyPair) — this function only handles getting the
// bytes onto disk safely:
//
//  1. the current cert/key are best-effort copied to *.bak first, so an
//     operator has a manual recovery path if something still goes wrong
//     after this returns;
//  2. each file is written to a *.tmp path and renamed into place, so a
//     crash mid-write never leaves a truncated cert or key file — a
//     rename is atomic on the same filesystem, a partial write is not.
//
// The two renames themselves are not a single transaction, so a crash
// between them is (in principle) still possible; the *.bak copy exists
// precisely to make that rare case recoverable rather than fatal.
func persistRenewedIdentity(dataDir string, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)

	if old, err := os.ReadFile(keyPath); err == nil {
		_ = os.WriteFile(keyPath+".bak", old, 0600)
	}
	if old, err := os.ReadFile(certPath); err == nil {
		_ = os.WriteFile(certPath+".bak", old, 0600)
	}

	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed key: %w", err)
	}
	if err := atomicWriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed certificate: %w", err)
	}
	return nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
