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

// generateKeyAndCSR creates a fresh ECDSA keypair and a self-signed CSR for
// it, used both at first registration (register.go) and at every later
// renewal (connect.go renewalLoop). The CSR's requested CommonName is
// informational only — the control plane always stamps the certificate's
// actual identity from server-side state (the bootstrap token at
// registration, the session's existing client cert at renewal), never from
// this value — so cn just needs to be human-readable in logs, not trusted.
func generateKeyAndCSR(cn string) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// certValidity returns the NotBefore/NotAfter window of a PEM-encoded
// certificate, used by connect.go's renewalLoop to decide when this
// agent's own client certificate is due for proactive renewal.
func certValidity(certPEM []byte) (notBefore, notAfter time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return cert.NotBefore, cert.NotAfter, nil
}

// persistRenewedCert atomically replaces the on-disk client cert+key with a
// freshly renewed pair. The previous pair is backed up first and restored
// if anything fails partway through, so a crash or disk error mid-renewal
// can never leave a certificate and private key that don't match each
// other — which would otherwise permanently lock the agent out of the
// gateway until it's manually re-registered with a brand new bootstrap
// token.
func persistRenewedCert(dataDir string, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)
	certBak := certPath + ".bak"
	certTmp, keyTmp := certPath+".tmp", keyPath+".tmp"

	oldCert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read current cert: %w", err)
	}
	if err := os.WriteFile(certBak, oldCert, 0600); err != nil {
		return fmt.Errorf("back up current cert: %w", err)
	}
	defer os.Remove(certBak)

	if err := os.WriteFile(certTmp, certPEM, 0600); err != nil {
		return fmt.Errorf("write temp cert: %w", err)
	}
	if err := os.WriteFile(keyTmp, keyPEM, 0600); err != nil {
		os.Remove(certTmp)
		return fmt.Errorf("write temp key: %w", err)
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		os.Remove(certTmp)
		os.Remove(keyTmp)
		return fmt.Errorf("rename cert into place: %w", err)
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		// Cert and key are now mismatched on disk (new cert, old key) —
		// restore the previous, still-valid cert rather than leaving the
		// agent unable to complete a TLS handshake at all until the next
		// scheduled renewal attempt. keyTmp holds a private key that never
		// got installed, so it's removed rather than left behind.
		os.Remove(keyTmp)
		if restoreErr := os.WriteFile(certPath, oldCert, 0600); restoreErr != nil {
			return fmt.Errorf("rename key into place failed (%v), AND could not restore previous cert (%v): agent identity is now broken, re-registration required", err, restoreErr)
		}
		return fmt.Errorf("rename key into place: %w (rolled back to previous certificate)", err)
	}
	return nil
}
