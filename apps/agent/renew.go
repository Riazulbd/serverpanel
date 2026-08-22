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

// certRenewalThreshold is how far before a client certificate's expiry the
// agent starts requesting a fresh one. Certs are issued with a 30-day TTL
// (see apps/controlplane/ca.go agentCertTTL), so a week-long window gives
// plenty of retries — a brief control-plane or network outage can't turn a
// missed renewal into an expired, unrecoverable identity (see
// certRenewalLoop in connect.go, which retries hourly).
const certRenewalThreshold = 7 * 24 * time.Hour

// certExpiry parses the NotAfter time out of a PEM-encoded certificate.
func certExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// shouldRenewCert reports whether a certificate expiring at notAfter should
// be renewed now, evaluated at "now" with the given lead time.
func shouldRenewCert(notAfter, now time.Time, threshold time.Duration) bool {
	return !notAfter.After(now.Add(threshold))
}

// generateRenewalCSR creates a brand new keypair and CSR for a renewal
// request. A fresh key is generated on every renewal rather than reusing the
// expiring cert's key, so a rotation is a genuine key rotation, not just a
// new expiry date on the same key material. The requested CommonName is
// informational only — the control plane's CA binds the issued certificate's
// identity to the already-authenticated session, never to anything in the
// CSR (see apps/controlplane/gateway.go's MsgRenewCert handling).
func generateRenewalCSR(serverID string) (csrPEM, keyPEM []byte, err error) {
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

// persistRenewedCert atomically replaces the on-disk cert/key pair with a
// freshly renewed one: each file is written to a ".tmp" sibling and renamed
// into place, so a crash mid-write never leaves a truncated file behind.
// Renaming the cert before the key leaves a narrow window where a crash
// could leave a new cert paired with the old key on disk; that pairing
// fails to load as a valid TLS certificate on the next agent start
// (runConnection's tls.X509KeyPair call), which is a fail-closed outcome —
// the operator re-registers with a fresh bootstrap token, the same recovery
// path already documented for a fully expired certificate — rather than a
// silent trust downgrade.
func persistRenewedCert(dataDir string, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := writeFileAtomic(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed certificate: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed key: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
