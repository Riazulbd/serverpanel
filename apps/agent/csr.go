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
)

// generateKeyAndCSR creates a fresh ECDSA P-256 keypair and a PKCS#10 CSR
// for it. The requested Subject.CommonName is never trusted by the control
// plane (both http.go's registration handler and gateway.go's renewal
// handler bind the issued certificate's CommonName to the caller's already-
// validated server identity instead — see docs/SECURITY.md §1-2), so its
// exact value here is only ever informational.
func generateKeyAndCSR(commonName string) (key *ecdsa.PrivateKey, csrPEM []byte, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// writeFileAtomic writes data to a temp file in the same directory as path
// and renames it into place, so a process crash or power loss mid-write can
// never leave a half-written identity file that a later startup would try
// (and fail) to load. Used for both the agent's initial identity (see
// register.go) and renewed certificates (see renew.go).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
