package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// certRenewalLoop watches the client certificate this session authenticated
// with and, once it enters proto.AgentCertRenewalWindow of expiry, requests
// a replacement over this same already-open mTLS connection — there is no
// separate renewal endpoint or credential; the connection itself, already
// verified by the gateway against the current certificate, *is* the
// credential (see docs/SECURITY.md §2 and gateway.handleRenewCSR).
//
// A failed renewal attempt (CA error, no response in time) is logged and
// retried on the next tick; the current certificate is still valid and the
// connection is left alone. A successful renewal persists the new cert+key
// to disk, then closes conn — the caller (runConnection) sees that as an
// ordinary connection error and returns, and main's reconnect loop reloads
// identity from disk before redialing, picking up the new certificate.
//
// Checking hourly is frequent enough relative to the multi-day renewal
// window to renew promptly without adding meaningful idle load.
func certRenewalLoop(ctx context.Context, dataDir string, certPEM []byte, conn io.Closer, cw *connWriter, renewCertCh <-chan proto.RenewCert) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		due, ok := certRenewalDue(certPEM)
		if !ok {
			log.Printf("cert renewal: could not parse current certificate; skipping check")
			continue
		}
		if !due {
			continue
		}

		keyPEM, csrPEM, err := generateRenewalCSR()
		if err != nil {
			log.Printf("cert renewal: could not generate renewal CSR: %v", err)
			continue
		}
		if err := cw.send(proto.Envelope{Type: proto.MsgRenewCSR, RenewCSR: &proto.RenewCSR{CSRPEM: string(csrPEM)}}); err != nil {
			log.Printf("cert renewal: could not send renewal request: %v", err)
			continue
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
			log.Printf("cert renewal: no response from control plane within 30s; will retry next cycle")
			continue
		case resp := <-renewCertCh:
			if resp.Error != "" {
				log.Printf("cert renewal: control plane rejected renewal: %s", resp.Error)
				continue
			}
			if resp.CertPEM == "" {
				log.Printf("cert renewal: control plane returned no certificate; will retry next cycle")
				continue
			}
			if err := persistRenewedIdentity(dataDir, []byte(resp.CertPEM), keyPEM); err != nil {
				log.Printf("cert renewal: could not persist new identity: %v", err)
				continue
			}
			log.Printf("cert renewal: succeeded, new certificate valid until %s; reconnecting to use it", resp.NotAfter.Format(time.RFC3339))
			conn.Close()
			return
		}
	}
}

// certRenewalDue reports whether certPEM is within proto.AgentCertRenewalWindow
// of its expiry. ok is false if certPEM could not be parsed at all, so the
// caller can tell "not due yet" apart from "couldn't tell."
func certRenewalDue(certPEM []byte) (due, ok bool) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, false
	}
	return time.Until(cert.NotAfter) <= proto.AgentCertRenewalWindow, true
}

// generateRenewalCSR creates a brand new key pair and CSR for a renewal
// request. A fresh key (never the one already in use) means a compromised
// old key gains nothing from the renewal exchange. The CSR's Subject is
// ignored by the CA (see ca.signAgentCSR) — the issued certificate's
// identity always comes from the server_id the gateway already derived
// from the still-valid certificate authenticating this session, never from
// anything the agent asserts here.
func generateRenewalCSR() (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-renewal"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return keyPEM, csrPEM, nil
}

// persistRenewedIdentity overwrites just the cert+key files (never
// ca.pem/identity.json — server_id and gateway_addr don't change on
// renewal) using write-to-temp-then-rename so a crash mid-write can never
// leave a truncated, unparseable cert or key on disk for the next start to
// load.
func persistRenewedIdentity(dataDir string, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist new key: %w", err)
	}
	if err := atomicWriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("persist new cert: %w", err)
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
