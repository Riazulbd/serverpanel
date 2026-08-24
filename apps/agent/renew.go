package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// renewBeforeExpiry is how far ahead of a certificate's expiry the agent
// starts trying to renew it. Certificates are issued with a 30-day TTL
// (apps/controlplane/http.go, apps/controlplane/gateway.go), so a generous
// 10-day window gives many reconnect cycles a chance to succeed well before
// expiry would ever block reconnection — this agent maintains one
// long-lived connection and only dials again on disconnect (see
// connect.go), so renewal deliberately doesn't require or trigger one.
const renewBeforeExpiry = 10 * 24 * time.Hour

// renewCheckInterval is how often the running connection checks whether its
// certificate needs renewing. Cheap (a local PEM parse, no network call
// unless renewal is actually due), so a modest interval costs nothing at
// idle — see docs/SYSTEM.md §22 on keeping the agent's steady-state
// footprint minimal.
const renewCheckInterval = 6 * time.Hour

// certNotAfter parses a certificate's expiry out of its leaf PEM block.
func certNotAfter(certPEM []byte) (time.Time, error) {
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

// renewalLoop periodically checks id's current certificate and, once within
// renewBeforeExpiry of expiring, requests a fresh one over the connection's
// already-authenticated session. On success the new cert/key are persisted
// to dataDir and id is updated in place (id is the same pointer main.go's
// reconnect loop reuses across dials) so the next reconnect automatically
// picks them up. Failures are logged and retried on the next tick — a
// transient renewal failure here is never fatal to the current session.
func renewalLoop(ctx context.Context, enc *json.Encoder, id *identity, dataDir string, resp <-chan proto.RenewResponse) {
	ticker := time.NewTicker(renewCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			notAfter, err := certNotAfter(id.CertPEM)
			if err != nil {
				log.Printf("renewal: could not parse current certificate, skipping check: %v", err)
				continue
			}
			if time.Until(notAfter) > renewBeforeExpiry {
				continue
			}
			log.Printf("certificate expires %s, requesting renewal", notAfter.Format(time.RFC3339))
			if err := requestRenewal(enc, id, dataDir, resp); err != nil {
				log.Printf("certificate renewal failed, will retry: %v", err)
				continue
			}
			log.Printf("certificate renewed, now valid until next expiry check")
		}
	}
}

// requestRenewal generates a fresh keypair and CSR, sends it as a
// RenewRequest, and waits for the gateway's RenewResponse. On success the
// new key and certificate are written to dataDir atomically (temp file +
// rename) before id is updated, so a crash mid-write never leaves a
// truncated identity on disk — this agent runs unattended, and a corrupted
// identity file would otherwise be a self-inflicted permanent lockout.
func requestRenewal(enc *json.Encoder, id *identity, dataDir string, resp <-chan proto.RenewResponse) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ServerID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renewal request: %w", err)
	}

	select {
	case rr := <-resp:
		if rr.Error != "" {
			return fmt.Errorf("gateway rejected renewal: %s", rr.Error)
		}
		if rr.CertPEM == "" {
			return fmt.Errorf("gateway returned an empty certificate")
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		certPath, keyPath, _, _ := identityPaths(dataDir)
		if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
			return fmt.Errorf("persist renewed key: %w", err)
		}
		if err := writeFileAtomic(certPath, []byte(rr.CertPEM), 0600); err != nil {
			return fmt.Errorf("persist renewed certificate: %w", err)
		}
		id.CertPEM = []byte(rr.CertPEM)
		id.KeyPEM = keyPEM
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timed out waiting for gateway renewal response")
	}
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
