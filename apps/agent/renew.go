package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// Renewal parameters. The 30-day certificate TTL is set control-plane-side
// (apps/controlplane/ca.go/gateway.go), not here; renewalThreshold just
// needs enough margin below that TTL that a missed check or a failed
// attempt has time to be retried well before the certificate actually
// expires. checkInterval is deliberately coarse (matching the heartbeat's
// "no aggressive polling" design goal) since the threshold gives days of
// slack, not minutes.
const (
	certRenewalThreshold     = 7 * 24 * time.Hour
	certRenewalCheckInterval = time.Hour
	certRenewalReplyTimeout  = 30 * time.Second
)

// certExpiry parses a PEM-encoded X.509 certificate and returns its
// NotAfter time.
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

// renewalLoop periodically checks the agent's current certificate expiry
// and, once within certRenewalThreshold of expiring, requests a fresh one
// over the already-authenticated mTLS session (rather than re-running the
// bootstrap-token flow, which is single-use and requires a human to issue a
// new token). It runs for the lifetime of one connection; if the connection
// drops, main.go's reconnect loop starts a fresh renewalLoop on the next
// successful connection, so a renewal that didn't complete before a drop is
// simply retried once reconnected.
func renewalLoop(ctx context.Context, id *identity, dataDir string, enc *json.Encoder, renewed <-chan proto.RenewResponse) {
	checkAndRenew(id, dataDir, enc, renewed)

	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAndRenew(id, dataDir, enc, renewed)
		}
	}
}

func checkAndRenew(id *identity, dataDir string, enc *json.Encoder, renewed <-chan proto.RenewResponse) {
	certPEM, _ := id.snapshot()
	expiry, err := certExpiry(certPEM)
	if err != nil {
		log.Printf("cert renewal: could not read current certificate expiry: %v", err)
		return
	}
	if time.Until(expiry) > certRenewalThreshold {
		return
	}

	log.Printf("cert renewal: current certificate expires %s, requesting a new one", expiry.Format(time.RFC3339))
	csrPEM, keyPEM, err := generateKeyAndCSR()
	if err != nil {
		log.Printf("cert renewal: could not generate CSR: %v", err)
		return
	}
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenew, Renew: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		log.Printf("cert renewal: could not send renew request: %v", err)
		return
	}

	select {
	case resp := <-renewed:
		if resp.Error != "" {
			log.Printf("cert renewal: gateway rejected renewal: %s", resp.Error)
			return
		}
		if resp.CertPEM == "" {
			log.Printf("cert renewal: gateway returned an empty certificate, ignoring")
			return
		}
		if err := persistRenewedIdentity(dataDir, id, []byte(resp.CertPEM), keyPEM); err != nil {
			log.Printf("cert renewal: could not persist new certificate: %v", err)
			return
		}
		newExpiry, _ := certExpiry([]byte(resp.CertPEM))
		log.Printf("cert renewal: succeeded, new certificate expires %s", newExpiry.Format(time.RFC3339))
	case <-time.After(certRenewalReplyTimeout):
		log.Printf("cert renewal: timed out waiting for gateway response, will retry on next check")
	}
}

// persistRenewedIdentity durably writes the new cert/key pair to disk
// before updating the in-memory identity, so a crash between the two never
// leaves the on-disk files and the running process's view disagreeing —
// worst case on a crash here, the write already landed (rename is atomic)
// and the process simply reloads it via loadIdentity on the next start.
func persistRenewedIdentity(dataDir string, id *identity, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := atomicWriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("write renewed cert: %w", err)
	}
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write renewed key: %w", err)
	}
	id.update(certPEM, keyPEM)
	return nil
}
