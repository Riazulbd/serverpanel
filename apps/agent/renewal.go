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
	"log"
	"os"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// certRenewalThreshold is how far ahead of a certificate's expiry the agent
// starts requesting a replacement. With a 30-day certificate TTL
// (apps/controlplane/gateway.go agentCertTTL), 10 days of margin gives
// several renewal-check cycles of retry room (see renewalCheckInterval)
// before an un-renewed certificate would actually stop working — a slow
// control-plane outage or a few missed connection attempts should never be
// enough to reach an expired, un-renewable certificate.
const certRenewalThreshold = 10 * 24 * time.Hour

// renewalCheckInterval is how often a live connection re-checks whether its
// certificate needs renewing. A dedicated ticker (rather than only checking
// once per reconnect) matters because a healthy connection can legitimately
// stay open far longer than that — heartbeats keep it alive indefinitely
// without ever forcing a reconnect.
const renewalCheckInterval = 6 * time.Hour

// renewalResponseTimeout bounds how long the agent waits for the gateway to
// answer a MsgRenewRequest before giving up for this cycle and trying again
// on the next tick.
const renewalResponseTimeout = 30 * time.Second

// renewalLoop periodically checks the current certificate's expiry on a
// live connection and, when it's within certRenewalThreshold, requests a
// replacement over the mTLS session that's already open (no bootstrap token
// needed — the live session's identity itself authorizes the renewal). It
// checks once immediately on connect (in case the agent was offline for a
// while and is already inside the renewal window) and then on a ticker for
// as long as this connection stays up.
func renewalLoop(ctx context.Context, enc *safeEncoder, renewCh <-chan proto.RenewResponse, id *identity, dataDir string) {
	check := func() {
		if err := maybeRenewCertificate(enc, renewCh, id, dataDir); err != nil {
			log.Printf("certificate renewal check failed: %v", err)
		}
	}

	check()
	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// maybeRenewCertificate is the synchronous core of one renewal check/attempt.
// It returns nil (no-op, no error) whenever renewal isn't due yet.
func maybeRenewCertificate(enc *safeEncoder, renewCh <-chan proto.RenewResponse, id *identity, dataDir string) error {
	leaf, err := parseLeafCert(id.CertPEM)
	if err != nil {
		return fmt.Errorf("parse current certificate: %w", err)
	}
	if time.Until(leaf.NotAfter) > certRenewalThreshold {
		return nil // not due yet
	}
	log.Printf("certificate expires %s (within renewal threshold), requesting renewal", leaf.NotAfter.Format(time.RFC3339))

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate new key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ServerID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, newKey)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renewal request: %w", err)
	}

	select {
	case resp := <-renewCh:
		keyDER, err := x509.MarshalECPrivateKey(newKey)
		if err != nil {
			return fmt.Errorf("marshal new key: %w", err)
		}
		newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

		certPath, keyPath, _, _ := identityPaths(dataDir)
		if err := writeFileAtomic(certPath, []byte(resp.CertPEM), 0600); err != nil {
			return fmt.Errorf("persist renewed certificate: %w", err)
		}
		if err := writeFileAtomic(keyPath, newKeyPEM, 0600); err != nil {
			return fmt.Errorf("persist renewed key: %w", err)
		}

		// Only mutate the in-memory identity (picked up automatically on
		// the next reconnect by main.go's loop, which holds this same *id)
		// after both files are safely on disk — a failure above leaves the
		// old, still-valid identity fully intact and simply retries next
		// tick.
		id.CertPEM = []byte(resp.CertPEM)
		id.KeyPEM = newKeyPEM

		// Confirm to the gateway only now that the new identity is durably
		// persisted — this is what lets the gateway safely revoke the old
		// certificate (see gateway.go handleRenewConfirm). If this encode
		// fails, the old certificate simply stays un-revoked and keeps
		// working until it naturally expires; the new one is already
		// persisted and will be used on the next reconnect either way.
		if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewConfirm}); err != nil {
			log.Printf("renewed certificate persisted but confirm failed to send: %v", err)
		}
		log.Printf("certificate renewed successfully, new expiry %s (takes effect on next reconnect)", resp.ExpiresAt.Format(time.RFC3339))
		return nil
	case <-time.After(renewalResponseTimeout):
		return fmt.Errorf("timed out waiting for renewal response")
	}
}

func parseLeafCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// writeFileAtomic writes data to a temp file in the same directory as path
// and renames it into place, so a crash or power loss mid-write can never
// leave a torn/partial certificate or key file on disk — the file at path
// is always either the old complete contents or the new complete contents,
// never a mix.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
