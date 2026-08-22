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
	"sync"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// defaultRenewBefore controls how long before its NotAfter the agent
// proactively asks the gateway for a fresh certificate. It is well short of
// the 30-day TTL the control plane issues (apps/controlplane/ca.go
// agentCertTTL) so a handful of missed connection windows (an outage, a
// paused VPS) still leave room to succeed before the old cert actually
// expires and the agent falls back to manual re-registration (see
// docs/SECURITY.md §2).
const (
	defaultRenewBefore   = 7 * 24 * time.Hour
	renewalCheckInterval = time.Hour
)

// pendingRenewal holds the private key generated for an in-flight
// renew_request until the matching renew_response arrives on the same
// connection. Only one renewal is ever in flight per connection.
type pendingRenewal struct {
	mu     sync.Mutex
	keyPEM []byte
}

func (p *pendingRenewal) start(keyPEM []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keyPEM = keyPEM
}

// take returns and clears the in-flight key, or nil if none is pending
// (e.g. an unsolicited/duplicate renew_response).
func (p *pendingRenewal) take() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := p.keyPEM
	p.keyPEM = nil
	return key
}

func (p *pendingRenewal) inFlight() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keyPEM != nil
}

// certNotAfter parses the NotAfter field of a PEM-encoded certificate.
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

// certRenewalLoop periodically checks the currently-active identity's
// certificate expiry and, once inside renewBefore of NotAfter, generates a
// fresh keypair/CSR and sends a renew_request over the live connection. It
// never blocks on a response — handleRenewResponse (connect.go) completes
// the exchange when renew_response arrives, or the next tick retries if the
// gateway never answers (e.g. this connection drops mid-renewal).
func certRenewalLoop(ctx context.Context, enc *json.Encoder, id *identity, renewBefore time.Duration, pending *pendingRenewal) {
	// Check once shortly after connecting (covers an agent that was
	// offline through most of its renewal window) rather than waiting a
	// full tick first.
	maybeRenew(enc, id, renewBefore, pending)

	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			maybeRenew(enc, id, renewBefore, pending)
		}
	}
}

func maybeRenew(enc *json.Encoder, id *identity, renewBefore time.Duration, pending *pendingRenewal) {
	if pending.inFlight() {
		return
	}
	notAfter, err := certNotAfter(id.CertPEM)
	if err != nil {
		log.Printf("could not parse current certificate to check renewal: %v", err)
		return
	}
	if time.Until(notAfter) > renewBefore {
		return
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("cert renewal: generate key: %v", err)
		return
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ServerID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		log.Printf("cert renewal: create CSR: %v", err)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Printf("cert renewal: marshal key: %v", err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	pending.start(keyPEM)
	log.Printf("current certificate expires %s, requesting renewal", notAfter.Format(time.RFC3339))
	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		log.Printf("cert renewal: send request: %v", err)
		pending.take() // clear so the next tick retries instead of waiting forever for a response that was never sent
	}
}

// handleRenewResponse completes a renewal in progress: persists the new
// cert/key to disk (atomically — a partial write must never leave the
// agent with no usable identity), updates the in-memory identity so the
// next reconnect uses it, and only then tells the gateway it's safe to
// revoke the old certificate.
func handleRenewResponse(dataDir string, id *identity, enc *json.Encoder, resp proto.RenewResponse, pending *pendingRenewal) {
	keyPEM := pending.take()
	if keyPEM == nil {
		log.Printf("received renew_response with no matching in-flight request; ignoring")
		return
	}
	if resp.Error != "" {
		log.Printf("certificate renewal rejected by control plane: %s", resp.Error)
		return
	}
	if resp.CertPEM == "" {
		log.Printf("certificate renewal response had no certificate; ignoring")
		return
	}

	if err := persistRenewedIdentity(dataDir, id, []byte(resp.CertPEM), keyPEM); err != nil {
		log.Printf("failed to persist renewed certificate (keeping current one): %v", err)
		return
	}
	log.Printf("certificate renewed, new expiry %s", resp.NotAfter.Format(time.RFC3339))

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewAck, RenewAck: &proto.RenewAck{OK: true}}); err != nil {
		// The new cert is already durably on disk and will be used on the
		// next reconnect regardless; a lost ack only delays revocation of
		// the now-superseded certificate, it never loses the new identity.
		log.Printf("cert renewal: send ack: %v", err)
	}
}

// persistRenewedIdentity writes the new cert/key to the same on-disk paths
// register() uses, via write-to-temp-then-rename so a crash mid-write never
// leaves a truncated cert or key file, then updates *id in place so the
// caller's next reconnect (main.go reuses the same *identity across
// retries) picks up the new credential without re-reading disk.
func persistRenewedIdentity(dataDir string, id *identity, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)

	if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := writeFileAtomic(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	id.CertPEM = certPEM
	id.KeyPEM = keyPEM
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
