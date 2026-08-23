package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// renewBefore is how far ahead of a client certificate's expiry the agent
// starts asking the gateway to renew it (see docs/SECURITY.md §2: "before
// expiry, the agent requests renewal authenticated by its current
// still-valid cert"). Against the control plane's 30-day agentCertTTL
// (apps/controlplane/ca.go), a 7-day window leaves ample room for renewal
// to succeed even across a multi-day network outage before the old
// certificate actually expires and the agent would fall back to manual
// re-registration.
const renewBefore = 7 * 24 * time.Hour

// renewRetryInterval bounds how often a failed or unacknowledged renewal
// attempt is retried, so a lost response (or a gateway that's temporarily
// rejecting renewals) doesn't turn into a tight resend loop.
const renewRetryInterval = time.Hour

// renewCheckInterval is how often renewalLoop re-checks the current
// certificate's expiry. Cheap (one PEM parse), so an hourly check against a
// multi-day renewBefore window is frequent enough to have no practical
// effect on how promptly renewal starts while staying far from a busy loop.
const renewCheckInterval = time.Hour

// certRenewer tracks in-flight certificate renewal for one connection and
// also owns synchronized access to the identity's mutable certificate
// fields (CertPEM/KeyPEM): renewalLoop's periodic check runs in its own
// goroutine while runConnection's read loop delivers the response on
// another, and both need to read/write those two fields — mu guards both
// concerns together rather than adding a second lock, since they're never
// touched independently of a renewal in flight.
type certRenewer struct {
	mu          sync.Mutex
	pendingKey  *ecdsa.PrivateKey
	lastAttempt time.Time
}

// certExpiry parses the NotAfter time out of a PEM-encoded certificate.
func certExpiry(certPEM []byte) (time.Time, error) {
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

// buildCSR generates a fresh ECDSA keypair and a signing request for it.
// The requested Subject is ignored by the CA (it binds the issued
// certificate's CommonName to the server_id it already knows from the
// session, never from the CSR — see ca.go signAgentCSR), so any
// placeholder value here is fine; register.go's initial-registration CSR
// uses the same one.
func buildCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-renewal"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// maybeRequestRenewal checks id's current certificate expiry and, if it's
// within renewBefore (and no request is already pending, and the last
// attempt wasn't too recent), sends a renew_cert request. send is the
// caller-supplied function that actually writes the envelope — kept
// generic here so this file has no direct dependency on the connection
// encoder type.
func (r *certRenewer) maybeRequestRenewal(id *identity, send func(csrPEM string) error) {
	r.mu.Lock()
	certPEM := id.CertPEM
	tooSoon := r.pendingKey != nil && time.Since(r.lastAttempt) < renewRetryInterval
	r.mu.Unlock()

	expiry, err := certExpiry(certPEM)
	if err != nil {
		log.Printf("cert renewal check: could not parse current certificate: %v", err)
		return
	}
	if time.Until(expiry) > renewBefore || tooSoon {
		return
	}

	key, csrPEM, err := buildCSR()
	if err != nil {
		log.Printf("cert renewal: could not build CSR: %v", err)
		return
	}

	r.mu.Lock()
	r.pendingKey = key
	r.lastAttempt = time.Now()
	r.mu.Unlock()

	log.Printf("certificate expires %s, requesting renewal", expiry.Format(time.RFC3339))
	if err := send(string(csrPEM)); err != nil {
		log.Printf("cert renewal: could not send request: %v", err)
	}
}

// handleRenewResult processes the gateway's response to a pending renewal
// request: on success, persists the new cert/key to dataDir (the same
// files loadIdentity reads) and updates id in place so the *next* dial
// (runConnection is re-invoked by main.go's reconnect loop after this
// connection eventually drops) uses the new identity — this deliberately
// does not force-close the current, still-valid connection just to adopt a
// cert it doesn't yet need.
func (r *certRenewer) handleRenewResult(id *identity, dataDir string, result proto.RenewCertResult) {
	r.mu.Lock()
	key := r.pendingKey
	r.pendingKey = nil
	r.mu.Unlock()

	if key == nil {
		log.Printf("cert renewal: received a result with no pending request, ignoring")
		return
	}
	if result.Error != "" {
		log.Printf("cert renewal rejected by control plane: %s (will retry)", result.Error)
		return
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Printf("cert renewal: could not marshal new key: %v", err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := []byte(result.CertPEM)

	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		log.Printf("cert renewal: could not persist new certificate: %v", err)
		return
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		log.Printf("cert renewal: could not persist new key: %v", err)
		return
	}

	r.mu.Lock()
	id.CertPEM = certPEM
	id.KeyPEM = keyPEM
	r.mu.Unlock()

	if expiry, err := certExpiry(certPEM); err == nil {
		log.Printf("certificate renewed, now valid until %s", expiry.Format(time.RFC3339))
	} else {
		log.Printf("certificate renewed")
	}
}
