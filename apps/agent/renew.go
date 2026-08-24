package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// errIdentityRenewed is returned by runConnection after the agent has
// persisted a renewed certificate. It is a signal, not a failure: the caller
// reloads the identity from disk and reconnects immediately (without
// backoff), so the new certificate is in use from the very next session
// rather than whenever the connection happens to drop next.
var errIdentityRenewed = errors.New("certificate renewed; reconnecting with the new identity")

// renewalFraction is how much of a certificate's total validity must remain
// before the agent stops asking to renew. At 1/3, a 30-day certificate is
// renewed once it has 10 days left — many reconnect opportunities before
// expiry, while still being far enough from issuance that a healthy agent
// renews roughly twice per certificate lifetime rather than constantly.
const renewalFraction = 3

// renewalGate rate-limits how often the agent will ask for a new
// certificate, across reconnects rather than per connection.
//
// This exists because a successful renewal deliberately drops the
// connection so the new certificate takes effect immediately. If the
// freshly issued certificate still reads as needing renewal — a badly
// skewed system clock, or a control plane configured with a TTL shorter
// than the renewal threshold — the agent would renew, reconnect, renew
// again, and turn one misconfigured server into a request flood against
// the gateway. The gate turns that failure mode into at most one wasted
// renewal per interval, which is recoverable and visible in the log rather
// than an outage.
type renewalGate struct {
	mu       sync.Mutex
	minEvery time.Duration
	last     time.Time
}

func newRenewalGate(minEvery time.Duration) *renewalGate {
	return &renewalGate{minEvery: minEvery}
}

// allow reports whether a renewal may be attempted now, recording the
// attempt if so.
func (g *renewalGate) allow(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.last.IsZero() && now.Sub(g.last) < g.minEvery {
		return false
	}
	g.last = now
	return true
}

// certNeedsRenewal reports whether the certificate is close enough to
// expiry to be worth renewing. An unparsable certificate returns false: the
// connection could not have been established with it in the first place, so
// treating it as "needs renewal" would only produce a request the gateway
// would have to reject.
func certNeedsRenewal(certPEM []byte, now time.Time) bool {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return false
	}
	total := cert.NotAfter.Sub(cert.NotBefore)
	if total <= 0 {
		return false
	}
	return cert.NotAfter.Sub(now) < total/renewalFraction
}

func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// newRenewalCSR generates a brand-new keypair and a CSR for it. The key is
// deliberately fresh on every renewal rather than reused: rotating the
// private key too is what makes renewal a real credential rotation instead
// of just an expiry-date extension.
func newRenewalCSR() (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate renewal key: %w", err)
	}
	// The subject here is ignored by the CA, which sets CommonName from the
	// authenticated connection's identity (see agentCA.signAgentCSR).
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "renewal"}}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create renewal CSR: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}
