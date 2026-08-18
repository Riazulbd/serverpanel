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
	"net"
	"os"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

const (
	// renewalCheckInterval is how often a live connection re-checks whether
	// its client certificate needs rotating. Cheap (one x509 parse of an
	// already-in-memory PEM), so a short interval costs nothing at idle.
	renewalCheckInterval = 6 * time.Hour

	// renewalWindow is how far ahead of the certificate's actual NotAfter
	// the agent starts trying to renew it. With a 30-day agentCertTTL
	// (apps/controlplane/ca.go) this gives several renewal attempts' worth
	// of margin even if the agent is offline, or the gateway is unreachable,
	// for days at a stretch — the agent should never actually reach a hard
	// expiry with no chance to have renewed first.
	renewalWindow = 7 * 24 * time.Hour

	// renewResponseTimeout bounds how long a renewal attempt waits for the
	// gateway's response before giving up for this cycle; the next tick (or
	// the next reconnect) tries again.
	renewResponseTimeout = 30 * time.Second
)

// renewalLoop periodically checks whether id's client certificate is close
// enough to expiry to need rotating and, if so, requests a fresh one over
// this already-authenticated connection. It checks once immediately (in
// case this connection turns out to be very long-lived) and then on
// renewalCheckInterval for as long as the connection stays open.
func renewalLoop(ctx context.Context, conn net.Conn, enc *json.Encoder, id *identity, resp <-chan proto.RenewResponse) {
	maybeRenew(conn, enc, id, resp)

	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			maybeRenew(conn, enc, id, resp)
		}
	}
}

// maybeRenew renews id's certificate if it is within renewalWindow of
// expiry. On success it persists the new cert/key to disk (atomically) and
// then closes conn: the live connection keeps working fine on the old cert
// (TLS never re-validates an already-established session), but the whole
// point of renewing is to have a certificate that can be used to *reconnect*
// — so the agent deliberately forces a prompt reconnect to prove the new
// identity actually works, rather than silently carrying it unused for
// however long this connection happens to stay up. main.go's reconnect loop
// already retries with backoff, so the resulting brief disconnect is safe.
func maybeRenew(conn net.Conn, enc *json.Encoder, id *identity, resp <-chan proto.RenewResponse) {
	notAfter, err := certNotAfter(id.CertPEM)
	if err != nil {
		log.Printf("renewal: could not parse current certificate, skipping check: %v", err)
		return
	}
	if time.Until(notAfter) > renewalWindow {
		return
	}
	log.Printf("client certificate expires %s (within renewal window), requesting a new one", notAfter.Format(time.RFC3339))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("renewal: generate key: %v", err)
		return
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ServerID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		log.Printf("renewal: create CSR: %v", err)
		return
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		log.Printf("renewal: send request: %v", err)
		return
	}

	select {
	case rr := <-resp:
		if err := persistRenewedIdentity(id, key, []byte(rr.CertPEM)); err != nil {
			log.Printf("renewal: persist new identity: %v (keeping current certificate; will retry)", err)
			return
		}
		log.Printf("client certificate renewed; reconnecting to use it")
		conn.Close()
	case <-time.After(renewResponseTimeout):
		log.Printf("renewal: timed out waiting for the gateway's response; will retry next cycle")
	}
}

// certNotAfter parses certPEM just far enough to read its expiry. The agent
// deliberately re-derives this from the certificate itself rather than
// trusting any separately-asserted timestamp, so there is exactly one
// source of truth for "when does my identity stop working."
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

// persistRenewedIdentity replaces the on-disk certificate and key with a
// newly issued pair using a temp-file-then-rename write for each file, so a
// crash mid-write can never leave a half-written certificate or a
// mismatched cert/key pair on disk — the previous, still-valid pair remains
// intact until the moment the new one is fully in place. It also updates
// id in memory so a subsequent reconnect (see maybeRenew's conn.Close())
// picks up the new pair immediately.
func persistRenewedIdentity(id *identity, key *ecdsa.PrivateKey, certPEM []byte) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal new key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath, keyPath, _, _ := identityPaths(id.DataDir)
	if err := atomicWriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("write new certificate: %w", err)
	}
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write new key: %w", err)
	}

	id.CertPEM = certPEM
	id.KeyPEM = keyPEM
	return nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
