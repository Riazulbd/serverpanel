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

// renewalCheckInterval is how often the agent checks whether its current
// certificate needs renewing. renewalWindow is how much life must remain
// before the agent proactively requests a new one — comfortably wider than
// renewalCheckInterval so a single missed/slow renewal attempt (network
// blip, gateway briefly unreachable) still leaves several more chances
// before the certificate actually expires and the agent would need a full
// manual bootstrap-token re-registration to recover.
const (
	renewalCheckInterval = time.Hour
	renewalWindow        = 7 * 24 * time.Hour
)

// certNotAfter parses a PEM-encoded certificate's expiry time.
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

// shouldRenew reports whether a certificate expiring at notAfter should be
// renewed now, given how much of its remaining life falls inside window.
// Pulled out as a pure function so the renewal decision itself is testable
// without waiting on real wall-clock time.
func shouldRenew(now, notAfter time.Time, window time.Duration) bool {
	return notAfter.Sub(now) <= window
}

// newRenewalCSR generates a fresh keypair and CSR for a renewal request. A
// new keypair every renewal (never reusing the previous one) means a
// compromised old private key can't be extended by riding along on a
// legitimate renewal.
func newRenewalCSR() (key *ecdsa.PrivateKey, csrPEM []byte, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-renewal"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// persistRenewedCert writes the new cert/key to the same paths
// loadIdentity reads from, and updates id in place so the next reconnect
// (main.go's retry loop reuses the same *identity across iterations) picks
// it up. Writes go through a temp-file-then-rename per file so a crash
// mid-write can never leave a half-written cert or key on disk — the
// previous, still-valid pair is what a partial write would leave behind,
// not a corrupt one.
func persistRenewedCert(dataDir string, id *identity, key *ecdsa.PrivateKey, certPEM []byte) error {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed key: %w", err)
	}
	if err := atomicWriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed cert: %w", err)
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

// renewalLoop periodically checks the current on-disk certificate's expiry
// and, once inside renewalWindow, requests a fresh one over the already-
// authenticated mTLS session. Only one renewal is ever in flight: the loop
// blocks on the response (bounded by a timeout) before it will consider
// renewing again, so a slow or lost response can't trigger a pile-up of
// concurrent requests.
func renewalLoop(ctx context.Context, w *safeEncoder, dataDir string, id *identity, results <-chan proto.RenewCertResult) {
	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			notAfter, err := certNotAfter(id.CertPEM)
			if err != nil {
				log.Printf("cert renewal: could not parse current certificate, skipping check: %v", err)
				continue
			}
			if !shouldRenew(time.Now(), notAfter, renewalWindow) {
				continue
			}
			log.Printf("certificate expires %s, requesting renewal", notAfter.Format(time.RFC3339))
			if err := attemptRenewal(ctx, w, dataDir, id, results); err != nil {
				log.Printf("cert renewal attempt failed, will retry at next check: %v", err)
			} else {
				log.Printf("certificate renewed, valid until %s", func() string {
					if t, err := certNotAfter(id.CertPEM); err == nil {
						return t.Format(time.RFC3339)
					}
					return "unknown"
				}())
			}
		}
	}
}

func attemptRenewal(ctx context.Context, w *safeEncoder, dataDir string, id *identity, results <-chan proto.RenewCertResult) error {
	key, csrPEM, err := newRenewalCSR()
	if err != nil {
		return fmt.Errorf("generate renewal CSR: %w", err)
	}
	if err := w.Encode(proto.Envelope{Type: proto.MsgRenewCert, RenewCert: &proto.RenewCertRequest{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renewal request: %w", err)
	}

	select {
	case res := <-results:
		if !res.Ok {
			return fmt.Errorf("gateway declined renewal: %s", res.Error)
		}
		if err := persistRenewedCert(dataDir, id, key, []byte(res.CertPEM)); err != nil {
			return err
		}
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timed out waiting for renewal response")
	case <-ctx.Done():
		return ctx.Err()
	}
}
