package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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

// certRenewalThreshold is how far ahead of a client certificate's expiry
// the agent proactively requests a replacement. Renewal happens over the
// already-authenticated mTLS session (no bootstrap token needed again), so
// there is no reason to wait until the last minute: a wide window means a
// transient control-plane outage right before expiry still leaves days of
// retries rather than one shot at reconnecting before the cert goes stale.
const certRenewalThreshold = 7 * 24 * time.Hour

// certRenewalCheckInterval is how often the agent checks whether its
// current certificate has entered the renewal window. Cheap (one x509
// parse), so hourly is not a resource concern and still reacts quickly
// relative to the multi-day window above.
const certRenewalCheckInterval = time.Hour

// renewalLoop periodically checks id's certificate expiry and, once inside
// certRenewalThreshold, requests a replacement over the live connection.
// It checks once immediately on start (covers an agent that was offline
// long enough to reconnect already inside the window), then on a ticker.
func renewalLoop(ctx context.Context, enc *json.Encoder, respCh <-chan proto.RenewResponse, id *identity, dataDir string) {
	maybeRenew(ctx, enc, respCh, id, dataDir)

	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			maybeRenew(ctx, enc, respCh, id, dataDir)
		}
	}
}

// maybeRenew is renewalLoop's single check-and-renew pass, split out so it
// can be unit tested without a ticker/context loop around it.
func maybeRenew(ctx context.Context, enc *json.Encoder, respCh <-chan proto.RenewResponse, id *identity, dataDir string) {
	due, notAfter, err := certDueForRenewal(id.CertPEM)
	if err != nil {
		log.Printf("cert renewal check: %v", err)
		return
	}
	if !due {
		return
	}
	log.Printf("client certificate expires %s (within renewal window), requesting replacement", notAfter.Format(time.RFC3339))

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

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		log.Printf("cert renewal: send request: %v", err)
		return
	}

	renewCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case resp := <-respCh:
		if resp.Error != "" {
			log.Printf("cert renewal rejected by gateway: %s", resp.Error)
			return
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			log.Printf("cert renewal: marshal new key: %v", err)
			return
		}
		newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		newCertPEM := []byte(resp.CertPEM)
		if err := persistRenewedIdentity(dataDir, newCertPEM, newKeyPEM); err != nil {
			log.Printf("cert renewal: persist new identity: %v", err)
			return
		}
		id.CertPEM, id.KeyPEM = newCertPEM, newKeyPEM
		log.Printf("certificate renewed; new certificate will be used on next reconnect")
	case <-renewCtx.Done():
		log.Printf("cert renewal: timed out waiting for gateway response")
	}
}

// certDueForRenewal reports whether certPEM's expiry is within
// certRenewalThreshold of now.
func certDueForRenewal(certPEM []byte) (due bool, notAfter time.Time, err error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, time.Time{}, fmt.Errorf("could not decode current certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("could not parse current certificate: %w", err)
	}
	return time.Until(cert.NotAfter) <= certRenewalThreshold, cert.NotAfter, nil
}

// persistRenewedIdentity writes a freshly renewed cert/key pair to disk,
// replacing the previous pair. It is not possible to atomically replace two
// separate files at once, so a process crash between the two renames below
// could otherwise leave a mismatched pair (new cert, old key, or vice
// versa) that can never complete a TLS handshake again — bricking an
// unattended agent. To make that recoverable, the previous, known-good pair
// is backed up to *.prev *before* either file is touched; loadIdentity
// automatically falls back to that backup if the live pair fails to verify.
func persistRenewedIdentity(dataDir string, certPEM, keyPEM []byte) error {
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("new cert/key do not form a valid pair, refusing to persist: %w", err)
	}

	certPath, keyPath, _, _ := identityPaths(dataDir)

	prevCertPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read current certificate before renewal: %w", err)
	}
	prevKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read current key before renewal: %w", err)
	}
	if err := os.WriteFile(certPath+".prev", prevCertPEM, 0600); err != nil {
		return fmt.Errorf("back up previous certificate: %w", err)
	}
	if err := os.WriteFile(keyPath+".prev", prevKeyPEM, 0600); err != nil {
		return fmt.Errorf("back up previous key: %w", err)
	}

	if err := writeFileAtomic(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("write new certificate: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write new key: %w", err)
	}
	return nil
}

// writeFileAtomic writes to a temp file in the same directory and renames
// it into place, so a reader (or a crash mid-write) never observes a
// partially written cert/key file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
