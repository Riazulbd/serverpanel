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
	"net"
	"os"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// certRenewalThreshold is how far ahead of a client certificate's expiry the
// agent proactively requests a replacement. It is well inside the 30-day
// certificate TTL the control plane issues (apps/controlplane/ca.go
// agentCertTTL), so a renewal gets many retries across normal reconnect
// cycles before the old certificate would actually expire, even if the
// gateway or network is intermittently unavailable.
const certRenewalThreshold = 7 * 24 * time.Hour

// certRenewalCheckInterval is how often a live connection checks whether its
// certificate needs renewing. The wide threshold above means this does not
// need to be frequent — an hourly check is cheap and still leaves days of
// margin for retries.
const certRenewalCheckInterval = time.Hour

// certRenewalResponseTimeout bounds how long a renewal waits for the
// gateway's response before giving up for this cycle and retrying on the
// next tick.
const certRenewalResponseTimeout = 30 * time.Second

// certExpiry parses the NotAfter of a PEM-encoded certificate.
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

// certRenewalLoop periodically checks the current identity's certificate
// expiry and, once within certRenewalThreshold of it, requests a fresh
// certificate over the already-authenticated connection identified by enc.
// On success it atomically replaces the on-disk identity, updates id in
// place, and closes conn so the caller's read loop returns and the agent's
// normal reconnect logic (apps/agent/main.go) redials using the new
// certificate — renewal never restarts the process, and never touches the
// still-valid old certificate.
func certRenewalLoop(ctx context.Context, dataDir string, id *identity, enc jsonEncoder, renewResultCh <-chan proto.RenewResponse, conn net.Conn) {
	ticker := time.NewTicker(certRenewalCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewIfDue(ctx, dataDir, id, enc, renewResultCh, conn)
		}
	}
}

func renewIfDue(ctx context.Context, dataDir string, id *identity, enc jsonEncoder, renewResultCh <-chan proto.RenewResponse, conn net.Conn) {
	expiry, err := certExpiry(id.CertPEM)
	if err != nil {
		log.Printf("cert renewal: could not parse current certificate: %v", err)
		return
	}
	if time.Until(expiry) > certRenewalThreshold {
		return
	}
	log.Printf("certificate expires %s (within renewal threshold), requesting a fresh one", expiry.Format(time.RFC3339))

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

	select {
	case resp := <-renewResultCh:
		if resp.Error != "" {
			log.Printf("cert renewal rejected by gateway: %s", resp.Error)
			return
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			log.Printf("cert renewal: marshal key: %v", err)
			return
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if err := persistRenewedIdentity(dataDir, []byte(resp.CertPEM), keyPEM); err != nil {
			log.Printf("cert renewal: persist new identity: %v", err)
			return
		}
		id.CertPEM = []byte(resp.CertPEM)
		id.KeyPEM = keyPEM
		log.Printf("certificate renewed; reconnecting to use it")
		conn.Close()
	case <-time.After(certRenewalResponseTimeout):
		log.Printf("cert renewal: timed out waiting for gateway response, will retry next cycle")
	case <-ctx.Done():
	}
}

// persistRenewedIdentity atomically replaces the on-disk certificate and key
// (write-to-temp-then-rename within the same directory) so a crash mid-write
// can never leave a torn/partial certificate or key file on disk — the
// agent would otherwise be unable to reconnect at all until manually
// re-registered.
func persistRenewedIdentity(dataDir string, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := atomicWriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("write renewed cert: %w", err)
	}
	if err := atomicWriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write renewed key: %w", err)
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

// jsonEncoder is the subset of *json.Encoder used here, so tests can supply
// a fake that captures/replays envelopes without a real TLS connection.
type jsonEncoder interface {
	Encode(v any) error
}
