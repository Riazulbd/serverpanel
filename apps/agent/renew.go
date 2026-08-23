package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// renewalCheckInterval controls how often the agent checks whether its
// client certificate needs renewing. It only needs to be well inside
// renewalWindow, not continuous — renewal itself only actually happens once
// per certificate lifetime.
const renewalCheckInterval = 1 * time.Hour

// renewalWindow is how far ahead of a certificate's expiry the agent
// proactively requests a replacement. It's intentionally generous relative
// to agentCertTTL (30 days, defined control-plane side in
// apps/controlplane/ca.go) so a renewal attempt that fails once (e.g. the
// gateway briefly unreachable) still has many more renewalCheckInterval
// retries before the certificate actually expires and the agent loses
// connectivity for good — see docs/SECURITY.md §2.
const renewalWindow = 7 * 24 * time.Hour

// renewalResponseTimeout bounds how long a single renewal request waits for
// the gateway's reply before giving up and retrying on the next tick.
const renewalResponseTimeout = 30 * time.Second

// certExpiringSoon reports whether the given PEM-encoded certificate's
// NotAfter falls within window of now.
func certExpiringSoon(certPEM []byte, window time.Duration) (bool, time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, time.Time{}, err
	}
	return time.Until(cert.NotAfter) < window, cert.NotAfter, nil
}

// renewalLoop watches the current on-disk identity's certificate and, once
// it's within renewalWindow of expiring, requests a fresh one over the
// already-authenticated connection and persists it to dataDir. It returns
// nil the moment a renewal succeeds — the caller (runConnection) treats
// that as a signal to close the connection and reconnect, so the new
// certificate takes effect promptly rather than sitting unused on disk
// until whatever the next unrelated reconnect happens to be. It returns
// ctx.Err() only when ctx is cancelled (connection torn down for an
// unrelated reason, or agent shutting down).
func renewalLoop(ctx context.Context, dataDir string, id *identity, safeEnc *safeEncoder, renewResp <-chan proto.RenewResponse) error {
	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			soon, notAfter, err := certExpiringSoon(id.CertPEM, renewalWindow)
			if err != nil {
				log.Printf("cert renewal: could not parse current certificate, skipping check: %v", err)
				continue
			}
			if !soon {
				continue
			}
			log.Printf("cert renewal: certificate expires %s, requesting a fresh one", notAfter.Format(time.RFC3339))
			if err := performRenewal(ctx, dataDir, id, safeEnc, renewResp); err != nil {
				log.Printf("cert renewal: attempt failed, will retry in %s: %v", renewalCheckInterval, err)
				continue
			}
			log.Printf("cert renewal: succeeded, reconnecting to use the new certificate")
			return nil
		}
	}
}

// performRenewal runs one renewal attempt: generate a new keypair/CSR, send
// it over the live session, wait for the gateway's response, and persist
// the result. On success it also updates id in place so the caller has the
// new certificate immediately without re-reading it from disk.
func performRenewal(ctx context.Context, dataDir string, id *identity, safeEnc *safeEncoder, renewResp <-chan proto.RenewResponse) error {
	key, csrPEM, err := generateKeyAndCSR("pending-renewal")
	if err != nil {
		return fmt.Errorf("generate renewal CSR: %w", err)
	}
	if err := safeEnc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renewal request: %w", err)
	}

	var resp proto.RenewResponse
	select {
	case resp = <-renewResp:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(renewalResponseTimeout):
		return fmt.Errorf("timed out waiting for gateway's renewal response")
	}
	if resp.Error != "" {
		return fmt.Errorf("gateway rejected renewal: %s", resp.Error)
	}
	if resp.CertPEM == "" {
		return fmt.Errorf("gateway returned an empty certificate")
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal renewed key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := writeFileAtomic(certPath, []byte(resp.CertPEM), 0600); err != nil {
		return fmt.Errorf("persist renewed certificate: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed key: %w", err)
	}

	id.CertPEM = []byte(resp.CertPEM)
	id.KeyPEM = keyPEM
	return nil
}
