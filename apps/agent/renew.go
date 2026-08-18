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
	"path/filepath"
	"sync"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// renewalWindow controls how far ahead of a certificate's expiry the agent
// requests a fresh one. It must comfortably exceed the longest realistic gap
// between renewal ticks (renewalCheckInterval) plus the time a server could
// plausibly stay disconnected, so a slow/flaky network never lets a
// certificate reach its control-plane-issued TTL (apps/controlplane/ca.go's
// AgentCertTTL, 30 days) unrenewed.
const renewalWindow = 7 * 24 * time.Hour

// renewalCheckInterval is how often a live connection re-checks whether its
// certificate is due for renewal. It does not need to be frequent: the
// window above gives days of slack.
const renewalCheckInterval = 12 * time.Hour

// syncEncoder serializes writes from the several goroutines that share one
// connection's *json.Encoder (heartbeatLoop, per-task handleTask calls, and
// the renewal loop) — encoding to the same underlying net.Conn concurrently
// without a lock could interleave partial JSON writes from two goroutines
// into one corrupted stream.
type syncEncoder struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (s *syncEncoder) Encode(v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(v)
}

// certNotAfter parses a PEM-encoded certificate's expiry.
func certNotAfter(certPEM []byte) (time.Time, error) {
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

// renewalDue reports whether a certificate expiring at notAfter should be
// renewed now, given the current time.
func renewalDue(notAfter, now time.Time) bool {
	return notAfter.Sub(now) <= renewalWindow
}

// renewalLoop periodically checks id's certificate expiry and, once it's
// within renewalWindow, requests a fresh one over the live mTLS session and
// persists it to disk. A failed renewal attempt is logged and retried on the
// next tick — the agent keeps operating on its current (still valid, just
// not-yet-renewed) certificate in the meantime, so a transient failure here
// is never fatal to the connection.
func renewalLoop(ctx context.Context, dataDir string, id *identity, enc *syncEncoder, renewCh <-chan proto.RenewResponse) {
	ticker := time.NewTicker(renewalCheckInterval)
	defer ticker.Stop()

	// Also check once shortly after connecting, so a long-lived process that
	// happened to (re)connect just past the renewal window doesn't wait a
	// full interval before renewing.
	check := func() {
		notAfter, err := certNotAfter(id.CertPEM)
		if err != nil {
			log.Printf("renewal: could not parse current certificate: %v", err)
			return
		}
		if !renewalDue(notAfter, time.Now()) {
			return
		}
		if err := requestRenewal(dataDir, id, enc, renewCh); err != nil {
			log.Printf("certificate renewal failed (current cert still valid until %s): %v", notAfter.Format(time.RFC3339), err)
			return
		}
		log.Printf("certificate renewed successfully")
	}

	check()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

// requestRenewal generates a fresh keypair, sends a RenewRequest over enc,
// waits (bounded) for the gateway's RenewResponse on renewCh, and persists
// the result to disk before mutating id in place so subsequent reconnects
// (and a process restart immediately afterward) use the renewed identity.
func requestRenewal(dataDir string, id *identity, enc *syncEncoder, renewCh <-chan proto.RenewResponse) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate renewal key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: id.ServerID}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return fmt.Errorf("create renewal CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	if err := enc.Encode(proto.Envelope{Type: proto.MsgRenewRequest, RenewRequest: &proto.RenewRequest{CSRPEM: string(csrPEM)}}); err != nil {
		return fmt.Errorf("send renewal request: %w", err)
	}

	var resp proto.RenewResponse
	select {
	case resp = <-renewCh:
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timed out waiting for renewal response")
	}
	if resp.Error != "" {
		return fmt.Errorf("control plane declined renewal: %s", resp.Error)
	}
	if resp.CertPEM == "" {
		return fmt.Errorf("control plane returned an empty certificate")
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal renewal key: %w", err)
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

// writeFileAtomic writes to a temp file in the same directory and renames it
// over the destination, so a crash mid-write never leaves a torn identity
// file on disk — a process restart always sees either the old, still-valid
// certificate or the complete new one, never a corrupt partial write.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
