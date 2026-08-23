package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// identity is the durable, on-disk machine identity issued by the control
// plane during registration: a client certificate + private key plus the
// pinned CA used to verify the gateway's own certificate. Files are written
// 0600, root-owned (the agent runs as root via systemd).
//
// CertPEM/KeyPEM are mutated in place after a successful renewal (see
// connect.go's runConnection), while renewalLoop concurrently reads them
// every tick to decide whether a renewal is due — certMu is what makes
// that concurrent read/write safe instead of a data race. Every access from
// more than one goroutine's worth of code must go through currentCert/
// setCert, never the fields directly; the single-goroutine reads at
// runConnection's very start (before any goroutine is spawned) are the only
// exception.
type identity struct {
	ServerID    string
	CertPEM     []byte
	KeyPEM      []byte
	CAPEM       []byte
	GatewayAddr string
	DataDir     string

	certMu sync.Mutex
}

// currentCert returns the identity's current certificate and key under
// lock.
func (id *identity) currentCert() (certPEM, keyPEM []byte) {
	id.certMu.Lock()
	defer id.certMu.Unlock()
	return id.CertPEM, id.KeyPEM
}

// setCert atomically replaces the identity's in-memory certificate and key,
// used once a renewal response has been persisted to disk.
func (id *identity) setCert(certPEM, keyPEM []byte) {
	id.certMu.Lock()
	defer id.certMu.Unlock()
	id.CertPEM = certPEM
	id.KeyPEM = keyPEM
}

func identityPaths(dataDir string) (cert, key, ca, meta string) {
	return filepath.Join(dataDir, "agent-cert.pem"),
		filepath.Join(dataDir, "agent-key.pem"),
		filepath.Join(dataDir, "ca.pem"),
		filepath.Join(dataDir, "identity.json")
}

func loadIdentity(dataDir string) (*identity, error) {
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var meta struct {
		ServerID    string `json:"server_id"`
		GatewayAddr string `json:"gateway_addr"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	return &identity{ServerID: meta.ServerID, CertPEM: certPEM, KeyPEM: keyPEM, CAPEM: caPEM, GatewayAddr: meta.GatewayAddr, DataDir: dataDir}, nil
}

// generateKeyAndCSR creates a fresh ECDSA keypair and a CSR requesting a
// client certificate for it. Used both for first-time registration and for
// every renewal (see connect.go renewalLoop) — renewal deliberately
// generates a brand new key rather than reusing the old one, so routine
// rotation also rotates key material, not just the certificate wrapping it.
// The CSR's requested Subject is ignored by the CA (packages/ca.go
// signAgentCSR sets CommonName from the server's already-authenticated
// identity, never from the CSR), so what's requested here is immaterial to
// what gets issued.
func generateKeyAndCSR() (csrPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-registration"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM, nil
}

// persistRenewedCert atomically replaces the on-disk certificate and
// private key with a renewed identity (write-to-temp-file-then-rename, so
// a crash or power loss mid-write can never leave a truncated/corrupt cert
// or key on disk — the previous, still-valid pair stays intact until the
// new one is fully and atomically in place).
func (id *identity) persistRenewedCert(certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(id.DataDir)
	if err := writeFileAtomic(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed certificate: %w", err)
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed key: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// register performs the one-time bootstrap-token-for-certificate exchange
// against the control plane's public API (plain server-TLS; the agent has
// no client cert yet — that's the whole point of this call). The bootstrap
// token is read once from the caller-supplied value and is never written to
// disk or logged; only the resulting certificate and identifiers persist.
func register(apiAddr, token, dataDir string) (*identity, error) {
	csrPEM, keyPEM, err := generateKeyAndCSR()
	if err != nil {
		return nil, err
	}

	reqBody, _ := json.Marshal(map[string]string{"token": token, "csr_pem": string(csrPEM)})
	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Post(apiAddr+"/agents/register", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("registration request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration rejected (%d): %s", resp.StatusCode, body)
	}

	var rr struct {
		ServerID    string `json:"server_id"`
		CertPEM     string `json:"cert_pem"`
		CAPEM       string `json:"ca_pem"`
		GatewayAddr string `json:"gateway_addr"`
	}
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("parse registration response: %w", err)
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	certPath, keyPath, caPath, metaPath := identityPaths(dataDir)
	if err := os.WriteFile(certPath, []byte(rr.CertPEM), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(caPath, []byte(rr.CAPEM), 0600); err != nil {
		return nil, err
	}
	metaBytes, _ := json.Marshal(map[string]string{"server_id": rr.ServerID, "gateway_addr": rr.GatewayAddr})
	if err := os.WriteFile(metaPath, metaBytes, 0600); err != nil {
		return nil, err
	}

	return &identity{ServerID: rr.ServerID, CertPEM: []byte(rr.CertPEM), KeyPEM: keyPEM, CAPEM: []byte(rr.CAPEM), GatewayAddr: rr.GatewayAddr, DataDir: dataDir}, nil
}
