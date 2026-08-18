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
// ServerID, CAPEM and GatewayAddr never change after registration and are
// safe to read directly. CertPEM/KeyPEM can be replaced in place by the
// certificate-renewal flow (renew.go) while a connection using the old pair
// is still active, so all access to those two fields goes through
// snapshot/update rather than direct field access.
type identity struct {
	mu sync.Mutex

	ServerID    string
	CertPEM     []byte
	KeyPEM      []byte
	CAPEM       []byte
	GatewayAddr string
}

// snapshot returns a defensive copy of the current cert/key pair, safe to
// use for a fresh connection attempt even if a renewal is concurrently in
// progress.
func (id *identity) snapshot() (certPEM, keyPEM []byte) {
	id.mu.Lock()
	defer id.mu.Unlock()
	return append([]byte(nil), id.CertPEM...), append([]byte(nil), id.KeyPEM...)
}

// update replaces the in-memory cert/key pair after a successful renewal.
// It does not touch disk — the caller persists first, then calls update
// only once the new pair is durable (see renew.go persistRenewedIdentity).
func (id *identity) update(certPEM, keyPEM []byte) {
	id.mu.Lock()
	id.CertPEM = certPEM
	id.KeyPEM = keyPEM
	id.mu.Unlock()
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
	return &identity{ServerID: meta.ServerID, CertPEM: certPEM, KeyPEM: keyPEM, CAPEM: caPEM, GatewayAddr: meta.GatewayAddr}, nil
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

	return &identity{ServerID: rr.ServerID, CertPEM: []byte(rr.CertPEM), KeyPEM: keyPEM, CAPEM: []byte(rr.CAPEM), GatewayAddr: rr.GatewayAddr}, nil
}

// generateKeyAndCSR creates a fresh ECDSA P-256 keypair and a CSR for it.
// The CSR's subject is a placeholder — every issuer in this system (the
// one-time /agents/register bootstrap and the in-session renewal flow in
// renew.go) ignores the CSR's requested subject and binds the certificate's
// CommonName to the server_id it already trusts from another source, so
// nothing here is ever treated as an identity claim.
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

// atomicWriteFile writes data to path via a temp file + rename in the same
// directory, so a concurrent reader (or a crash mid-write) never observes a
// partially written identity file — important here because the renewal
// flow (renew.go) replaces the agent's live certificate/key files while the
// agent process keeps running.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
