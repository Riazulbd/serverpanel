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
	"time"
)

// identity is the durable, on-disk machine identity issued by the control
// plane during registration: a client certificate + private key plus the
// pinned CA used to verify the gateway's own certificate. Files are written
// 0600, root-owned (the agent runs as root via systemd).
type identity struct {
	ServerID    string
	CertPEM     []byte
	KeyPEM      []byte
	CAPEM       []byte
	GatewayAddr string
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
	key, csrPEM, err := newCSR()
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

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

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

// certNotAfter returns the NotAfter time of a single PEM-encoded
// certificate, used by the renewal loop (connect.go) to decide when a
// currently-valid identity is close enough to expiry to renew.
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

// newCSR generates a fresh ECDSA keypair and a CSR for it, used both by
// register (bootstrap) and by the renewal loop. Generating a new key on
// every renewal (rather than reusing the old one indefinitely) bounds how
// long any single private key needs to stay secret.
func newCSR() (key *ecdsa.PrivateKey, csrPEM []byte, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	// CommonName here is never trusted by the CA (see ca.go signAgentCSR):
	// it always sets CommonName from the server_id it already knows, either
	// from the redeemed bootstrap token (registration) or the TLS session
	// that carried this request (renewal). This value is a placeholder.
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "unbound-csr"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// persistRenewedIdentity durably replaces the on-disk cert+key with a newly
// renewed pair. It writes to temp files in dataDir first and renames them
// into place (atomic on the same filesystem) so a crash mid-write can never
// leave a half-written, unusable cert or key on disk — the agent would
// otherwise be permanently locked out with no bootstrap token to recover.
func persistRenewedIdentity(dataDir string, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)

	tmpCert := certPath + ".tmp"
	if err := os.WriteFile(tmpCert, certPEM, 0600); err != nil {
		return fmt.Errorf("write temp cert: %w", err)
	}
	tmpKey := keyPath + ".tmp"
	if err := os.WriteFile(tmpKey, keyPEM, 0600); err != nil {
		os.Remove(tmpCert)
		return fmt.Errorf("write temp key: %w", err)
	}
	// Key first: if we crash between renames, the worst case is a
	// mismatched cert/key pair that fails to load, not a truncated file.
	if err := os.Rename(tmpKey, keyPath); err != nil {
		os.Remove(tmpCert)
		os.Remove(tmpKey)
		return fmt.Errorf("rename key into place: %w", err)
	}
	if err := os.Rename(tmpCert, certPath); err != nil {
		return fmt.Errorf("rename cert into place: %w", err)
	}
	return nil
}
