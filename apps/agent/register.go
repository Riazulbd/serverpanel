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
// ServerID, CAPEM, and GatewayAddr never change after construction and are
// safe to read directly. certPEM/keyPEM do change — connect.go's
// renewalLoop replaces them in place after a successful certificate
// renewal, from a goroutine that outlives any single runConnection call —
// so they're guarded by mu and only ever touched through certKeyPEM/
// setCertKeyPEM, never as bare field reads/writes, to avoid a data race
// between a renewal in flight and the next reconnect reading the identity
// to dial with.
type identity struct {
	ServerID    string
	CAPEM       []byte
	GatewayAddr string

	mu      sync.Mutex
	certPEM []byte
	keyPEM  []byte
}

func newIdentity(serverID string, certPEM, keyPEM, caPEM []byte, gatewayAddr string) *identity {
	return &identity{ServerID: serverID, CAPEM: caPEM, GatewayAddr: gatewayAddr, certPEM: certPEM, keyPEM: keyPEM}
}

// certKeyPEM returns the current certificate and private key, safe to call
// concurrently with a renewal that's updating them.
func (id *identity) certKeyPEM() (certPEM, keyPEM []byte) {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.certPEM, id.keyPEM
}

// setCertKeyPEM atomically swaps in a renewed certificate and key.
func (id *identity) setCertKeyPEM(certPEM, keyPEM []byte) {
	id.mu.Lock()
	defer id.mu.Unlock()
	id.certPEM = certPEM
	id.keyPEM = keyPEM
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
	return newIdentity(meta.ServerID, certPEM, keyPEM, caPEM, meta.GatewayAddr), nil
}

// generateKeyAndCSR creates a fresh ECDSA P-256 keypair and a PKCS#10 CSR for
// it. commonName is cosmetic only — the control plane never trusts a CSR's
// requested Subject for identity (see ca.go signAgentCSR and gateway.go
// renewAgentCert); it always binds the issued certificate's CommonName to
// the server ID it has independently validated (via the bootstrap token at
// registration, or via the live mTLS session at renewal).
func generateKeyAndCSR(commonName string) (key *ecdsa.PrivateKey, csrPEM []byte, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return key, csrPEM, nil
}

func marshalECKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// register performs the one-time bootstrap-token-for-certificate exchange
// against the control plane's public API (plain server-TLS; the agent has
// no client cert yet — that's the whole point of this call). The bootstrap
// token is read once from the caller-supplied value and is never written to
// disk or logged; only the resulting certificate and identifiers persist.
func register(apiAddr, token, dataDir string) (*identity, error) {
	key, csrPEM, err := generateKeyAndCSR("pending-registration")
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

	keyPEM, err := marshalECKeyPEM(key)
	if err != nil {
		return nil, err
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

	return newIdentity(rr.ServerID, []byte(rr.CertPEM), keyPEM, []byte(rr.CAPEM), rr.GatewayAddr), nil
}

// parseCertPEM decodes a single PEM-encoded X.509 certificate, used to read
// the current identity's own expiry (see needsRenewal).
func parseCertPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// needsRenewal reports whether cert should be renewed now: true once fewer
// than threshold remains before NotAfter. A pure function of (cert, now,
// threshold) so the renewal decision is unit-testable without a clock or a
// network connection — see connect.go's renewalLoop, the only caller.
func needsRenewal(cert *x509.Certificate, now time.Time, threshold time.Duration) bool {
	return cert.NotAfter.Sub(now) < threshold
}

// generateRenewalCSR builds a fresh keypair + CSR for a certificate-renewal
// request. The private key is returned alongside the CSR (never sent to the
// control plane) so the caller can pair it with whatever certificate comes
// back from the gateway.
func generateRenewalCSR() (keyPEM, csrPEM []byte, err error) {
	key, csrPEM, err := generateKeyAndCSR("pending-renewal")
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = marshalECKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	return keyPEM, csrPEM, nil
}

// atomicWriteFile writes data to path via a temp file + rename in the same
// directory, so a crash mid-write can never leave a half-written identity
// file on disk — a reader either sees the old complete content or the new
// complete content, never a truncated mix.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// persistRenewedIdentity durably writes a renewed certificate + key to disk
// (same paths register() uses, so a restarted agent picks them straight back
// up via loadIdentity) and updates id in place so the *current* process also
// starts using them on its next reconnect, without needing a restart.
func persistRenewedIdentity(dataDir string, id *identity, certPEM, keyPEM []byte) error {
	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed key: %w", err)
	}
	if err := atomicWriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed certificate: %w", err)
	}
	id.setCertKeyPEM(certPEM, keyPEM)
	return nil
}
