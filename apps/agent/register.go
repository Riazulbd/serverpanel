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
	key, csrPEM, err := newKeyAndCSR()
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

// newKeyAndCSR generates a fresh ECDSA keypair and a certificate signing
// request for it. The CSR's requested Subject is never trusted by the
// control plane (see proto.RenewRequest) — for a renewal the signed
// identity comes entirely from the already-authenticated connection it's
// sent over — so any placeholder subject here is fine.
func newKeyAndCSR() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-registration"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// certExpiry returns the NotAfter time of a PEM-encoded certificate, used
// by the renewal loop to decide when the current identity is close enough
// to expiry to renew.
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

// atomicWriteFile writes data to path via a temp file + rename, so a crash
// or power loss mid-write can never leave behind a truncated identity file
// the agent would fail (or worse, silently misbehave) trying to load on
// its next start.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// pendingRenewal holds a freshly generated key while a renewal request is
// in flight with the gateway. Nothing is persisted to disk until the
// gateway's signed certificate comes back and finish is called, so a
// renewal that never completes (connection drops mid-exchange, gateway
// refuses it) leaves the existing, still-valid identity on disk untouched.
type pendingRenewal struct {
	key *ecdsa.PrivateKey
}

// startRenewal generates the keypair/CSR for a renewal attempt.
func startRenewal() (*pendingRenewal, []byte, error) {
	key, csrPEM, err := newKeyAndCSR()
	if err != nil {
		return nil, nil, err
	}
	return &pendingRenewal{key: key}, csrPEM, nil
}

// finish persists the gateway-signed certificate paired with this
// renewal's private key, and updates id in place so the caller's next
// reconnect attempt picks up the new identity automatically.
func (p *pendingRenewal) finish(dataDir string, id *identity, certPEM string) error {
	keyDER, err := x509.MarshalECPrivateKey(p.key)
	if err != nil {
		return fmt.Errorf("marshal renewed key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certPath, keyPath, _, _ := identityPaths(dataDir)
	if err := atomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("persist renewed key: %w", err)
	}
	if err := atomicWriteFile(certPath, []byte(certPEM), 0600); err != nil {
		return fmt.Errorf("persist renewed cert: %w", err)
	}

	id.CertPEM = []byte(certPEM)
	id.KeyPEM = keyPEM
	return nil
}
