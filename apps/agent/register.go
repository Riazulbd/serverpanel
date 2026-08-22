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
	DataDir     string // where CertPEM/KeyPEM are persisted; needed to persist a renewed cert (see renew.go)
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

// register performs the one-time bootstrap-token-for-certificate exchange
// against the control plane's public API (plain server-TLS; the agent has
// no client cert yet — that's the whole point of this call). The bootstrap
// token is read once from the caller-supplied value and is never written to
// disk or logged; only the resulting certificate and identifiers persist.
func register(apiAddr, token, dataDir string) (*identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "pending-registration"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

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

	return &identity{ServerID: rr.ServerID, CertPEM: []byte(rr.CertPEM), KeyPEM: keyPEM, CAPEM: []byte(rr.CAPEM), GatewayAddr: rr.GatewayAddr, DataDir: dataDir}, nil
}
