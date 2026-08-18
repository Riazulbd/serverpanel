package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// agentCA is a minimal internal certificate authority used to issue
// short-lived client certificates to registered agents, and a server
// certificate for the gateway's own TLS listener. In production this
// signing key belongs in a dedicated, tightly access-controlled service
// (e.g. step-ca or an HSM-backed KMS) separate from the general
// application tier — see docs/security-trust-model.md §2. This in-process
// implementation is a functional skeleton for Phase 1 development, not the
// production CA deployment.
// AgentCertTTL is the validity period issued to an agent client certificate,
// both at first registration (http.go handleRegister) and on every
// subsequent renewal (gateway.go handleRenew). Kept short deliberately (see
// signAgentCSR's doc comment) so a leaked certificate has a bounded blast
// radius; the agent renews well before this expires (see
// apps/agent/renew.go's renewalWindow).
const AgentCertTTL = 30 * 24 * time.Hour

type agentCA struct {
	mu       sync.Mutex
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootPEM  []byte
	nextSN   int64
}

func newAgentCA() (*agentCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ServerPanel Internal Agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return &agentCA{rootCert: cert, rootKey: key, rootPEM: pemBytes, nextSN: 100}, nil
}

// loadOrCreateAgentCA persists the CA's signing key to disk (certPath,
// keyPath) and reuses it across restarts. Without this, every control-plane
// restart would mint a brand new CA — silently invalidating every already
// -registered agent's certificate, since none of them would chain to the
// new root anymore. That defeats the entire point of a durable,
// certificate-based machine identity (docs/security-trust-model.md §2): a
// restart is not a revocation event, and must not behave like one.
//
// startSerial seeds the serial-number counter above the highest serial
// this control plane has ever issued (tracked via the servers/revoked_certs
// tables, see store.maxKnownCertSerial) — required because reusing a
// serial number that's already meaningful in the revocation list would be
// a real ambiguity, not just a cosmetic issue.
func loadOrCreateAgentCA(certPath, keyPath string, startSerial int64) (*agentCA, error) {
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		ca, err := parseAgentCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse existing CA at %s / %s: %w", certPath, keyPath, err)
		}
		if startSerial > ca.nextSN {
			ca.nextSN = startSerial
		}
		return ca, nil
	}

	ca, err := newAgentCA()
	if err != nil {
		return nil, err
	}
	if startSerial > ca.nextSN {
		ca.nextSN = startSerial
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.rootKey)
	if err != nil {
		return nil, err
	}
	rootKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, rootKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("persist CA key: %w", err)
	}
	if err := os.WriteFile(certPath, ca.rootPEM, 0644); err != nil {
		return nil, fmt.Errorf("persist CA certificate: %w", err)
	}
	return ca, nil
}

func parseAgentCA(certPEM, keyPEM []byte) (*agentCA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &agentCA{rootCert: cert, rootKey: key, rootPEM: certPEM, nextSN: 100}, nil
}

// CAPEM returns the PEM-encoded root certificate agents should pin.
func (ca *agentCA) CAPEM() []byte {
	return ca.rootPEM
}

// signServerCert issues the gateway's own TLS server certificate, valid for
// the given DNS names and/or literal IP addresses (each host is classified
// automatically so dialing the gateway by bare IP, common for a freshly
// registered agent before any DNS exists, verifies correctly).
func (ca *agentCA) signServerCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ca.mu.Lock()
	sn := ca.nextSN
	ca.nextSN++
	ca.mu.Unlock()

	var dnsNames []string
	var ipAddrs []net.IP
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(sn),
		Subject:      pkix.Name{CommonName: "serverpanel-gateway"},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.rootCert, &key.PublicKey, ca.rootKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// signAgentCSR validates and signs an agent's certificate signing request,
// binding the issued certificate's CommonName to serverID so the gateway
// can trust the identity embedded in the certificate itself during mTLS,
// without a second lookup. TTL is intentionally short (see
// docs/security-trust-model.md §2) so a leaked cert has a bounded blast
// radius and rotation is routine rather than exceptional.
func (ca *agentCA) signAgentCSR(csrPEM []byte, serverID string, ttl time.Duration) (certPEM []byte, serial *big.Int, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR signature invalid: %w", err)
	}

	ca.mu.Lock()
	sn := big.NewInt(ca.nextSN)
	ca.nextSN++
	ca.mu.Unlock()

	tmpl := &x509.Certificate{
		SerialNumber: sn,
		// CommonName is set by the CA from the validated server_id, not
		// taken from the CSR's requested subject, so an agent cannot claim
		// a different server's identity by crafting its CSR.
		Subject:     pkix.Name{CommonName: serverID},
		NotBefore:   time.Now().Add(-5 * time.Minute),
		NotAfter:    time.Now().Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.rootCert, csr.PublicKey, ca.rootKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), sn, nil
}

// certPool returns an x509.CertPool containing just the root, for verifying
// peer certificates during mTLS.
func (ca *agentCA) certPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)
	return pool
}
