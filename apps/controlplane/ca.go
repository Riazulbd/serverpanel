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
