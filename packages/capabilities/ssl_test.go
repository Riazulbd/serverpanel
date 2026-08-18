package capabilities

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCert generates a throwaway self-signed certificate for domain,
// expiring in ttl from now, and writes it to path (creating parent dirs).
func writeTestCert(t *testing.T, path, domain string, ttl time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(ttl),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func withTestSSLDirs(t *testing.T) (leDir, customDir string) {
	t.Helper()
	leDir = t.TempDir()
	customDir = t.TempDir()
	origLE, origCustom := letsEncryptLiveDir, customSSLDir
	letsEncryptLiveDir, customSSLDir = leDir, customDir
	t.Cleanup(func() { letsEncryptLiveDir, customSSLDir = origLE, origCustom })
	return leDir, customDir
}

func TestScanManagedCerts_ExpiringAndExpired(t *testing.T) {
	leDir, customDir := withTestSSLDirs(t)

	writeTestCert(t, filepath.Join(leDir, "soon-to-expire.example", "cert.pem"), "soon-to-expire.example", 5*24*time.Hour)
	writeTestCert(t, filepath.Join(leDir, "already-expired.example", "cert.pem"), "already-expired.example", -24*time.Hour)
	writeTestCert(t, filepath.Join(customDir, "custom.example", "fullchain.pem"), "custom.example", 90*24*time.Hour)

	statuses, err := scanManagedCerts()
	if err != nil {
		t.Fatalf("scanManagedCerts: %v", err)
	}
	if len(statuses) != 3 {
		t.Fatalf("expected 3 certs, got %d: %+v", len(statuses), statuses)
	}

	byDomain := map[string]certStatus{}
	for _, c := range statuses {
		byDomain[c.Domain] = c
	}

	soon, ok := byDomain["soon-to-expire.example"]
	if !ok {
		t.Fatal("missing soon-to-expire.example")
	}
	if soon.Issuer != "letsencrypt" {
		t.Errorf("issuer = %q, want letsencrypt", soon.Issuer)
	}
	if soon.Expired {
		t.Error("soon-to-expire.example should not be reported expired")
	}
	if soon.DaysRemaining < 0 || soon.DaysRemaining > 5 {
		t.Errorf("days_remaining = %d, want 0-5", soon.DaysRemaining)
	}

	expired, ok := byDomain["already-expired.example"]
	if !ok {
		t.Fatal("missing already-expired.example")
	}
	if !expired.Expired {
		t.Error("already-expired.example should be reported expired")
	}
	if expired.DaysRemaining >= 0 {
		t.Errorf("days_remaining = %d, want negative", expired.DaysRemaining)
	}

	custom, ok := byDomain["custom.example"]
	if !ok {
		t.Fatal("missing custom.example")
	}
	if custom.Issuer != "custom" {
		t.Errorf("issuer = %q, want custom", custom.Issuer)
	}
}

func TestHandleSSLStatus_DomainFilter(t *testing.T) {
	leDir, _ := withTestSSLDirs(t)
	writeTestCert(t, filepath.Join(leDir, "a.example", "cert.pem"), "a.example", 30*24*time.Hour)
	writeTestCert(t, filepath.Join(leDir, "b.example", "cert.pem"), "b.example", 30*24*time.Hour)

	detail, err := handleSSLStatus(nil, map[string]any{"domain": "a.example"}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var statuses []certStatus
	if err := json.Unmarshal([]byte(detail), &statuses); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(statuses) != 1 || statuses[0].Domain != "a.example" {
		t.Fatalf("expected only a.example, got %+v", statuses)
	}
}

func TestHandleSSLStatus_NoCertsReturnsEmptyList(t *testing.T) {
	withTestSSLDirs(t)

	detail, err := handleSSLStatus(nil, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("handleSSLStatus: %v", err)
	}
	var statuses []certStatus
	if err := json.Unmarshal([]byte(detail), &statuses); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("expected empty list, got %+v", statuses)
	}
}
