package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestSSLEndpointsRequireARealSite(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "ssl-ops@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "ssl-ops@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-ssl"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/ssl", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get ssl status for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/ssl/letsencrypt", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("issue LE ssl for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/ssl/custom",
		map[string]any{"cert_pem": "x", "key_pem": "y"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("install custom ssl for nonexistent site: status = %d, want 404", rec.Code)
	}
}

func TestInstallCustomSSLRejectsMissingParams(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "ssl-ops2@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "ssl-ops2@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-ssl2"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	site, err := a.store.createSite(created.ServerID, "d.example.com", "sp_d", "/home/sites/sp_d", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/ssl/custom",
		map[string]any{"cert_pem": ""}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("install custom ssl with missing key_pem: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed request against a site whose server has no connected
	// agent should fail as a gateway/dispatch error, not a validation
	// error — proving parameter validation happens before dispatch, the
	// same property the backup endpoint tests establish.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/ssl/letsencrypt", nil, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("issue LE ssl with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestUpsertSSLCertificateReplacesExistingRow(t *testing.T) {
	a := newTestAPIServer(t)

	serverID, _, err := a.store.createServer("srv-ssl", "", nil, time.Hour, "actor@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	site, err := a.store.createSite(serverID, "e.example.com", "sp_e", "/home/sites/sp_e", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	firstExpiry := time.Now().Add(60 * 24 * time.Hour).UTC()
	first, err := a.store.upsertSSLCertificate(serverID, site.ID, "e.example.com", "letsencrypt", firstExpiry)
	if err != nil {
		t.Fatalf("upsertSSLCertificate (first): %v", err)
	}

	secondExpiry := time.Now().Add(90 * 24 * time.Hour).UTC()
	second, err := a.store.upsertSSLCertificate(serverID, site.ID, "e.example.com", "custom", secondExpiry)
	if err != nil {
		t.Fatalf("upsertSSLCertificate (second): %v", err)
	}

	if second.ID != first.ID {
		t.Fatalf("expected the second upsert to reuse the same row id; got %q vs %q", second.ID, first.ID)
	}
	if second.Issuer != "custom" {
		t.Fatalf("issuer after re-upsert = %q, want custom", second.Issuer)
	}

	certs := a.store.listSSLCertificates(serverID, site.ID)
	if len(certs) != 1 {
		t.Fatalf("expected exactly 1 ssl_certificates row after re-upsert, got %d", len(certs))
	}
	if certs[0].ExpiresAt.Unix() != secondExpiry.Unix() {
		t.Fatalf("expires_at after re-upsert = %v, want %v", certs[0].ExpiresAt, secondExpiry)
	}
}
