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

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/ssl/letsencrypt",
		map[string]any{"email": "admin@example.com"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("issue letsencrypt for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/ssl/custom",
		map[string]any{"cert_pem": "x", "key_pem": "y"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("install custom ssl for nonexistent site: status = %d, want 404", rec.Code)
	}
}

func TestSSLEndpointsValidateInput(t *testing.T) {
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

	site, err := a.store.createSite(created.ServerID, "ssl.example.com", "sp_ssl", "/home/sites/sp_ssl", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}
	if site.SSLStatus != "none" {
		t.Fatalf("new site SSLStatus = %q, want %q", site.SSLStatus, "none")
	}

	// Missing email is rejected before any dispatch is attempted.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/ssl/letsencrypt",
		map[string]any{}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("issue letsencrypt with no email: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Missing cert/key is rejected before any dispatch is attempted.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/ssl/custom",
		map[string]any{"cert_pem": ""}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("install custom ssl with no cert/key: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed request against a site whose server has no connected
	// agent fails as a gateway/dispatch error, not a validation error —
	// proving validation happens before dispatch, same as backups.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/ssl/letsencrypt",
		map[string]any{"email": "admin@example.com"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("issue letsencrypt with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateSiteSSLPersistsStatusAndExpiry(t *testing.T) {
	st := newTestStore(t)
	serverID, _, err := st.createServer("web-store", "", nil, 15*time.Minute, "test-actor")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	site, err := st.createSite(serverID, "store.example.com", "sp_store", "/home/sites/sp_store", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	if err := st.updateSiteSSL(serverID, site.ID, "active", "2030-01-01T00:00:00Z", ""); err != nil {
		t.Fatalf("updateSiteSSL: %v", err)
	}
	got, ok := st.getSite(serverID, site.ID)
	if !ok {
		t.Fatal("getSite: not found after updateSiteSSL")
	}
	if got.SSLStatus != "active" || got.SSLExpiresAt != "2030-01-01T00:00:00Z" || got.SSLError != "" {
		t.Fatalf("got SSLStatus=%q SSLExpiresAt=%q SSLError=%q after active update", got.SSLStatus, got.SSLExpiresAt, got.SSLError)
	}

	// An error update must not blank out a previously recorded expiry —
	// a failed renewal attempt shouldn't make the dashboard forget the
	// still-valid certificate's expiry date.
	if err := st.updateSiteSSL(serverID, site.ID, "error", "", "certbot: rate limited"); err != nil {
		t.Fatalf("updateSiteSSL (error): %v", err)
	}
	got, _ = st.getSite(serverID, site.ID)
	if got.SSLStatus != "error" || got.SSLExpiresAt != "2030-01-01T00:00:00Z" || got.SSLError != "certbot: rate limited" {
		t.Fatalf("got SSLStatus=%q SSLExpiresAt=%q SSLError=%q after error update, want expiry preserved", got.SSLStatus, got.SSLExpiresAt, got.SSLError)
	}

	sites := st.sitesWithActiveSSL()
	for _, s := range sites {
		if s.ID == site.ID {
			t.Fatalf("sitesWithActiveSSL still includes a site whose status was just set to error")
		}
	}
}
