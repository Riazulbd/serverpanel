package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestCronEndpointsRequireARealSite(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "cron-ops@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "cron-ops@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-cron-1"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list cron jobs for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron",
		map[string]any{"schedule": "@daily", "command": "true"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create cron job for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/cron/cron_nonexistent/enabled",
		map[string]any{"enabled": false}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("enable/disable nonexistent cron job: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "DELETE", "/api/v1/servers/"+created.ServerID+"/cron/cron_nonexistent", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent cron job: status = %d, want 404", rec.Code)
	}
}

func TestCreateCronJobRejectsMissingFieldsAndRequiresDispatch(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "cron-ops2@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "cron-ops2@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-cron-2"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	site, err := a.store.createSite(created.ServerID, "cron.example.com", "site_cron", "/home/sites/site_cron", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/cron",
		map[string]any{"schedule": "@daily"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create cron job without command: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A valid, well-formed request against a site whose server has no
	// connected agent should fail as a gateway/dispatch error, not a
	// validation error — proving validation happens before dispatch, the
	// same property TestCreateBackupRejectsInvalidScope checks for backups.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/cron",
		map[string]any{"schedule": "@daily", "command": "true"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create cron job with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
