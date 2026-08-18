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

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-cron"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list cron for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron",
		map[string]any{"schedule": "* * * * *", "command": "true"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create cron for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "DELETE", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron/cron_x", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete cron for nonexistent site: status = %d, want 404", rec.Code)
	}
}

func TestCreateCronRejectsMissingFieldsAndRequiresAgent(t *testing.T) {
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

	site, err := a.store.createSite(created.ServerID, "cron.example.com", "site_cron_example_com", "/home/sites/site_cron_example_com", "php", "8.3")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/cron",
		map[string]any{"schedule": "* * * * *"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create cron without command: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed request against a site whose server has no connected
	// agent should fail as a gateway error, not a validation error — proving
	// validation happens before dispatch, matching TestCreateBackupRejectsInvalidScope.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/cron",
		map[string]any{"schedule": "*/5 * * * *", "command": "php artisan schedule:run"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create cron with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
