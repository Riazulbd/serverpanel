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
		"Email": "ops@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "ops@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-9"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/crons", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list crons for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/crons",
		map[string]any{"schedule": "* * * * *", "command": "id"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create cron for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "DELETE", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/crons/cron_nonexistent", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete cron for nonexistent site: status = %d, want 404", rec.Code)
	}
}

// TestCreateCronRejectsMissingFields exercises the request-body validation
// in handleCreateCron, which runs (and can reject the request) before any
// agent dispatch is attempted — so it doesn't need a connected agent to
// verify, unlike a successful create.
func TestCreateCronRejectsMissingFields(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "ops2@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "ops2@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-10"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	site, err := a.store.createSite(created.ServerID, "example.com", "site_example_com", "/home/sites/site_example_com/public", "php", "8.3")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/crons",
		map[string]any{"command": "id"}, cookie) // missing schedule
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create cron missing schedule: status = %d, want 400", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/crons",
		map[string]any{"schedule": "* * * * *"}, cookie) // missing command
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create cron missing command: status = %d, want 400", rec.Code)
	}

	// A valid request against a site with no connected agent fails at
	// dispatch (502), not at validation — this confirms the site-lookup +
	// body-validation path (the part this test targets) got past both
	// checks and reached the point of actually trying to reach the agent.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/crons",
		map[string]any{"schedule": "* * * * *", "command": "id"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create cron with no connected agent: status = %d, want 502", rec.Code)
	}
}
