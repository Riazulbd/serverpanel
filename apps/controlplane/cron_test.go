package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func loginNewUser(t *testing.T, h http.Handler, email string) *http.Cookie {
	t.Helper()
	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": email, "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": email, "Password": "correcthorsebattery",
	}, nil)
	return sessionCookie(rec)
}

func TestCronEndpointsRequireARealSite(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()
	cookie := loginNewUser(t, h, "cronops@example.com")

	rec := doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-cron"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list cron jobs for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron",
		map[string]any{"schedule": "* * * * *", "command": "echo hi"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create cron job for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "DELETE", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/cron/cron_nope", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete cron job for nonexistent site: status = %d, want 404", rec.Code)
	}
}

func TestCreateCronJobRejectsInvalidScheduleAndCommand(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()
	cookie := loginNewUser(t, h, "cronops2@example.com")

	rec := doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-cron-2"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	site, err := a.store.createSite(created.ServerID, "cron2.example.com", "site_cron2", "/home/sites/site_cron2", "php", "8.3")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}
	base := "/api/v1/servers/" + created.ServerID + "/sites/" + site.ID + "/cron"

	rec = doJSON(t, h, "POST", base, map[string]any{"schedule": "not a schedule", "command": "echo hi"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with invalid schedule: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", base, map[string]any{"schedule": "* * * * *", "command": ""}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with empty command: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed request against a site with no connected agent should
	// fail as a gateway/dispatch error, not a validation error — proving
	// validation happens before dispatch (same property TestCreateBackupRejectsInvalidScope
	// establishes for backups).
	rec = doJSON(t, h, "POST", base, map[string]any{"schedule": "@daily", "command": "wp cron event run --due-now"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	if jobs := a.store.listCronJobs(created.ServerID, site.ID); len(jobs) != 0 {
		t.Fatalf("a failed dispatch must not persist a cron job, found %d", len(jobs))
	}
}

func TestUpdateAndDeleteCronJobRequireExistingJob(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()
	cookie := loginNewUser(t, h, "cronops3@example.com")

	rec := doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-cron-3"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	site, err := a.store.createSite(created.ServerID, "cron3.example.com", "site_cron3", "/home/sites/site_cron3", "php", "8.3")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}
	base := "/api/v1/servers/" + created.ServerID + "/sites/" + site.ID + "/cron"

	rec = doJSON(t, h, "PATCH", base+"/cron_nonexistent", map[string]any{"enabled": false}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update nonexistent cron job: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "DELETE", base+"/cron_nonexistent", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent cron job: status = %d, want 404", rec.Code)
	}
}
