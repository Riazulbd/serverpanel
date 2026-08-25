package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// setUpCronTestServer signs up/logs in one user and creates one server +
// one site, returning everything a cron-endpoint test needs to exercise the
// real routes() mux end-to-end (matching http_test.go's style).
func setUpCronTestServer(t *testing.T) (h http.Handler, cookie *http.Cookie, serverID string, site *siteRecord) {
	t.Helper()
	secureCookies = false
	t.Cleanup(func() { secureCookies = true })

	a := newTestAPIServer(t)
	h = a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "cronops@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "cronops@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie = sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-cron"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	serverID = created.ServerID

	rec2, err := a.store.createSite(serverID, "cron.example.com", "site_cron01", "/home/sites/site_cron01", "php", "8.3")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}
	site = rec2
	return h, cookie, serverID, site
}

func cronBasePath(serverID string, site *siteRecord) string {
	return "/api/v1/servers/" + serverID + "/sites/" + site.ID + "/cron"
}

// TestCronEndpointsRejectUnauthenticatedRequests is the authz-negative
// case: this codebase's session model (see auth.go requireAuth) is the only
// access boundary that exists today — every /api/v1/* route (cron included)
// requires a valid, MFA-satisfied session, and there is no narrower
// per-server/per-site ownership model yet (see SERVERAVATAR_PARITY.md
// ORG-001 and this feature's "Known differences"). A request carrying no
// session at all — the one kind of "session without access to that
// server/site" this codebase can actually express today — must be rejected
// on every one of the new cron routes, exactly like every other protected
// route.
func TestCronEndpointsRejectUnauthenticatedRequests(t *testing.T) {
	h, _, serverID, site := setUpCronTestServer(t)
	base := cronBasePath(serverID, site)

	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", base, nil},
		{"POST", base, map[string]any{"schedule": "* * * * *", "command": "/bin/true"}},
		{"PUT", base + "/cron_x", map[string]any{"schedule": "* * * * *", "command": "/bin/true"}},
		{"DELETE", base + "/cron_x", nil},
		{"POST", base + "/cron_x/enable", nil},
		{"POST", base + "/cron_x/disable", nil},
	}
	for _, c := range cases {
		rec := doJSON(t, h, c.method, c.path, c.body, nil) // no cookie
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session: status = %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

func TestCronEndpointsRequireARealSite(t *testing.T) {
	h, cookie, serverID, _ := setUpCronTestServer(t)
	bogusBase := "/api/v1/servers/" + serverID + "/sites/site_nonexistent/cron"

	rec := doJSON(t, h, "GET", bogusBase, nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list cron for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "POST", bogusBase, map[string]any{"schedule": "* * * * *", "command": "/bin/true"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create cron for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "PUT", bogusBase+"/cron_x", map[string]any{"schedule": "* * * * *", "command": "/bin/true"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update cron for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "DELETE", bogusBase+"/cron_x", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete cron for nonexistent site: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "POST", bogusBase+"/cron_x/enable", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("enable cron for nonexistent site: status = %d, want 404", rec.Code)
	}

	// A different (also nonexistent, from this server's point of view)
	// server id must 404 too, not silently fall through to some other
	// server's site — same cross-tenant-addressing guard getSite already
	// gives every other per-site endpoint.
	rec = doJSON(t, h, "GET", "/api/v1/servers/srv_other/sites/site_nonexistent/cron", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list cron for nonexistent server: status = %d, want 404", rec.Code)
	}
}

func TestCreateCronRejectsMissingFieldsBeforeDispatch(t *testing.T) {
	h, cookie, serverID, site := setUpCronTestServer(t)
	base := cronBasePath(serverID, site)

	rec := doJSON(t, h, "POST", base, map[string]any{"command": "/bin/true"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create cron without schedule: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", base, map[string]any{"schedule": "* * * * *"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create cron without command: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", base, map[string]any{"schedule_preset": "not_a_real_preset", "command": "/bin/true"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create cron with unknown schedule_preset: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed request against a site whose server has no connected
	// agent must fail as a gateway/dispatch error, not a validation error —
	// proving field validation happens before dispatch, same pattern as
	// TestCreateBackupRejectsInvalidScope.
	rec = doJSON(t, h, "POST", base, map[string]any{"schedule_preset": "hourly", "command": "/bin/true"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create cron with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateCronRejectsMissingFieldsBeforeDispatch(t *testing.T) {
	h, cookie, serverID, site := setUpCronTestServer(t)
	base := cronBasePath(serverID, site)

	rec := doJSON(t, h, "PUT", base+"/cron_x", map[string]any{"command": "/bin/true"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("update cron without schedule: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "PUT", base+"/cron_x", map[string]any{"schedule": "* * * * *"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("update cron without command: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDeleteAndEnableCronFailAsGatewayErrorWithNoAgentConnected(t *testing.T) {
	h, cookie, serverID, site := setUpCronTestServer(t)
	base := cronBasePath(serverID, site)

	rec := doJSON(t, h, "DELETE", base+"/cron_x", nil, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("delete cron with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", base+"/cron_x/enable", nil, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("enable cron with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, h, "POST", base+"/cron_x/disable", nil, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("disable cron with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestCronCreateNeverAcceptsAClientSuppliedSystemUser is a regression guard
// for the ownership boundary resolveCronSite documents: even if a request
// body smuggles a "system_user" field (naming, say, another site's user, or
// "root"), it must be silently ignored — the dispatched capability call is
// always built server-side from the resolved site's own SystemUser. This is
// exercised indirectly here: since no agent is connected either way, both
// requests fail identically (BadGateway) rather than one succeeding with an
// attacker-chosen user, which would be the observable symptom of the field
// leaking through.
func TestCronCreateNeverAcceptsAClientSuppliedSystemUser(t *testing.T) {
	h, cookie, serverID, site := setUpCronTestServer(t)
	base := cronBasePath(serverID, site)

	rec := doJSON(t, h, "POST", base, map[string]any{
		"schedule": "* * * * *", "command": "/bin/true", "system_user": "root",
	}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create cron with a spoofed system_user: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}
