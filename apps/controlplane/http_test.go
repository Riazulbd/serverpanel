package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func doJSON(t *testing.T, handler http.Handler, method, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func TestSignupLoginProtectedRouteFlow(t *testing.T) {
	secureCookies = false // httptest requests aren't TLS
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	rec := doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "owner@example.com", "Password": "correcthorsebattery",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signup status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Protected route without a session must be rejected.
	rec = doJSON(t, h, "GET", "/api/v1/auth/me", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me status = %d, want 401", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "owner@example.com", "Password": "correcthorsebattery",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookie(rec)
	if cookie == nil {
		t.Fatal("expected login to set a session cookie")
	}

	rec = doJSON(t, h, "GET", "/api/v1/auth/me", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated /me status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Wrong password must be rejected without revealing which factor failed.
	rec = doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "owner@example.com", "Password": "wrongpassword",
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad-password login status = %d, want 401", rec.Code)
	}
}

func TestTOTPEnrollmentGatesSession(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "twofactor@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "twofactor@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/auth/totp/enroll", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("totp enroll status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var enroll struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &enroll); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}

	code, err := totpCodeAt(enroll.Secret, time.Now())
	if err != nil {
		t.Fatalf("totpCodeAt: %v", err)
	}
	rec = doJSON(t, h, "POST", "/api/v1/auth/totp/verify", map[string]string{"Code": code}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("totp verify status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Log out, log back in: now that 2FA is enabled, the fresh session must
	// require an MFA challenge before /me works, even with a valid cookie.
	doJSON(t, h, "POST", "/api/v1/auth/logout", nil, cookie)
	rec = doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "twofactor@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie2 := sessionCookie(rec)
	var loginResp struct {
		MFARequired bool `json:"mfa_required"`
	}
	json.Unmarshal(rec.Body.Bytes(), &loginResp)
	if !loginResp.MFARequired {
		t.Fatal("expected mfa_required=true once 2FA is enabled")
	}

	rec = doJSON(t, h, "GET", "/api/v1/auth/me", nil, cookie2)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/me before MFA challenge status = %d, want 403", rec.Code)
	}

	code2, _ := totpCodeAt(enroll.Secret, time.Now())
	rec = doJSON(t, h, "POST", "/api/v1/auth/mfa/challenge", map[string]string{"Code": code2}, cookie2)
	if rec.Code != http.StatusOK {
		t.Fatalf("mfa challenge status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "GET", "/api/v1/auth/me", nil, cookie2)
	if rec.Code != http.StatusOK {
		t.Fatalf("/me after MFA challenge status = %d, want 200", rec.Code)
	}
}

func TestServerCreateListRevokeFlow(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "fleet@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "fleet@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-1", "Group": "prod"}, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create server status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ServerID == "" {
		t.Fatal("expected a server_id in the create response")
	}

	rec = doJSON(t, h, "GET", "/api/v1/servers", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("list servers status = %d", rec.Code)
	}
	var list []serverRecord
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 server, got %d", len(list))
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/revoke", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID, nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("get server status = %d", rec.Code)
	}
	var rec2 serverRecord
	json.Unmarshal(rec.Body.Bytes(), &rec2)
	if rec2.Status != statusDisconnected {
		t.Fatalf("status after revoke = %q, want %q", rec2.Status, statusDisconnected)
	}
}

func TestBackupEndpointsRequireARealSite(t *testing.T) {
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

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/backups", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("list backups for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/site_nonexistent/backups",
		map[string]any{"scope": "files"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create backup for nonexistent site: status = %d, want 404", rec.Code)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/backups/backup_nonexistent/restore", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("restore nonexistent backup: status = %d, want 404", rec.Code)
	}
}

func TestCreateBackupRejectsInvalidScope(t *testing.T) {
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

	site, err := a.store.createSite(created.ServerID, "c.example.com", "sp_c", "/home/sites/sp_c", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/backups",
		map[string]any{"scope": "everything"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create backup with invalid scope: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/backups",
		map[string]any{"scope": "db"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create db-scope backup without db_name: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A valid, well-formed request against a site whose server has no
	// connected agent should fail as a gateway/dispatch error, not a
	// validation error — proving validation happens before dispatch.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/sites/"+site.ID+"/backups",
		map[string]any{"scope": "files"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create files-scope backup with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreateDatabaseRejectsInvalidNameAndOwner(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "ops3@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "ops3@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-11"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": ""}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create database with empty name: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": "not valid; drop table x"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create database with invalid name: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": "app_db", "owner_user": "root; --"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create database with invalid owner_user: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed request against a server with no connected agent should
	// fail as a gateway/dispatch error, not a validation error — proving
	// validation happens before dispatch, same pattern as backups.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": "app_db"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create database with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDatabaseEndpointsScopeToServerAndRejectDuplicates(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "ops4@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "ops4@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-12"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Seed a database record directly (bypassing agent dispatch, which
	// requires a live agent connection this test doesn't have) to exercise
	// the list/delete endpoints' own logic.
	dbRec, err := a.store.createDatabase(created.ServerID, "app_db", "app_user")
	if err != nil {
		t.Fatalf("createDatabase: %v", err)
	}

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/databases", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("list databases: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("list databases = %v, want 1 entry", list)
	}

	// A duplicate name on the same server must be rejected before dispatch.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": "app_db"}, cookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("create duplicate-named database: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Delete of an unknown database ID must 404.
	rec = doJSON(t, h, "DELETE", "/api/v1/servers/"+created.ServerID+"/databases/db_nonexistent", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent database: status = %d, want 404", rec.Code)
	}

	// Delete of a real database ID with no agent connected fails as a
	// gateway error, and the control-plane record must still exist
	// afterward (delete-then-forget-on-agent-failure would be a data-loss
	// bug: the record must only be removed after the agent confirms).
	rec = doJSON(t, h, "DELETE", "/api/v1/servers/"+created.ServerID+"/databases/"+dbRec.ID, nil, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("delete database with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, ok := a.store.getDatabase(created.ServerID, dbRec.ID); !ok {
		t.Fatal("expected database record to survive a failed (no-agent) delete attempt")
	}
}

func TestRegisterEndpointRejectsBadToken(t *testing.T) {
	a := newTestAPIServer(t)
	h := a.routes()
	rec := doJSON(t, h, "POST", "/agents/register", map[string]string{"Token": "bogus", "CSRPEM": ""}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("register with bad token status = %d, want 401", rec.Code)
	}
}
