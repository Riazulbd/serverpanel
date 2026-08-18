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

func TestDatabaseEndpoints(t *testing.T) {
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

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-13"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Invalid name is rejected before any dispatch is attempted.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": "Not-Valid!"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create database with invalid name: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A referenced site that doesn't exist is rejected before dispatch too.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": "wp_example", "site_id": "site_nonexistent"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create database for nonexistent site: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed request against a server with no connected agent fails
	// as a gateway/dispatch error, not a validation error — proving
	// validation happens before dispatch, same as backups.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases",
		map[string]any{"name": "wp_example"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create database with no agent connected: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// List/reveal/delete against a nonexistent database all 404, never a
	// dispatch attempt against a database the control plane never recorded.
	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/databases", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("list databases: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var listed []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &listed)
	if len(listed) != 0 {
		t.Fatalf("list databases after a failed create = %+v, want empty", listed)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases/db_nonexistent/reveal", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("reveal nonexistent database: status = %d, want 404", rec.Code)
	}
	rec = doJSON(t, h, "DELETE", "/api/v1/servers/"+created.ServerID+"/databases/db_nonexistent", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete nonexistent database: status = %d, want 404", rec.Code)
	}
}

func TestDatabaseRevealReturnsThePasswordAndAuditLogsTheAccess(t *testing.T) {
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

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-14"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Create the record directly through the store (bypassing dispatch,
	// which needs a live agent connection this test doesn't have) so the
	// HTTP-level reveal path itself can be exercised end-to-end.
	encPassword, err := a.secrets.encrypt("plaintext-owner-password")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	db, err := a.store.createDatabase(created.ServerID, "", "wp_reveal", "wp_reveal", encPassword)
	if err != nil {
		t.Fatalf("createDatabase: %v", err)
	}

	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/databases/"+db.ID+"/reveal", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("reveal database password: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var revealed struct {
		OwnerUser string `json:"owner_user"`
		Password  string `json:"password"`
	}
	json.Unmarshal(rec.Body.Bytes(), &revealed)
	if revealed.Password != "plaintext-owner-password" || revealed.OwnerUser != "wp_reveal" {
		t.Fatalf("revealed = %+v, want the decrypted original credential", revealed)
	}

	entries := a.store.auditLog()
	found := false
	for _, e := range entries {
		if e.Action == "database.password_revealed" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected a database.password_revealed audit-log entry")
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
