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

func TestBackupEndpointsValidateAndScope(t *testing.T) {
	secureCookies = false
	defer func() { secureCookies = true }()

	a := newTestAPIServer(t)
	h := a.routes()

	doJSON(t, h, "POST", "/api/v1/auth/signup", map[string]string{
		"Email": "backups@example.com", "Password": "correcthorsebattery",
	}, nil)
	rec := doJSON(t, h, "POST", "/api/v1/auth/login", map[string]string{
		"Email": "backups@example.com", "Password": "correcthorsebattery",
	}, nil)
	cookie := sessionCookie(rec)

	rec = doJSON(t, h, "POST", "/api/v1/servers", map[string]any{"Name": "web-1"}, cookie)
	var created struct {
		ServerID string `json:"server_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)

	// Missing scope must be rejected before any dispatch is attempted.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/backups", map[string]any{}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create backup without scope status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}

	// files scope without a site_id must be rejected before any dispatch.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/backups", map[string]any{"scope": "files"}, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create files backup without site_id status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}

	// files scope with a site_id that doesn't exist on this server must 404
	// before any dispatch, never trusting a client-asserted path.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/backups", map[string]any{"scope": "files", "site_id": "site_bogus"}, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create files backup with unknown site_id status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}

	// A well-formed db backup request reaches dispatch, which fails because
	// no agent is connected in this test — proves validation passed and the
	// request got as far as the gateway, without needing a live agent.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/backups", map[string]any{"scope": "db", "db_name": "exampledb"}, cookie)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("create db backup with no connected agent status = %d, want 502, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, h, "GET", "/api/v1/servers/"+created.ServerID+"/backups", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("list backups status = %d", rec.Code)
	}
	var list []backupRecord
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("expected 0 backups (none succeeded), got %d", len(list))
	}

	// Restoring an unknown backup id must 404.
	rec = doJSON(t, h, "POST", "/api/v1/servers/"+created.ServerID+"/backups/bkp_bogus/restore", nil, cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("restore unknown backup status = %d, want 404, body = %s", rec.Code, rec.Body.String())
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
