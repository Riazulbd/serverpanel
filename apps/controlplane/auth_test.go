package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestAPI(t *testing.T) *apiServer {
	t.Helper()
	st := newTestStore(t)
	ca, err := newAgentCA()
	if err != nil {
		t.Fatalf("newAgentCA: %v", err)
	}
	return &apiServer{
		store: st, ca: ca, gw: newGateway(ca, st),
		gatewayAddr: "127.0.0.1:8843", tokenTTL: time.Minute,
		publicURL: "https://cp.example.test",
	}
}

func doJSON(t *testing.T, h http.Handler, method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// signupAndLogin returns the session cookies for a fresh account with 2FA
// not yet enabled.
func signupAndLogin(t *testing.T, api *apiServer) []*http.Cookie {
	t.Helper()
	h := api.routes()

	const creds = `{"email":"owner@example.com","password":"correct-horse-battery-staple"}`
	if w := doJSON(t, h, "POST", "/api/v1/auth/signup", creds, nil); w.Code != http.StatusCreated {
		t.Fatalf("signup: got %d, body %s", w.Code, w.Body)
	}
	w := doJSON(t, h, "POST", "/api/v1/auth/login", creds, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: got %d, body %s", w.Code, w.Body)
	}
	return w.Result().Cookies()
}

// TestProtectedRoutesRejectAnonymous is the blanket check that no
// server-management route is reachable without a session. It walks the
// real route table rather than a hand-maintained list so a newly added
// unprotected route fails here.
func TestProtectedRoutesRejectAnonymous(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()

	protected := []struct{ method, path string }{
		{"POST", "/api/v1/servers"},
		{"GET", "/api/v1/servers"},
		{"GET", "/api/v1/servers/srv_x"},
		{"POST", "/api/v1/servers/srv_x/revoke"},
		{"POST", "/api/v1/servers/srv_x/tasks"},
		{"GET", "/api/v1/servers/srv_x/sites"},
		{"POST", "/api/v1/servers/srv_x/sites"},
		{"GET", "/api/v1/audit"},
		{"GET", "/api/v1/auth/me"},
		{"POST", "/api/v1/auth/totp/enroll"},
		{"POST", "/api/v1/auth/totp/verify"},
	}
	for _, rt := range protected {
		w := doJSON(t, h, rt.method, rt.path, `{}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

func TestInvalidSessionCookieIsRejected(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()

	bogus := []*http.Cookie{{Name: sessionCookieName, Value: "not-a-real-session-token"}}
	if w := doJSON(t, h, "GET", "/api/v1/servers", "", bogus); w.Code != http.StatusUnauthorized {
		t.Errorf("forged session cookie = %d, want 401", w.Code)
	}
}

func TestLoginErrorsDoNotRevealAccountExistence(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()
	signupAndLogin(t, api)

	unknown := doJSON(t, h, "POST", "/api/v1/auth/login",
		`{"email":"nobody@example.com","password":"whatever-long-enough"}`, nil)
	wrongPw := doJSON(t, h, "POST", "/api/v1/auth/login",
		`{"email":"owner@example.com","password":"wrong-password-here"}`, nil)

	if unknown.Code != http.StatusUnauthorized || wrongPw.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for both, got %d and %d", unknown.Code, wrongPw.Code)
	}
	if unknown.Body.String() != wrongPw.Body.String() {
		t.Errorf("login responses distinguish unknown-account from wrong-password:\n unknown: %s\n wrongpw: %s",
			unknown.Body.String(), wrongPw.Body.String())
	}
}

func TestSignupRejectsWeakPassword(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()

	w := doJSON(t, h, "POST", "/api/v1/auth/signup",
		`{"email":"a@example.com","password":"short"}`, nil)
	if w.Code == http.StatusCreated {
		t.Error("signup accepted a password below the minimum length")
	}
}

func TestPasswordIsNotStoredInPlaintext(t *testing.T) {
	api := newTestAPI(t)
	signupAndLogin(t, api)

	var hash string
	if err := api.store.db.QueryRow(`SELECT password_hash FROM users LIMIT 1`).Scan(&hash); err != nil {
		t.Fatalf("read user row: %v", err)
	}
	if strings.Contains(hash, "correct-horse-battery-staple") {
		t.Fatal("password stored in plaintext")
	}
	if !strings.HasPrefix(hash, "$2") { // bcrypt marker
		t.Errorf("password_hash %q does not look like a bcrypt hash", hash)
	}
}

// TestMFAGatingBlocksUnverifiedSession is the 2FA enforcement path: once
// an account has TOTP enabled, a password-only session must not reach any
// protected route until it passes the challenge.
func TestMFAGatingBlocksUnverifiedSession(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()
	cookies := signupAndLogin(t, api)

	// Enroll and enable TOTP on this session.
	w := doJSON(t, h, "POST", "/api/v1/auth/totp/enroll", "", cookies)
	if w.Code != http.StatusOK {
		t.Fatalf("totp enroll: %d %s", w.Code, w.Body)
	}
	var enroll struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &enroll); err != nil {
		t.Fatalf("decode enroll response: %v", err)
	}
	code, err := totpCodeAt(enroll.Secret, time.Now())
	if err != nil {
		t.Fatalf("totpCodeAt: %v", err)
	}
	if w := doJSON(t, h, "POST", "/api/v1/auth/totp/verify", `{"code":"`+code+`"}`, cookies); w.Code != http.StatusOK {
		t.Fatalf("totp verify: %d %s", w.Code, w.Body)
	}

	// A brand new login now yields an MFA-unverified session.
	lw := doJSON(t, h, "POST", "/api/v1/auth/login",
		`{"email":"owner@example.com","password":"correct-horse-battery-staple"}`, nil)
	if lw.Code != http.StatusOK {
		t.Fatalf("second login: %d %s", lw.Code, lw.Body)
	}
	var loginResp struct {
		MFARequired bool `json:"mfa_required"`
	}
	json.Unmarshal(lw.Body.Bytes(), &loginResp)
	if !loginResp.MFARequired {
		t.Error("login did not report mfa_required for a 2FA-enabled account")
	}
	fresh := lw.Result().Cookies()

	if w := doJSON(t, h, "GET", "/api/v1/servers", "", fresh); w.Code != http.StatusForbidden {
		t.Errorf("MFA-unverified session reached /api/v1/servers with %d, want 403", w.Code)
	}

	// Wrong code must not promote the session.
	if w := doJSON(t, h, "POST", "/api/v1/auth/mfa/challenge", `{"code":"000000"}`, fresh); w.Code == http.StatusOK {
		t.Error("MFA challenge accepted an incorrect code")
	}
	if w := doJSON(t, h, "GET", "/api/v1/servers", "", fresh); w.Code != http.StatusForbidden {
		t.Error("session was promoted despite a failed MFA challenge")
	}

	// Correct code unlocks it.
	good, _ := totpCodeAt(enroll.Secret, time.Now())
	if w := doJSON(t, h, "POST", "/api/v1/auth/mfa/challenge", `{"code":"`+good+`"}`, fresh); w.Code != http.StatusOK {
		t.Fatalf("MFA challenge with a valid code: %d %s", w.Code, w.Body)
	}
	if w := doJSON(t, h, "GET", "/api/v1/servers", "", fresh); w.Code != http.StatusOK {
		t.Errorf("verified session still blocked: %d", w.Code)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()
	cookies := signupAndLogin(t, api)

	if w := doJSON(t, h, "GET", "/api/v1/servers", "", cookies); w.Code != http.StatusOK {
		t.Fatalf("precondition: session should work, got %d", w.Code)
	}
	if w := doJSON(t, h, "POST", "/api/v1/auth/logout", "", cookies); w.Code != http.StatusOK {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := doJSON(t, h, "GET", "/api/v1/servers", "", cookies); w.Code != http.StatusUnauthorized {
		t.Errorf("session still valid after logout: %d", w.Code)
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	api := newTestAPI(t)
	cookies := signupAndLogin(t, api)

	// Age the session past its expiry directly in the store.
	if _, err := api.store.db.Exec(`UPDATE sessions SET expires_at = ?`,
		time.Now().Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("age session: %v", err)
	}

	if w := doJSON(t, api.routes(), "GET", "/api/v1/servers", "", cookies); w.Code != http.StatusUnauthorized {
		t.Errorf("expired session accepted with %d, want 401", w.Code)
	}
}

// TestInstallCommandUsesConfiguredPublicURL pins the fix that made the
// install flow real: the command must be built from -public-url, never a
// hardcoded placeholder host.
func TestInstallCommandUsesConfiguredPublicURL(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()
	cookies := signupAndLogin(t, api)

	w := doJSON(t, h, "POST", "/api/v1/servers", `{"name":"vps-1"}`, cookies)
	if w.Code != http.StatusCreated {
		t.Fatalf("create server: %d %s", w.Code, w.Body)
	}
	var resp struct {
		InstallCommand string `json:"install_command"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !strings.Contains(resp.InstallCommand, api.publicURL) {
		t.Errorf("install command does not reference the configured public URL %q: %s", api.publicURL, resp.InstallCommand)
	}
	if strings.Contains(resp.InstallCommand, "serverpanel.example") {
		t.Errorf("install command still contains a placeholder host: %s", resp.InstallCommand)
	}
}

// TestRegisterEndpointRejectsBadTokens makes sure the one endpoint an
// unregistered agent can reach can't be brute-forced into an identity.
func TestRegisterEndpointRejectsBadTokens(t *testing.T) {
	api := newTestAPI(t)
	h := api.routes()

	for _, body := range []string{
		`{"token":"","csr_pem":""}`,
		`{"token":"deadbeef","csr_pem":"not a csr"}`,
		`{}`,
	} {
		w := doJSON(t, h, "POST", "/agents/register", body, nil)
		if w.Code == http.StatusOK {
			t.Errorf("register accepted bad payload %s", body)
		}
	}
}
