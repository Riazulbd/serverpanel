package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionTTL = 12 * time.Hour
const sessionCookieName = "sp_session"

type user struct {
	ID           string
	Email        string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
}

// createUser hashes the password with bcrypt (cost 12 — deliberately above
// the library default to raise the offline cracking cost for a leaked
// hash) and stores the account with 2FA not yet enabled; enableTOTP
// finishes enrollment once the user has verified a code.
func (s *store) createUser(email, password string) (*user, error) {
	if len(password) < 12 {
		return nil, fmt.Errorf("password must be at least 12 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return nil, err
	}
	u := &user{ID: randID("usr"), Email: strings.ToLower(strings.TrimSpace(email)), PasswordHash: string(hash), CreatedAt: time.Now().UTC()}
	_, err = s.db.Exec(
		`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("create user (email may already be registered): %w", err)
	}
	s.log("", u.Email, "user.created", "")
	return u, nil
}

func (s *store) getUserByEmail(email string) (*user, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, totp_secret, totp_enabled, created_at FROM users WHERE email = ?`,
		strings.ToLower(strings.TrimSpace(email))))
}

func (s *store) getUserByID(id string) (*user, error) {
	return s.scanUser(s.db.QueryRow(
		`SELECT id, email, password_hash, totp_secret, totp_enabled, created_at FROM users WHERE id = ?`, id))
}

func (s *store) scanUser(row *sql.Row) (*user, error) {
	var u user
	var totpEnabled int
	var createdAt string
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.TOTPSecret, &totpEnabled, &createdAt); err != nil {
		return nil, err
	}
	u.TOTPEnabled = totpEnabled != 0
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return &u, nil
}

func (s *store) setTOTPSecret(userID, secret string) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret = ? WHERE id = ?`, secret, userID)
	return err
}

func (s *store) enableTOTP(userID string) error {
	_, err := s.db.Exec(`UPDATE users SET totp_enabled = 1 WHERE id = ?`, userID)
	return err
}

// createSession issues a new session token. mfaVerified is false for a
// user whose account has 2FA enabled but hasn't yet supplied a TOTP code
// this login — the auth middleware treats such a session as insufficient
// for any API route until verifyMFA promotes it.
func (s *store) createSession(userID string, mfaVerified bool) (token string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token = hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	mfa := 0
	if mfaVerified {
		mfa = 1
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO sessions (token_hash, user_id, created_at, expires_at, mfa_verified) VALUES (?, ?, ?, ?, ?)`,
		hashHex, userID, now.Format(time.RFC3339Nano), now.Add(sessionTTL).Format(time.RFC3339Nano), mfa,
	)
	return token, err
}

func (s *store) verifySessionMFA(token string) error {
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])
	_, err := s.db.Exec(`UPDATE sessions SET mfa_verified = 1 WHERE token_hash = ?`, hashHex)
	return err
}

type sessionInfo struct {
	UserID      string
	Email       string
	MFAVerified bool
	MFARequired bool
}

func (s *store) lookupSession(token string) (*sessionInfo, error) {
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	var userID, expiresAt string
	var mfaVerified int
	row := s.db.QueryRow(`SELECT user_id, expires_at, mfa_verified FROM sessions WHERE token_hash = ?`, hashHex)
	if err := row.Scan(&userID, &expiresAt, &mfaVerified); err != nil {
		return nil, fmt.Errorf("no such session")
	}
	exp, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil || time.Now().After(exp) {
		s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashHex)
		return nil, fmt.Errorf("session expired")
	}
	u, err := s.getUserByID(userID)
	if err != nil {
		return nil, fmt.Errorf("session user not found")
	}
	return &sessionInfo{UserID: u.ID, Email: u.Email, MFAVerified: mfaVerified != 0, MFARequired: u.TOTPEnabled}, nil
}

func (s *store) deleteSession(token string) {
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])
	s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hashHex)
}

// --- HTTP handlers -------------------------------------------------------

type ctxKey int

const sessionCtxKey ctxKey = 1

func sessionFromContext(ctx context.Context) *sessionInfo {
	s, _ := ctx.Value(sessionCtxKey).(*sessionInfo)
	return s
}

// requireAuth wraps a handler so it only runs for a request carrying a
// valid, non-expired session whose MFA requirement (if the account has 2FA
// enabled) has been satisfied. Every protected route in routes() goes
// through this — there is no API surface that skips it other than
// registration/login themselves.
func (a *apiServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		sess, err := a.store.lookupSession(cookie.Value)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "session invalid or expired")
			return
		}
		if sess.MFARequired && !sess.MFAVerified {
			writeErr(w, http.StatusForbidden, "two-factor verification required")
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func (a *apiServer) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "email and password are required")
		return
	}
	u, err := a.store.createUser(req.Email, req.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"user_id": u.ID, "email": u.Email})
}

func (a *apiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u, err := a.store.getUserByEmail(req.Email)
	if err != nil {
		// Same generic error for unknown-user and wrong-password: don't
		// let the response distinguish account existence.
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, err := a.store.createSession(u.ID, !u.TOTPEnabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	setSessionCookie(w, token)
	a.store.log("", u.Email, "user.login", "")
	writeJSON(w, http.StatusOK, map[string]any{"mfa_required": u.TOTPEnabled})
}

func (a *apiServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		a.store.deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// handleTOTPEnroll issues a fresh TOTP secret for the authenticated user
// and returns the otpauth:// URI for a QR code. The secret is not yet
// "enabled" (verifyTOTP against it doesn't grant MFA-verified sessions)
// until handleTOTPVerify confirms the user actually captured it correctly.
func (a *apiServer) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	secret, err := generateTOTPSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate secret")
		return
	}
	if err := a.store.setTOTPSecret(sess.UserID, secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": totpURI("ServerPanel", sess.Email, secret),
	})
}

func (a *apiServer) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	var req struct{ Code string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u, err := a.store.getUserByID(sess.UserID)
	if err != nil || u.TOTPSecret == "" {
		writeErr(w, http.StatusBadRequest, "no pending TOTP enrollment")
		return
	}
	if !verifyTOTP(u.TOTPSecret, req.Code) {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	if err := a.store.enableTOTP(sess.UserID); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not enable 2FA")
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		a.store.verifySessionMFA(cookie.Value)
	}
	a.store.log("", sess.Email, "user.2fa_enabled", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa enabled"})
}

// handleMFAChallenge verifies a TOTP code against an already-established,
// already-enabled account during login (the account has 2FA, and the
// initial login left the session MFA-unverified).
func (a *apiServer) handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	sess, err := a.store.lookupSession(cookie.Value)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "session invalid or expired")
		return
	}
	var req struct{ Code string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u, err := a.store.getUserByID(sess.UserID)
	if err != nil || !u.TOTPEnabled {
		writeErr(w, http.StatusBadRequest, "2fa not enabled on this account")
		return
	}
	if !verifyTOTP(u.TOTPSecret, req.Code) {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	a.store.verifySessionMFA(cookie.Value)
	a.store.log("", u.Email, "user.mfa_verified", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

func (a *apiServer) handleMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"user_id": sess.UserID, "email": sess.Email})
}

// secureCookies controls the Cookie.Secure flag. It defaults to true
// (production: cookies only ever sent over TLS) and is only ever flipped
// off by an explicit -insecure-cookies flag for local development over
// plain HTTP — see main.go.
var secureCookies = true

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookies,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}
