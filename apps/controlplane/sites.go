package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateSite dispatches site.create to the agent and, only on
// success, persists a site record — this is the one place the control
// plane's sites table is ever written, which is why generic capability
// dispatch (handleDispatchTask) and site creation are separate endpoints
// even though both ultimately call gateway.dispatch: a raw task result
// alone isn't enough to know a site now exists, and the JSON detail
// site.create returns (packages/capabilities/site.go siteResult) is the
// one place that fact is expressed.
//
// For app_type=wordpress, this also chains db.create and
// app.wordpress_install after site.create succeeds — previously the
// dashboard offered "WordPress" as a site type but never actually
// installed it, silently leaving an empty docroot. A failure in either
// chained step is reported back as wordpress_error in the response rather
// than as an HTTP error, because the site itself was already created
// successfully by that point: there is no automatic rollback of a
// successful site.create (see docs/OPERATIONS.md), so the caller needs to
// know the site exists even if the WordPress install on top of it failed
// partway and needs a retry.
func (a *apiServer) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Domain     string `json:"domain"`
		AppType    string `json:"app_type"`
		PHPVersion string `json:"php_version"`
		AdminEmail string `json:"admin_email"`
		AdminUser  string `json:"admin_user"`
		SiteTitle  string `json:"site_title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" || req.AppType == "" {
		writeErr(w, http.StatusBadRequest, "domain and app_type are required")
		return
	}
	if req.AppType == "wordpress" && req.AdminEmail == "" {
		writeErr(w, http.StatusBadRequest, "admin_email is required for a WordPress site")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	ev, err := a.gw.dispatch(ctx, serverID, actor, "site.create", map[string]any{
		"domain": req.Domain, "app_type": req.AppType, "php_version": req.PHPVersion,
	})
	cancel()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "site.create failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Domain     string `json:"domain"`
		TempDomain string `json:"temp_domain"`
		SystemUser string `json:"system_user"`
		Docroot    string `json:"docroot"`
		PHPVersion string `json:"php_version"`
		AppType    string `json:"app_type"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "site was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	site, err := a.store.createSite(serverID, result.Domain, result.SystemUser, result.Docroot, result.AppType, result.PHPVersion)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "site was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "site.created", "domain="+result.Domain+" temp_domain="+result.TempDomain)

	resp := map[string]any{
		"site":        site,
		"temp_domain": result.TempDomain,
	}

	if req.AppType == "wordpress" {
		wp, wpErr := a.installWordPress(r.Context(), serverID, actor, result.SystemUser, result.Docroot, result.Domain, req.AdminUser, req.AdminEmail, req.SiteTitle)
		if wpErr != nil {
			resp["wordpress_error"] = wpErr.Error()
		} else {
			resp["wordpress"] = wp
		}
	}

	writeJSON(w, http.StatusCreated, resp)
}

type wordpressCredentials struct {
	DBName        string `json:"db_name"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
}

// installWordPress creates a dedicated, least-privilege database and runs
// app.wordpress_install on top of an already-created site. Generated
// secrets (db password, admin password if the caller didn't supply one)
// are returned exactly once in the HTTP response, the same "shown once,
// never persisted" treatment createServer already gives the agent
// bootstrap token — the control plane's database has no databases table
// to persist DB credentials into yet (see docs/SYSTEM.md's known
// limitations), so this is the only place they're ever visible again after
// this call.
func (a *apiServer) installWordPress(ctx context.Context, serverID, actor, systemUser, docroot, domain, adminUser, adminEmail, siteTitle string) (*wordpressCredentials, error) {
	dbName, err := randomIdentifier("wp_")
	if err != nil {
		return nil, fmt.Errorf("generate database name: %w", err)
	}
	dbPassword, err := randomSecret(24)
	if err != nil {
		return nil, fmt.Errorf("generate database password: %w", err)
	}

	dctx, dcancel := context.WithTimeout(ctx, 120*time.Second)
	dbEv, err := a.gw.dispatch(dctx, serverID, actor, "db.create", map[string]any{
		"name": dbName, "owner_user": dbName, "owner_password": dbPassword,
	})
	dcancel()
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	if dbEv.Status != proto.TaskSucceeded {
		return nil, fmt.Errorf("db.create failed on the agent: %s", dbEv.Message)
	}

	if adminUser == "" {
		adminUser = "admin"
	}
	adminPassword, err := randomSecret(18)
	if err != nil {
		return nil, fmt.Errorf("generate admin password: %w", err)
	}

	// WordPress core download + install can take noticeably longer than a
	// typical capability, especially on a fresh server with a cold package
	// cache — a separate, longer timeout than the 120s default used
	// elsewhere in this file.
	ictx, icancel := context.WithTimeout(ctx, 240*time.Second)
	wpEv, err := a.gw.dispatch(ictx, serverID, actor, "app.wordpress_install", map[string]any{
		"system_user": systemUser, "docroot": docroot, "domain": domain,
		"db_name": dbName, "db_user": dbName, "db_password": dbPassword,
		"admin_user": adminUser, "admin_password": adminPassword, "admin_email": adminEmail,
		"site_title": siteTitle,
	})
	icancel()
	if err != nil {
		return nil, fmt.Errorf("install WordPress: %w", err)
	}
	if wpEv.Status != proto.TaskSucceeded {
		return nil, fmt.Errorf("app.wordpress_install failed on the agent: %s", wpEv.Message)
	}

	a.store.log(serverID, actor, "wordpress.installed", fmt.Sprintf("domain=%s db_name=%s admin_user=%s", domain, dbName, adminUser))

	return &wordpressCredentials{DBName: dbName, AdminUser: adminUser, AdminPassword: adminPassword}, nil
}

// randomIdentifier generates a database/user identifier matching
// packages/capabilities/db.go's identifierRe (^[a-z][a-z0-9_]{0,30}$):
// prefix + 12 lowercase hex characters, well within the 31-character limit
// regardless of prefix length, and never derived from caller-supplied
// text (e.g. the domain), which the identifier regex wouldn't accept
// unmodified anyway.
func randomIdentifier(prefix string) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// randomSecret generates a URL-safe-base64-encoded random secret of
// nBytes of entropy — safe to place in argv (no shell metacharacters) and
// long enough to satisfy db.create's 16-character minimum for any nBytes
// used in this file.
func randomSecret(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
