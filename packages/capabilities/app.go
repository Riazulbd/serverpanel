package capabilities

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// runAsUser executes wp-cli as the site's own isolated system user via
// runuser's argv form (`runuser -u <user> -- <argv...>`), never through a
// shell string — so even though callers here build these commands from
// values we've already validated (domain regex, our own generated
// credentials), there is no shell metacharacter interpretation to worry
// about at all.
func runAsUser(ctx context.Context, sysUser string, argv ...string) (string, error) {
	args := append([]string{"-u", sysUser, "--"}, argv...)
	return run(ctx, "runuser", args...)
}

func handleWordPressInstall(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	docroot, _ := params["docroot"].(string)
	domain, _ := params["domain"].(string)
	dbName, _ := params["db_name"].(string)
	dbUser, _ := params["db_user"].(string)
	dbPassword, _ := params["db_password"].(string)
	adminUser, _ := params["admin_user"].(string)
	adminPassword, _ := params["admin_password"].(string)
	adminEmail, _ := params["admin_email"].(string)
	siteTitle, _ := params["site_title"].(string)

	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}
	expectedRoot := siteHome(sysUser)
	if !strings.HasPrefix(docroot, expectedRoot) {
		return "", fmt.Errorf("docroot must be under %s (got %q) — refusing to operate outside the site's isolated home", expectedRoot, docroot)
	}
	for name, val := range map[string]string{
		"domain": domain, "db_name": dbName, "db_user": dbUser, "db_password": dbPassword,
		"admin_user": adminUser, "admin_password": adminPassword, "admin_email": adminEmail,
	} {
		if val == "" {
			return "", fmt.Errorf("%s is required", name)
		}
	}
	if siteTitle == "" {
		siteTitle = domain
	}

	if _, err := os.Stat("/usr/local/bin/wp"); err != nil {
		return "", fmt.Errorf("wp-cli is not installed on this server; run stack.install first")
	}

	if _, err := os.Stat(filepath.Join(docroot, "wp-load.php")); err != nil {
		progress("downloading WordPress core")
		if out, err := runAsUser(ctx, sysUser, "/usr/local/bin/wp", "core", "download", "--path="+docroot, "--locale=en_US"); err != nil {
			return "", fmt.Errorf("wp core download: %w: %s", err, out)
		}
	} else {
		progress("WordPress core already present, skipping download")
	}

	if _, err := os.Stat(filepath.Join(docroot, "wp-config.php")); err != nil {
		progress("writing wp-config.php")
		out, err := runAsUser(ctx, sysUser, "/usr/local/bin/wp", "config", "create",
			"--path="+docroot, "--dbname="+dbName, "--dbuser="+dbUser, "--dbpass="+dbPassword,
			"--dbhost=localhost", "--skip-check")
		if err != nil {
			return "", fmt.Errorf("wp config create: %w: %s", err, out)
		}
	} else {
		progress("wp-config.php already present, skipping")
	}

	if _, err := runAsUser(ctx, sysUser, "/usr/local/bin/wp", "core", "is-installed", "--path="+docroot); err != nil {
		progress("running WordPress core install")
		out, err := runAsUser(ctx, sysUser, "/usr/local/bin/wp", "core", "install",
			"--path="+docroot, "--url="+domain, "--title="+siteTitle,
			"--admin_user="+adminUser, "--admin_password="+adminPassword, "--admin_email="+adminEmail,
			"--skip-email")
		if err != nil {
			return "", fmt.Errorf("wp core install: %w: %s", err, out)
		}
	} else {
		progress("WordPress already installed, skipping core install")
	}

	return fmt.Sprintf("WordPress installed for %s (admin user: %s)", domain, adminUser), nil
}
