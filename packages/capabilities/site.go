package capabilities

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// disabledPHPFunctions is the default deny-list applied to every site's
// php-fpm pool. Combined with open_basedir, this is the isolation boundary
// mentioned throughout docs/security-trust-model.md §4: a compromised
// WordPress plugin in one site can't shell out or read another site's
// files even though PHP itself is capable of both.
var disabledPHPFunctions = []string{
	"exec", "shell_exec", "system", "passthru", "popen", "proc_open",
	"proc_close", "pcntl_exec", "pcntl_fork", "show_source",
}

// siteResult is what site.create returns as its TaskEvent detail (JSON) —
// the control plane parses this to persist a site record; see
// apps/controlplane/sites.go handleCreateSite.
type siteResult struct {
	Domain     string `json:"domain"`
	TempDomain string `json:"temp_domain"`
	SystemUser string `json:"system_user"`
	Docroot    string `json:"docroot"`
	HomeDir    string `json:"home_dir"`
	PHPVersion string `json:"php_version"`
	AppType    string `json:"app_type"`
}

func systemUserForDomain(domain string) string {
	safe := strings.NewReplacer(".", "_", "-", "_").Replace(domain)
	safe = strings.ToLower(safe)
	if len(safe) > 28 {
		safe = safe[:28]
	}
	return "site_" + safe
}

func primaryIP(ctx context.Context) string {
	out, err := run(ctx, "hostname", "-I")
	if err != nil {
		return "127.0.0.1"
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "127.0.0.1"
	}
	return fields[0]
}

func tempDomainFor(user string, ip string) string {
	return fmt.Sprintf("%s.%s.sslip.io", user, strings.ReplaceAll(ip, ".", "-"))
}

func handleSiteCreate(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	domain, _ := params["domain"].(string)
	appType, _ := params["app_type"].(string)
	phpVersion, _ := params["php_version"].(string)
	if phpVersion == "" {
		phpVersion = "8.3"
	}
	if !domainRe.MatchString(strings.ToLower(domain)) {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if appType != "static" && appType != "php" && appType != "wordpress" {
		return "", fmt.Errorf("unsupported app_type %q", appType)
	}
	if phpVersion != "8.3" {
		return "", fmt.Errorf("only php_version 8.3 is supported in this release")
	}

	sysUser := systemUserForDomain(domain)
	home := filepath.Join("/home/sites", sysUser)
	docroot := filepath.Join(home, "public")

	progress("creating isolated system user " + sysUser)
	if _, err := run(ctx, "id", "-u", sysUser); err != nil {
		if _, err := run(ctx, "useradd", "--create-home", "--home-dir", home, "--shell", "/usr/sbin/nologin", sysUser); err != nil {
			return "", fmt.Errorf("create system user: %w", err)
		}
	}

	progress("preparing document root")
	if err := os.MkdirAll(docroot, 0750); err != nil {
		return "", fmt.Errorf("create docroot: %w", err)
	}
	if _, err := run(ctx, "chown", "-R", sysUser+":"+sysUser, home); err != nil {
		return "", fmt.Errorf("chown home dir: %w", err)
	}

	if appType != "static" {
		progress("writing isolated php-fpm pool")
		if err := writePHPFPMPool(sysUser, docroot, phpVersion); err != nil {
			return "", fmt.Errorf("write php-fpm pool: %w", err)
		}
	}

	ip := primaryIP(ctx)
	tempDomain := tempDomainFor(sysUser, ip)

	progress("writing nginx vhost")
	if err := writeNginxVhost(sysUser, domain, tempDomain, docroot, appType, phpVersion); err != nil {
		return "", fmt.Errorf("write nginx vhost: %w", err)
	}

	progress("validating and reloading nginx")
	if out, err := run(ctx, "nginx", "-t"); err != nil {
		return "", fmt.Errorf("nginx config test failed, not reloading: %w: %s", err, out)
	}
	if _, err := run(ctx, "systemctl", "reload", "nginx"); err != nil {
		progress(fmt.Sprintf("warning: could not reload nginx (%v) — may need a manual reload if systemd is unavailable", err))
	}
	if appType != "static" {
		if _, err := run(ctx, "systemctl", "reload", "php8.3-fpm"); err != nil {
			progress(fmt.Sprintf("warning: could not reload php8.3-fpm (%v)", err))
		}
	}

	res := siteResult{Domain: domain, TempDomain: tempDomain, SystemUser: sysUser, Docroot: docroot, HomeDir: home, PHPVersion: phpVersion, AppType: appType}
	out, _ := json.Marshal(res)

	if appType == "static" {
		writeDefaultIndex(docroot, sysUser, domain, "<h1>It works.</h1><p>Static site placeholder — replace the contents of this document root.</p>")
	} else if appType == "php" {
		writeDefaultIndex(docroot, sysUser, domain, "<?php echo 'ServerPanel: PHP site placeholder for "+domain+"'; ?>")
	}

	return string(out), nil
}

func writeDefaultIndex(docroot, sysUser, domain, body string) {
	ext := "html"
	if strings.HasPrefix(body, "<?php") {
		ext = "php"
	}
	path := filepath.Join(docroot, "index."+ext)
	if _, err := os.Stat(path); err == nil {
		return // don't clobber an existing deployment on a retried create
	}
	os.WriteFile(path, []byte(body), 0640)
	run(context.Background(), "chown", sysUser+":"+sysUser, path)
}

func phpFPMPoolPath(sysUser, phpVersion string) string {
	return fmt.Sprintf("/etc/php/%s/fpm/pool.d/%s.conf", phpVersion, sysUser)
}

func phpFPMSocketPath(sysUser, phpVersion string) string {
	return fmt.Sprintf("/run/php/php%s-fpm-%s.sock", phpVersion, sysUser)
}

func writePHPFPMPool(sysUser, docroot, phpVersion string) error {
	tmpl := `; Managed by ServerPanel — isolated pool for %[1]s. Do not edit by hand;
; changes made through the dashboard regenerate this file.
[%[1]s]
user = %[1]s
group = %[1]s
listen = %[2]s
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 5
pm.process_idle_timeout = 10s
php_admin_value[open_basedir] = %[3]s:/tmp
php_admin_value[disable_functions] = %[4]s
php_admin_value[upload_tmp_dir] = /tmp
php_admin_flag[allow_url_fopen] = off
`
	content := fmt.Sprintf(tmpl, sysUser, phpFPMSocketPath(sysUser, phpVersion), docroot, strings.Join(disabledPHPFunctions, ","))
	if err := os.MkdirAll(filepath.Dir(phpFPMPoolPath(sysUser, phpVersion)), 0755); err != nil {
		return err
	}
	return os.WriteFile(phpFPMPoolPath(sysUser, phpVersion), []byte(content), 0644)
}

func nginxVhostPath(sysUser string) string {
	return "/etc/nginx/sites-available/" + sysUser + ".conf"
}

func writeNginxVhost(sysUser, domain, tempDomain, docroot, appType, phpVersion string) error {
	var locationBlock string
	switch appType {
	case "static":
		locationBlock = `    location / {
        try_files $uri $uri/ =404;
    }`
	default:
		locationBlock = fmt.Sprintf(`    index index.php index.html;
    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:%s;
    }
    location ~ /\.ht {
        deny all;
    }`, phpFPMSocketPath(sysUser, phpVersion))
	}

	ipv6Listen := ""
	if ipv6Available() {
		ipv6Listen = "\n    listen [::]:80;"
	}

	content := fmt.Sprintf(`# Managed by ServerPanel for %[1]s (temp domain: %[2]s). Do not edit by
# hand; changes made through the dashboard regenerate this file.
server {
    listen 80;%[6]s
    server_name %[1]s %[2]s;
    root %[3]s;

%[4]s

    access_log /var/log/nginx/%[5]s.access.log;
    error_log  /var/log/nginx/%[5]s.error.log;
}
`, domain, tempDomain, docroot, locationBlock, sysUser, ipv6Listen)

	if err := os.WriteFile(nginxVhostPath(sysUser), []byte(content), 0644); err != nil {
		return err
	}
	enabledPath := "/etc/nginx/sites-enabled/" + sysUser + ".conf"
	os.Remove(enabledPath)
	return os.Symlink(nginxVhostPath(sysUser), enabledPath)
}

func handleSiteSetPHP(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	phpVersion, _ := params["php_version"].(string)
	if phpVersion != "8.3" {
		return "", fmt.Errorf("only php_version 8.3 is available in this release")
	}
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}
	return "no-op: only one PHP version is currently offered", nil
}

func handleSiteSetStatus(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	sysUser, _ := params["system_user"].(string)
	status, _ := params["status"].(string)
	if sysUser == "" || !strings.HasPrefix(sysUser, "site_") {
		return "", fmt.Errorf("invalid system_user")
	}
	enabledPath := "/etc/nginx/sites-enabled/" + sysUser + ".conf"

	switch status {
	case "disabled":
		os.Remove(enabledPath)
	case "active":
		if err := os.Symlink(nginxVhostPath(sysUser), enabledPath); err != nil && !os.IsExist(err) {
			return "", err
		}
	default:
		return "", fmt.Errorf("status must be \"active\" or \"disabled\"")
	}

	if out, err := run(ctx, "nginx", "-t"); err != nil {
		return "", fmt.Errorf("nginx config test failed: %w: %s", err, out)
	}
	run(ctx, "systemctl", "reload", "nginx")
	return "site status set to " + status, nil
}
