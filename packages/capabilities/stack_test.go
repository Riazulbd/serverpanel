package capabilities

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestCertbotDeployHookPath points certbotDeployHookPath at a temp
// directory for the duration of one test, mirroring newTestBackupBaseDir in
// backup_test.go, so the deploy-hook install/idempotency logic can be
// exercised without writing under the real /etc/letsencrypt.
func newTestCertbotDeployHookPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "renewal-hooks", "deploy", "serverpanel-reload-nginx.sh")
	orig := certbotDeployHookPath
	certbotDeployHookPath = path
	t.Cleanup(func() { certbotDeployHookPath = orig })
	return path
}

func TestCertbotDeployHookNotInstalledInitially(t *testing.T) {
	newTestCertbotDeployHookPath(t)
	if certbotDeployHookInstalled() {
		t.Fatal("expected certbotDeployHookInstalled to be false before install")
	}
}

func TestInstallCertbotDeployHookWritesExecutableScript(t *testing.T) {
	path := newTestCertbotDeployHookPath(t)

	if err := installCertbotDeployHook(); err != nil {
		t.Fatalf("installCertbotDeployHook: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected hook script to exist: %v", err)
	}
	if info.Mode().Perm()&0111 == 0 {
		t.Fatalf("expected hook script to be executable, got mode %v", info.Mode())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hook script: %v", err)
	}
	if string(data) != certbotDeployHookScript {
		t.Fatal("written hook script content does not match certbotDeployHookScript")
	}

	// A script that only ever runs `nginx -t` and `systemctl reload nginx`
	// (a fixed argv with no caller-supplied input) — never anything derived
	// from certbot's renewal environment variables.
	got := string(data)
	for _, forbidden := range []string{"$RENEWED_DOMAINS", "$RENEWED_LINEAGE", "eval"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("hook script must not reference renewal environment variables or eval: %q", got)
		}
	}
}

func TestCertbotDeployHookInstalledIsIdempotent(t *testing.T) {
	newTestCertbotDeployHookPath(t)

	if err := installCertbotDeployHook(); err != nil {
		t.Fatalf("installCertbotDeployHook (first): %v", err)
	}
	if !certbotDeployHookInstalled() {
		t.Fatal("expected certbotDeployHookInstalled to be true after install")
	}

	// Re-running must be a no-op that leaves the check satisfied — this is
	// what phase1LEMPSteps' Check/Run pair relies on to skip already-done
	// steps on a retried stack.install.
	if err := installCertbotDeployHook(); err != nil {
		t.Fatalf("installCertbotDeployHook (second): %v", err)
	}
	if !certbotDeployHookInstalled() {
		t.Fatal("expected certbotDeployHookInstalled to remain true after a second install")
	}
}

func TestCertbotDeployHookDetectsDrift(t *testing.T) {
	path := newTestCertbotDeployHookPath(t)

	if err := installCertbotDeployHook(); err != nil {
		t.Fatalf("installCertbotDeployHook: %v", err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho tampered\n"), 0755); err != nil {
		t.Fatalf("simulate drift: %v", err)
	}
	if certbotDeployHookInstalled() {
		t.Fatal("expected certbotDeployHookInstalled to be false once file content drifts from certbotDeployHookScript")
	}
}

// TestPhase1LEMPStepsInstallsCertbotTimerAndHookAfterCertbotPackage guards
// against a future edit silently dropping or reordering the renewal-timer
// steps ahead of the certbot package itself being installed.
func TestPhase1LEMPStepsInstallsCertbotTimerAndHookAfterCertbotPackage(t *testing.T) {
	steps := phase1LEMPSteps()

	names := make([]string, len(steps))
	for i, s := range steps {
		names[i] = s.Name
	}

	certbotIdx := indexOf(names, "certbot (Let's Encrypt ACME client)")
	timerIdx := indexOf(names, "certbot renewal timer active")
	hookIdx := indexOf(names, "certbot renewal deploy-hook (nginx reload)")

	if certbotIdx == -1 || timerIdx == -1 || hookIdx == -1 {
		t.Fatalf("expected all three certbot-related steps present, got: %v", names)
	}
	if !(certbotIdx < timerIdx && timerIdx < hookIdx) {
		t.Fatalf("expected certbot package -> renewal timer -> deploy-hook order, got indices %d, %d, %d", certbotIdx, timerIdx, hookIdx)
	}
}

func indexOf(names []string, name string) int {
	for i, n := range names {
		if n == name {
			return i
		}
	}
	return -1
}
