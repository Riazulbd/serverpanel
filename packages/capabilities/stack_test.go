package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase1LEMPStepsIncludesSSLRenewalWiring(t *testing.T) {
	steps := phase1LEMPSteps()
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	joined := strings.Join(names, "|")
	if !strings.Contains(joined, "renewal deploy-hook") {
		t.Errorf("phase1LEMPSteps missing the certbot renewal deploy-hook step; got steps: %v", names)
	}
	if !strings.Contains(joined, "certbot.timer") {
		t.Errorf("phase1LEMPSteps missing the certbot.timer enable step; got steps: %v", names)
	}

	// The renewal deploy-hook step must come after the certbot install
	// step (it writes into a directory certbot's package creates) and the
	// timer-enable step must come after the hook step (so the hook exists
	// before the timer can ever fire a renewal).
	idx := func(sub string) int {
		for i, n := range names {
			if strings.Contains(n, sub) {
				return i
			}
		}
		return -1
	}
	certbotIdx, hookIdx, timerIdx := idx("certbot (Let's Encrypt"), idx("renewal deploy-hook"), idx("certbot.timer")
	if certbotIdx == -1 || hookIdx == -1 || timerIdx == -1 {
		t.Fatalf("could not locate all three steps: certbot=%d hook=%d timer=%d", certbotIdx, hookIdx, timerIdx)
	}
	if !(certbotIdx < hookIdx && hookIdx < timerIdx) {
		t.Errorf("expected order certbot(%d) < hook(%d) < timer(%d)", certbotIdx, hookIdx, timerIdx)
	}
}

func TestInstallSSLRenewalHookWritesExecutableScript(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "renewal-hooks", "deploy", "serverpanel-reload-nginx.sh")

	origPath := sslDeployHookPath
	sslDeployHookPath = hookPath
	defer func() { sslDeployHookPath = origPath }()

	if err := installSSLRenewalHook(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("hook script was not written: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Errorf("hook script is not executable: mode=%v", info.Mode())
	}

	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "systemctl reload nginx") {
		t.Error("written hook script does not reload nginx")
	}
}

func TestInstallSSLRenewalHookOverwritesExistingContent(t *testing.T) {
	// The install step's Check always returns false (see phase1LEMPSteps),
	// so Run executes on every stack.install call — this test guards that
	// a stale/hand-edited hook is actually replaced, not left alone.
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "renewal-hooks", "deploy", "serverpanel-reload-nginx.sh")
	origPath := sslDeployHookPath
	sslDeployHookPath = hookPath
	defer func() { sslDeployHookPath = origPath }()

	if err := os.MkdirAll(filepath.Dir(hookPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\necho stale\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := installSSLRenewalHook(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "stale") {
		t.Error("stale hook content was not overwritten")
	}
}

func TestCertbotTimerStepCheckHandlesMissingSystemctl(t *testing.T) {
	// On a host with no systemd (e.g. this test sandbox), `systemctl` may
	// not exist at all. The step's Check must degrade to "not active" (so
	// Run gets attempted, which will itself fail loudly rather than the
	// Check silently lying about state) instead of panicking.
	var timerStep *installStep
	for i, s := range phase1LEMPSteps() {
		if strings.Contains(s.Name, "certbot.timer") {
			timerStep = &phase1LEMPSteps()[i]
			break
		}
	}
	if timerStep == nil {
		t.Fatal("certbot.timer step not found")
	}
	// Should not panic regardless of whether systemctl is on PATH.
	_ = timerStep.Check(context.Background())
}
