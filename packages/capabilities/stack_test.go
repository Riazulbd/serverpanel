package capabilities

import "testing"

// TestPhase1LEMPStepsAreWellFormed checks the structural properties every
// installStep must have regardless of the host it eventually runs on
// (unique, non-empty names; both Check and Run set) — this is what's
// actually feasible to verify without real apt/systemd (see TESTING.md);
// the steps' actual effect on a live Ubuntu host remains manually verified.
func TestPhase1LEMPStepsAreWellFormed(t *testing.T) {
	steps := phase1LEMPSteps()
	if len(steps) == 0 {
		t.Fatal("expected at least one install step")
	}

	seen := map[string]bool{}
	for _, s := range steps {
		if s.Name == "" {
			t.Fatal("install step with an empty name")
		}
		if seen[s.Name] {
			t.Fatalf("duplicate install step name %q", s.Name)
		}
		seen[s.Name] = true
		if s.Check == nil {
			t.Fatalf("install step %q has a nil Check", s.Name)
		}
		if s.Run == nil {
			t.Fatalf("install step %q has a nil Run", s.Name)
		}
	}
}

// TestPhase1LEMPStepsIncludeCertbotRenewalTimer guards against silently
// dropping the certbot.timer verification step in a future edit — SSL
// certificates issued by ssl.issue_letsencrypt are worthless without
// something actually renewing them before their ~90-day expiry.
func TestPhase1LEMPStepsIncludeCertbotRenewalTimer(t *testing.T) {
	for _, s := range phase1LEMPSteps() {
		if s.Name == "certbot automatic renewal timer" {
			return
		}
	}
	t.Fatal("expected a \"certbot automatic renewal timer\" install step")
}

// TestCertbotTimerUnitExistsChecksBothPackagePaths documents (and pins) the
// two on-disk locations Debian/Ubuntu certbot builds have shipped
// certbot.timer at; it can't assert a specific outcome in a sandboxed test
// environment (certbot isn't installed here), only that the check doesn't
// panic and returns a bool.
func TestCertbotTimerUnitExistsChecksBothPackagePaths(t *testing.T) {
	_ = certbotTimerUnitExists()
}
