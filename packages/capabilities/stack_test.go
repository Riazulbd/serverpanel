package capabilities

import "testing"

// TestPhase1LEMPStepsUniqueNamesAndShape guards the structural properties
// the installer's retry/skip logic depends on (docs/SYSTEM.md §22 "safe to
// retry"): every step must have a name (used in progress messages and error
// wrapping), a Check, and a Run, and names must be unique so a
// "resume from exactly this step" error message unambiguously identifies
// one step. It deliberately does not execute Check/Run themselves — those
// shell out to apt/systemctl and are verified manually against a real
// Ubuntu host (see docs/TESTING.md).
func TestPhase1LEMPStepsUniqueNamesAndShape(t *testing.T) {
	steps := phase1LEMPSteps()
	if len(steps) == 0 {
		t.Fatal("phase1LEMPSteps() returned no steps")
	}

	seen := map[string]bool{}
	for _, s := range steps {
		if s.Name == "" {
			t.Fatal("a step has an empty Name")
		}
		if seen[s.Name] {
			t.Fatalf("duplicate step name %q", s.Name)
		}
		seen[s.Name] = true
		if s.Check == nil {
			t.Fatalf("step %q has a nil Check", s.Name)
		}
		if s.Run == nil {
			t.Fatalf("step %q has a nil Run", s.Name)
		}
	}
}

// TestPhase1LEMPStepsRenewalTimerAfterCertbot pins the ordering dependency:
// the renewal-timer step enables a systemd unit that only exists once the
// certbot package step above it has actually installed it.
func TestPhase1LEMPStepsRenewalTimerAfterCertbot(t *testing.T) {
	steps := phase1LEMPSteps()
	certbotIdx, timerIdx := -1, -1
	for i, s := range steps {
		switch s.Name {
		case "certbot (Let's Encrypt ACME client)":
			certbotIdx = i
		case "certbot auto-renewal timer":
			timerIdx = i
		}
	}
	if certbotIdx == -1 {
		t.Fatal("certbot install step not found")
	}
	if timerIdx == -1 {
		t.Fatal("certbot auto-renewal timer step not found")
	}
	if timerIdx <= certbotIdx {
		t.Fatalf("renewal timer step (index %d) must come after the certbot install step (index %d)", timerIdx, certbotIdx)
	}
}
