package capabilities

import "testing"

// TestValidIdentifierBoundaries locks down the exact identifier rule
// db.create/db.delete enforce, and that the control plane's exported entry
// point (ValidIdentifier) agrees with it — this is the one guardrail
// against SQL-identifier injection on a code path that can't use
// placeholders (MySQL has no bind-parameter syntax for identifiers).
func TestValidIdentifierBoundaries(t *testing.T) {
	valid := []string{"a", "wp_example", "db1", "a123456789012345678901234567890"} // 31 chars: the max
	for _, s := range valid {
		if !ValidIdentifier(s) {
			t.Errorf("ValidIdentifier(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",                                 // empty
		"1abc",                             // must start with a letter
		"Abc",                              // uppercase not allowed
		"a-b",                              // hyphen not allowed
		"a b",                              // space not allowed
		"a.b",                              // dot not allowed
		"a`b",                              // backtick — the injection case this guards against
		"a; DROP TABLE users;--",           // classic injection attempt
		"a1234567890123456789012345678901", // 32 chars, one over the limit
	}
	for _, s := range invalid {
		if ValidIdentifier(s) {
			t.Errorf("ValidIdentifier(%q) = true, want false", s)
		}
	}
}
