package capabilities

import "testing"

func TestValidIdentifier(t *testing.T) {
	valid := []string{"a", "wp_example", "site_1", "a23456789012345678901234567890"}
	invalid := []string{
		"", "1abc", "Abc", "has space", "has-dash", "has.dot",
		"a`; DROP TABLE users; --", "toolongtoolongtoolongtoolongtoolongtoolong",
	}
	for _, s := range valid {
		if !ValidIdentifier(s) {
			t.Errorf("ValidIdentifier(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if ValidIdentifier(s) {
			t.Errorf("ValidIdentifier(%q) = true, want false", s)
		}
	}
}
