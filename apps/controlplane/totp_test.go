package main

import (
	"strings"
	"testing"
	"time"
)

// TestTOTPMatchesRFC6238Vectors validates the implementation against the
// published RFC 6238 SHA-1 test vectors, using the RFC's ASCII secret
// "12345678901234567890" base32-encoded. Getting this right is what makes
// ordinary authenticator apps interoperate; a homegrown OTP that only
// agrees with itself would pass a round-trip test but fail every real
// phone.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// base32("12345678901234567890") with no padding.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	// RFC 6238 Appendix B, truncated to the 6 digits this implementation
	// emits (the RFC table shows 8).
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := totpCodeAt(secret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("totpCodeAt(%d): %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("totpCodeAt(%d) = %s, want %s (RFC 6238 vector)", c.unix, got, c.want)
		}
	}
}

func TestVerifyTOTPAcceptsCurrentCode(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	code, err := totpCodeAt(secret, time.Now())
	if err != nil {
		t.Fatalf("totpCodeAt: %v", err)
	}
	if !verifyTOTP(secret, code) {
		t.Error("verifyTOTP rejected the current code")
	}
}

// TestVerifyTOTPToleratesClockSkew covers the ±1 period window, which is
// what stops a slightly-off phone clock from locking a user out.
func TestVerifyTOTPToleratesClockSkew(t *testing.T) {
	secret, _ := generateTOTPSecret()

	for _, offset := range []time.Duration{-totpPeriod, 0, totpPeriod} {
		code, _ := totpCodeAt(secret, time.Now().Add(offset))
		if !verifyTOTP(secret, code) {
			t.Errorf("verifyTOTP rejected a code from offset %v, inside the allowed skew window", offset)
		}
	}
}

// TestVerifyTOTPRejectsCodesOutsideSkewWindow is the other half: the
// window must not be so wide that stale codes stay usable.
func TestVerifyTOTPRejectsCodesOutsideSkewWindow(t *testing.T) {
	secret, _ := generateTOTPSecret()

	for _, offset := range []time.Duration{-10 * totpPeriod, -3 * totpPeriod, 3 * totpPeriod, 10 * totpPeriod} {
		code, _ := totpCodeAt(secret, time.Now().Add(offset))
		if verifyTOTP(secret, code) {
			t.Errorf("verifyTOTP accepted a code from offset %v, outside the allowed skew window", offset)
		}
	}
}

func TestVerifyTOTPRejectsBadInput(t *testing.T) {
	secret, _ := generateTOTPSecret()

	for _, code := range []string{"", "000000", "12345", "1234567", "abcdef", "  123456  "} {
		if verifyTOTP(secret, code) {
			t.Errorf("verifyTOTP accepted invalid code %q", code)
		}
	}
	// A well-formed code from a *different* secret must not verify.
	other, _ := generateTOTPSecret()
	otherCode, _ := totpCodeAt(other, time.Now())
	if verifyTOTP(secret, otherCode) {
		t.Error("verifyTOTP accepted a code generated from a different secret")
	}
}

func TestVerifyTOTPRejectsMalformedSecret(t *testing.T) {
	if verifyTOTP("not-valid-base32!!!", "123456") {
		t.Error("verifyTOTP accepted a code against a malformed secret")
	}
}

func TestGenerateTOTPSecretIsRandomAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 25; i++ {
		s, err := generateTOTPSecret()
		if err != nil {
			t.Fatalf("generateTOTPSecret: %v", err)
		}
		if seen[s] {
			t.Fatal("generateTOTPSecret returned a duplicate secret")
		}
		seen[s] = true

		if strings.ContainsAny(s, "=018") { // base32 alphabet excludes 0,1,8; no padding expected
			t.Errorf("secret %q contains characters outside the unpadded base32 alphabet", s)
		}
		if len(s) != 32 { // 20 random bytes -> 32 base32 chars
			t.Errorf("secret %q has length %d, want 32", s, len(s))
		}
		if _, err := totpCodeAt(s, time.Now()); err != nil {
			t.Errorf("generated secret %q is not usable: %v", s, err)
		}
	}
}

// TestTOTPURIIsScannable checks the otpauth:// URI carries what an
// authenticator app needs to enroll.
func TestTOTPURIIsScannable(t *testing.T) {
	uri := totpURI("ServerPanel", "owner@example.com", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

	for _, want := range []string{
		"otpauth://totp/",
		"ServerPanel:owner@example.com",
		"secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"issuer=ServerPanel",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("otpauth URI missing %q: %s", want, uri)
		}
	}
}
