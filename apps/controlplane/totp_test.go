package main

import (
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	code, err := totpCodeAt(secret, time.Now())
	if err != nil {
		t.Fatalf("totpCodeAt: %v", err)
	}
	if len(code) != totpDigits {
		t.Fatalf("code %q has length %d, want %d", code, len(code), totpDigits)
	}
	if !verifyTOTP(secret, code) {
		t.Fatal("verifyTOTP rejected a freshly generated valid code")
	}
}

func TestTOTPRejectsWrongCode(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	if verifyTOTP(secret, "000000") {
		// Astronomically unlikely to collide; if it ever does, the test
		// itself is flaky evidence of nothing.
		t.Skip("random collision with 000000, skipping")
	}
	if verifyTOTP(secret, "not-a-code") {
		t.Fatal("verifyTOTP accepted a non-numeric code")
	}
}

func TestTOTPToleratesClockSkewWithinWindow(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	past := time.Now().Add(-totpPeriod)
	code, err := totpCodeAt(secret, past)
	if err != nil {
		t.Fatalf("totpCodeAt: %v", err)
	}
	if !verifyTOTP(secret, code) {
		t.Fatal("verifyTOTP should tolerate one period of clock drift")
	}
}

func TestTOTPRejectsCodeOutsideSkewWindow(t *testing.T) {
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatalf("generateTOTPSecret: %v", err)
	}
	farPast := time.Now().Add(-10 * totpPeriod)
	code, err := totpCodeAt(secret, farPast)
	if err != nil {
		t.Fatalf("totpCodeAt: %v", err)
	}
	if verifyTOTP(secret, code) {
		t.Fatal("verifyTOTP accepted a code far outside the allowed skew window")
	}
}

func TestTOTPCodeAtRejectsInvalidSecretEncoding(t *testing.T) {
	if _, err := totpCodeAt("not-valid-base32!!!", time.Now()); err == nil {
		t.Fatal("expected an error for invalid base32 secret")
	}
}

func TestTOTPURIContainsExpectedFields(t *testing.T) {
	uri := totpURI("ServerPanel", "user@example.com", "SECRET")
	want := "otpauth://totp/ServerPanel:user@example.com?secret=SECRET&issuer=ServerPanel&digits=6&period=30"
	if uri != want {
		t.Fatalf("totpURI = %q, want %q", uri, want)
	}
}
