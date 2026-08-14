package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

// TOTP (RFC 6238) implemented directly against stdlib crypto primitives —
// small enough (~60 lines) that pulling in a third-party OTP library isn't
// worth the extra dependency for a 30-second, 6-digit, SHA-1 code, which is
// what every authenticator app (Google/Microsoft/Authy/1Password, ...)
// expects by default.
const (
	totpPeriod = 30 * time.Second
	totpDigits = 6
	totpSkew   = 1 // accept one period early/late to tolerate clock drift
)

// generateTOTPSecret returns a fresh random base32-encoded shared secret
// suitable for an authenticator app enrollment QR/URI.
func generateTOTPSecret() (string, error) {
	raw := make([]byte, 20) // 160 bits, standard for SHA-1 HOTP/TOTP
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// totpURI builds the otpauth:// URI an authenticator app's QR scanner
// expects, per Google Authenticator's key-uri-format convention.
func totpURI(issuer, accountEmail, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		issuer, accountEmail, secret, issuer, totpDigits, int(totpPeriod.Seconds()))
}

func totpCodeAt(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret encoding: %w", err)
	}
	counter := uint64(t.Unix() / int64(totpPeriod.Seconds()))

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(math.Pow10(totpDigits))
	return fmt.Sprintf("%0*d", totpDigits, code%mod), nil
}

// verifyTOTP checks a user-supplied code against the secret, tolerating up
// to totpSkew periods of clock drift in either direction. Comparison is
// constant-time to avoid a timing side-channel on the correct code.
func verifyTOTP(secret, code string) bool {
	now := time.Now()
	for skew := -totpSkew; skew <= totpSkew; skew++ {
		want, err := totpCodeAt(secret, now.Add(time.Duration(skew)*totpPeriod))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}
