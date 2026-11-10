package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected PHC hash: %s", hash)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("not-a-hash", "correct horse battery staple") {
		t.Fatal("malformed hash accepted")
	}
	if VerifyPassword("$argon2id$v=19$m=999999999,t=99,p=99$aaaa$bbbb", "x") {
		t.Fatal("absurd Argon2 parameters accepted")
	}
	if err := ValidatePassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := ValidatePassword(strings.Repeat("a", PasswordMaxLength+1)); err == nil {
		t.Fatal("oversized password accepted")
	}
}

func TestTOTPKnownVector(t *testing.T) {
	// RFC 6238 SHA-1 secret for the ASCII string "12345678901234567890".
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, step, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" || step != 1 {
		t.Fatalf("unexpected TOTP code/step: %s/%d", code, step)
	}
	matched, ok := ValidateTOTP(secret, "287082", time.Unix(59, 0))
	if !ok || matched != 1 {
		t.Fatalf("valid TOTP rejected: step=%d ok=%v", matched, ok)
	}
	if _, ok := ValidateTOTP(secret, "000000", time.Unix(59, 0)); ok {
		t.Fatal("invalid TOTP accepted")
	}
	previous, _, _ := TOTPCode(secret, time.Unix(29, 0))
	if matched, ok := ValidateTOTP(secret, previous, time.Unix(59, 0)); !ok || matched != 0 {
		t.Fatalf("one-step clock skew rejected: step=%d ok=%v", matched, ok)
	}
	if !strings.HasPrefix(TOTPURI("HIBP", "admin", secret), "otpauth://totp/HIBP:admin?") {
		t.Fatal("unexpected otpauth URI")
	}
}

func TestUsernameValidation(t *testing.T) {
	for _, valid := range []string{"admin", "ops.user", "ops_user-1", "123abc"} {
		if err := ValidateUsername(valid); err != nil {
			t.Fatalf("expected %q valid: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "ab", ".admin", "-admin", "admin space", "admin\n"} {
		if err := ValidateUsername(invalid); err == nil {
			t.Fatalf("expected %q invalid", invalid)
		}
	}
}
