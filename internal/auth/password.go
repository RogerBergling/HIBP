// Package auth contains password, session, username, and TOTP primitives.
//
// Security notes:
//   - Passwords are hashed with Argon2id, a memory-hard KDF. The encoded hash
//     records the parameters so they can be raised later without a schema
//     change.
//   - Verification refuses absurd parameter values from a tampered database.
//     Without that bound, a malicious row could turn every login into a memory
//     exhaustion attempt.
//   - Password length is checked in characters but hashing consumes bytes.
//     The maximum prevents a pathological multi-megabyte input.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	PasswordMinLength = 12
	PasswordMaxLength = 1024

	passwordSaltLength        = 16
	passwordKeyLength         = 32
	passwordTime       uint32 = 3
	passwordMemory     uint32 = 64 * 1024 // 64 MiB
	passwordThreads    uint8  = 2

	// These bounds protect the verifier from tampered PHC parameters.
	maxPasswordMemory  = 256 * 1024
	maxPasswordTime    = 10
	maxPasswordThreads = 16
)

// ValidatePassword is intentionally simple. Length is the only hard rule; a
// breach-corpus or zxcvbn check can be added later without changing storage.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", PasswordMinLength)
	}
	if len(password) > PasswordMaxLength {
		return fmt.Errorf("password must be at most %d bytes", PasswordMaxLength)
	}
	return nil
}

// HashPassword returns a PHC-formatted Argon2id hash.
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, passwordSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, passwordTime, passwordMemory, passwordThreads, passwordKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		passwordMemory, passwordTime, passwordThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword performs a constant-time comparison after deriving the key.
// Any malformed or out-of-bounds hash returns false, never an error that would
// leak whether the account exists.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var memory, iterations, threads int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	if memory < 64*1024 || memory > maxPasswordMemory ||
		iterations < 1 || iterations > maxPasswordTime ||
		threads < 1 || threads > maxPasswordThreads {
		return false
	}
	salt, ok := decodeBase64(parts[4])
	if !ok || len(salt) < 8 {
		return false
	}
	want, ok := decodeBase64(parts[5])
	if !ok || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func decodeBase64(value string) ([]byte, bool) {
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return decoded, true
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, true
	}
	return nil, false
}

// DummyPasswordHash is used for a fixed-cost failure when the username is not
// found, so login timing does not reveal account existence. It is generated at
// startup by the server, not stored in the database.
func DummyPasswordHash() string {
	const dummy = "hibp-dummy-password-never-used"
	hash, err := HashPassword(dummy)
	if err != nil {
		return ""
	}
	return hash
}
