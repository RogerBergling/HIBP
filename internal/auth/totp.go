package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	TOTPPeriod    = 30
	TOTPDigits    = 6
	TOTPSkew      = 1
	totpSecretLen = 20
)

// ErrInvalidTOTPSecret is returned when a stored or submitted secret is not a
// valid base32 TOTP key.
var ErrInvalidTOTPSecret = errors.New("invalid TOTP secret")

// GenerateTOTPSecret returns a 160-bit base32 secret without padding. The
// secret is stored only in the SQLCipher database and returned once to the
// authenticated enrollment UI.
func GenerateTOTPSecret() (string, error) {
	secret := make([]byte, totpSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// TOTPURI builds the standard otpauth URI consumed by authenticator apps.
func TOTPURI(issuer, account, secret string) string {
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", strconv.Itoa(TOTPDigits))
	values.Set("period", strconv.Itoa(TOTPPeriod))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + values.Encode()
}

// TOTPCode returns the current code and its time step. It is exported for
// tests and operational tooling; the server normally only verifies codes.
func TOTPCode(secret string, at time.Time) (string, int64, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", 0, err
	}
	step := at.Unix() / TOTPPeriod
	code, err := hotp(key, uint64(step))
	return code, step, err
}

// ValidateTOTP checks the current 30-second step and one step either side. The
// caller must reject a returned step that is not greater than the last used
// step; that replay guard is stateful and lives in the database.
func ValidateTOTP(secret, code string, at time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return 0, false
	}
	for _, character := range code {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return 0, false
	}
	current := at.Unix() / TOTPPeriod
	for offset := -TOTPSkew; offset <= TOTPSkew; offset++ {
		step := current + int64(offset)
		if step < 0 {
			continue
		}
		expected, err := hotp(key, uint64(step))
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil || len(key) < 10 {
		return nil, ErrInvalidTOTPSecret
	}
	return key, nil
}

func hotp(key []byte, counter uint64) (string, error) {
	mac := hmac.New(sha1.New, key)
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], counter)
	if _, err := mac.Write(payload[:]); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", TOTPDigits, value%1_000_000), nil
}
