package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/RogerBergling/hibp/internal/crypto"
)

const (
	// PendingTTL is deliberately short: it only covers the password-to-MFA
	// window. A stolen pending cookie cannot reach the application.
	PendingTTL = 5 * time.Minute
	// SessionTTL is an absolute cap regardless of activity.
	SessionTTL = 12 * time.Hour
	// SessionIdleTTL logs out an unattended browser.
	SessionIdleTTL = 30 * time.Minute
)

// NewSessionToken returns a high-entropy cookie value. Only its hash is stored
// in SQLCipher, so a database leak does not yield a usable session.
func NewSessionToken() (string, error) {
	return crypto.RandomToken()
}

// HashSessionToken is the lookup key stored in the sessions table.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
