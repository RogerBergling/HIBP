package auth

import (
	"errors"
	"regexp"
	"strings"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)

// ValidateUsername keeps the local account name predictable and avoids
// whitespace, control characters, and leading punctuation in audit output.
func ValidateUsername(username string) error {
	if username != strings.TrimSpace(username) || !usernamePattern.MatchString(username) {
		return errors.New("username must be 3-64 characters and start with a letter or digit")
	}
	return nil
}
