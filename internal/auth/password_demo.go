//go:build demo

package auth

// HashPasswordForDemo hashes the deliberately short public demo password
// without applying the interactive account password-length policy. It is
// compiled only into the demo binary.
func HashPasswordForDemo(password string) (string, error) {
	return hashPassword(password)
}
