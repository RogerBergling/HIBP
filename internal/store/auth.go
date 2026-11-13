package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/google/uuid"
)

// User is the local HIBP administrator. Password hashes and TOTP secrets are
// intentionally excluded from JSON. The database itself is SQLCipher-encrypted.
type User struct {
	ID                string `json:"id"`
	Username          string `json:"username"`
	PasswordHash      string `json:"-"`
	TOTPSecret        string `json:"-"`
	TOTPPendingSecret string `json:"-"`
	TOTPEnabled       bool   `json:"totp_enabled"`
	TOTPLastStep      int64  `json:"-"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// Passkey is a stored WebAuthn credential. CredentialJSON is the library's
// complete credential record so sign counters and flags round-trip correctly.
type Passkey struct {
	ID             string `json:"id"`
	UserID         string `json:"-"`
	CredentialID   []byte `json:"-"`
	CredentialJSON string `json:"-"`
	SignCount      int64  `json:"sign_count"`
	Name           string `json:"name"`
	CreatedAt      string `json:"created_at"`
	LastUsedAt     string `json:"last_used_at"`
}

// Session is a browser login session. Only the token hash is persisted.
type Session struct {
	ID          string `json:"-"`
	UserID      string `json:"-"`
	TokenHash   string `json:"-"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	LastSeenAt  string `json:"last_seen_at"`
	MFAVerified bool   `json:"mfa_verified"`
}

func (s *Store) CountUsers() (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (s *Store) CreateUser(username, passwordHash string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" || passwordHash == "" {
		return User{}, errors.New("username and password hash are required")
	}
	id := uuid.NewString()
	now := crypto.Now()
	_, err := s.db.Exec(`INSERT INTO users(id,username,password_hash,created_at,updated_at)
		VALUES(?,?,?,?,?)`, id, username, passwordHash, now, now)
	if err != nil {
		return User{}, err
	}
	return User{ID: id, Username: username, PasswordHash: passwordHash, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) GetUserByUsername(username string) (User, error) {
	return s.scanUser(s.db.QueryRow(`SELECT id,username,password_hash,totp_secret,totp_pending_secret,
		totp_enabled,totp_last_step,created_at,updated_at FROM users WHERE username=? COLLATE NOCASE`, username))
}

func (s *Store) GetUserByID(id string) (User, error) {
	return s.scanUser(s.db.QueryRow(`SELECT id,username,password_hash,totp_secret,totp_pending_secret,
		totp_enabled,totp_last_step,created_at,updated_at FROM users WHERE id=?`, id))
}

type userScanner interface {
	Scan(dest ...any) error
}

func (s *Store) scanUser(row userScanner) (User, error) {
	var user User
	var enabled int
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret,
		&user.TOTPPendingSecret, &enabled, &user.TOTPLastStep, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return User{}, err
	}
	user.TOTPEnabled = enabled == 1
	return user, nil
}

func (s *Store) ListUsers() ([]string, error) {
	rows, err := s.db.Query("SELECT username FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		}
		users = append(users, username)
	}
	return users, rows.Err()
}

func (s *Store) SetUserPassword(userID, passwordHash string) error {
	if passwordHash == "" {
		return errors.New("password hash is required")
	}
	res, err := s.db.Exec("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", passwordHash, crypto.Now(), userID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) SetTOTPPendingSecret(userID, secret string) error {
	res, err := s.db.Exec("UPDATE users SET totp_pending_secret=?, updated_at=? WHERE id=?", secret, crypto.Now(), userID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) EnableTOTP(userID, secret string, lastStep int64) error {
	res, err := s.db.Exec(`UPDATE users SET totp_secret=?, totp_pending_secret='', totp_enabled=1,
		totp_last_step=?, updated_at=? WHERE id=?`, secret, lastStep, crypto.Now(), userID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

// EnableTOTPIfNoPasskeys atomically enrolls the pending TOTP secret only when
// the account still has no passkey, TOTP is not already enabled and the pending
// secret is unchanged. It closes the window where a password-only session could
// enroll TOTP on an account that was passkey-only when the request started.
func (s *Store) EnableTOTPIfNoPasskeys(userID, pendingSecret string, lastStep int64) (bool, error) {
	if pendingSecret == "" {
		return false, errors.New("pending TOTP secret is required")
	}
	res, err := s.db.Exec(`UPDATE users SET totp_secret=?, totp_pending_secret='', totp_enabled=1,
		totp_last_step=?, updated_at=?
		WHERE id=? AND totp_enabled=0 AND totp_pending_secret=?
		AND NOT EXISTS (SELECT 1 FROM user_passkeys WHERE user_id=?)`,
		pendingSecret, lastStep, crypto.Now(), userID, pendingSecret, userID)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

func (s *Store) SetTOTPLastStep(userID string, step int64) error {
	res, err := s.db.Exec("UPDATE users SET totp_last_step=?, updated_at=? WHERE id=?", step, crypto.Now(), userID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) ClearTOTP(userID string) error {
	res, err := s.db.Exec(`UPDATE users SET totp_secret='', totp_pending_secret='', totp_enabled=0,
		totp_last_step=0, updated_at=? WHERE id=?`, crypto.Now(), userID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) ListPasskeys(userID string) ([]Passkey, error) {
	rows, err := s.db.Query(`SELECT id,user_id,credential_id,credential_json,sign_count,name,created_at,last_used_at
		FROM user_passkeys WHERE user_id=? ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var passkeys []Passkey
	for rows.Next() {
		var passkey Passkey
		if err := rows.Scan(&passkey.ID, &passkey.UserID, &passkey.CredentialID, &passkey.CredentialJSON,
			&passkey.SignCount, &passkey.Name, &passkey.CreatedAt, &passkey.LastUsedAt); err != nil {
			return nil, err
		}
		passkeys = append(passkeys, passkey)
	}
	return passkeys, rows.Err()
}

func (s *Store) CountPasskeys(userID string) (int, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM user_passkeys WHERE user_id=?", userID).Scan(&count)
	return count, err
}

func (s *Store) AddPasskey(userID string, credentialID []byte, credentialJSON string, signCount int64, name string) (Passkey, error) {
	if len(credentialID) == 0 || credentialJSON == "" {
		return Passkey{}, errors.New("credential id and credential JSON are required")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	id := uuid.NewString()
	now := crypto.Now()
	_, err := s.db.Exec(`INSERT INTO user_passkeys(id,user_id,credential_id,credential_json,sign_count,name,created_at,last_used_at)
		VALUES(?,?,?,?,?,?,?,?)`, id, userID, credentialID, credentialJSON, signCount, name, now, "")
	if err != nil {
		return Passkey{}, err
	}
	return Passkey{ID: id, UserID: userID, CredentialID: credentialID, CredentialJSON: credentialJSON,
		SignCount: signCount, Name: name, CreatedAt: now}, nil
}

func (s *Store) UpdatePasskeyUsage(userID string, credentialID []byte, credentialJSON string, signCount int64) error {
	res, err := s.db.Exec(`UPDATE user_passkeys SET credential_json=?, sign_count=?, last_used_at=?
		WHERE user_id=? AND credential_id=?`, credentialJSON, signCount, crypto.Now(), userID, credentialID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) DeletePasskey(userID, passkeyID string) error {
	res, err := s.db.Exec("DELETE FROM user_passkeys WHERE user_id=? AND id=?", userID, passkeyID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) CreateSession(userID, tokenHash string, mfaVerified bool, ttl time.Duration) (Session, error) {
	if userID == "" || tokenHash == "" {
		return Session{}, errors.New("user id and token hash are required")
	}
	if ttl <= 0 {
		return Session{}, errors.New("session ttl must be positive")
	}
	now := time.Now().UTC()
	created := now.Format(time.RFC3339Nano)
	expires := now.Add(ttl).Format(time.RFC3339Nano)
	id := uuid.NewString()
	verified := 0
	if mfaVerified {
		verified = 1
	}
	_, err := s.db.Exec(`INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at,last_seen_at,mfa_verified)
		VALUES(?,?,?,?,?,?,?)`, id, userID, tokenHash, created, expires, created, verified)
	if err != nil {
		return Session{}, err
	}
	return Session{ID: id, UserID: userID, TokenHash: tokenHash, CreatedAt: created,
		ExpiresAt: expires, LastSeenAt: created, MFAVerified: mfaVerified}, nil
}

func (s *Store) GetSessionByTokenHash(tokenHash string) (Session, error) {
	var session Session
	var verified int
	err := s.db.QueryRow(`SELECT id,user_id,token_hash,created_at,expires_at,last_seen_at,mfa_verified
		FROM sessions WHERE token_hash=?`, tokenHash).Scan(&session.ID, &session.UserID, &session.TokenHash,
		&session.CreatedAt, &session.ExpiresAt, &session.LastSeenAt, &verified)
	session.MFAVerified = verified == 1
	return session, err
}

func (s *Store) TouchSession(sessionID, lastSeen string) error {
	res, err := s.db.Exec("UPDATE sessions SET last_seen_at=? WHERE id=?", lastSeen, sessionID)
	if err != nil {
		return err
	}
	return requireRow(res)
}

func (s *Store) DeleteSession(sessionID string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id=?", sessionID)
	return err
}

func (s *Store) DeleteUserSessions(userID string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE user_id=?", userID)
	return err
}

func (s *Store) DeleteExpiredSessions(now string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires_at < ?", now)
	return err
}

// ResetUserAuth is used by the local recovery command. It removes every MFA
// method and session so a locked-out operator can regain access with the DB
// passphrase and physical access to the controller.
func (s *Store) ResetUserAuth(userID, passwordHash string) error {
	if passwordHash == "" {
		return errors.New("password hash is required")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE users SET password_hash=?, totp_secret='', totp_pending_secret='',
		totp_enabled=0, totp_last_step=0, updated_at=? WHERE id=?`, passwordHash, crypto.Now(), userID)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := requireRow(res); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec("DELETE FROM user_passkeys WHERE user_id=?", userID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec("DELETE FROM sessions WHERE user_id=?", userID); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func requireRow(result sql.Result) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
