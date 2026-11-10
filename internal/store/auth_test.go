package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openAuthTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "auth.hibp"), []byte("correct horse battery staple"), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestUserPasskeyAndSessionLifecycle(t *testing.T) {
	s := openAuthTestStore(t)
	if count, err := s.CountUsers(); err != nil || count != 0 {
		t.Fatalf("expected empty users, count=%d err=%v", count, err)
	}
	user, err := s.CreateUser("admin", "hash-one")
	if err != nil {
		t.Fatal(err)
	}
	if user.ID == "" || user.Username != "admin" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if _, err := s.CreateUser("ADMIN", "hash-two"); err == nil {
		t.Fatal("expected case-insensitive username uniqueness")
	}
	got, err := s.GetUserByUsername("ADMIN")
	if err != nil || got.ID != user.ID {
		t.Fatalf("case-insensitive lookup failed: %+v %v", got, err)
	}

	if err := s.SetTOTPPendingSecret(user.ID, "PENDING"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableTOTP(user.ID, "SECRET", 42); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TOTPEnabled || got.TOTPSecret != "SECRET" || got.TOTPPendingSecret != "" || got.TOTPLastStep != 42 {
		t.Fatalf("unexpected TOTP state: %+v", got)
	}

	passkey, err := s.AddPasskey(user.ID, []byte("credential-id"), `{"id":"credential-id"}`, 1, "Laptop")
	if err != nil {
		t.Fatal(err)
	}
	if count, err := s.CountPasskeys(user.ID); err != nil || count != 1 {
		t.Fatalf("expected one passkey, count=%d err=%v", count, err)
	}
	if err := s.UpdatePasskeyUsage(user.ID, passkey.CredentialID, `{"id":"credential-id","updated":true}`, 2); err != nil {
		t.Fatal(err)
	}
	passkeys, err := s.ListPasskeys(user.ID)
	if err != nil || len(passkeys) != 1 {
		t.Fatalf("unexpected passkeys: %+v %v", passkeys, err)
	}
	if passkeys[0].SignCount != 2 || passkeys[0].LastUsedAt == "" {
		t.Fatalf("passkey usage not updated: %+v", passkeys[0])
	}

	session, err := s.CreateSession(user.ID, "token-hash", true, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := s.GetSessionByTokenHash("token-hash")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ID != session.ID || !loaded.MFAVerified {
		t.Fatalf("unexpected session: %+v", loaded)
	}
	if err := s.TouchSession(session.ID, "2026-11-10T12:00:00Z"); err != nil {
		t.Fatal(err)
	}
	loaded, _ = s.GetSessionByTokenHash("token-hash")
	if loaded.LastSeenAt != "2026-11-10T12:00:00Z" {
		t.Fatalf("session touch failed: %+v", loaded)
	}

	if err := s.ResetUserAuth(user.ID, "hash-reset"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetUserByID(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "hash-reset" || got.TOTPEnabled {
		t.Fatalf("reset did not clear auth: %+v", got)
	}
	if count, _ := s.CountPasskeys(user.ID); count != 0 {
		t.Fatalf("expected passkeys removed, got %d", count)
	}
	if _, err := s.GetSessionByTokenHash("token-hash"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected session removal, got %v", err)
	}
}
