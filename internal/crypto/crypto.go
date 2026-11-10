// Package crypto contains the passphrase, sidecar, token, and hashing helpers.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

const (
	SidecarVersion = 1
	KDFName        = "argon2id"
	SaltLen        = 16
	KeyLen         = 32

	DefaultTime    uint32 = 3
	DefaultMemory  uint32 = 256 * 1024 // KiB
	DefaultThreads uint8  = 4

	MinTime    uint32 = 1
	MaxTime    uint32 = 10
	MinMemory  uint32 = 64 * 1024
	MaxMemory  uint32 = 1024 * 1024
	MinThreads uint8  = 1
	MaxThreads uint8  = 16
)

// Sidecar is the non-secret key-derivation metadata stored next to the database.
type Sidecar struct {
	Version  int    `json:"version"`
	KDF      string `json:"kdf"`
	Salt     string `json:"salt"`
	Time     uint32 `json:"time"`
	Memory   uint32 `json:"memory_kib"`
	Threads  uint8  `json:"threads"`
	KeyLen   uint32 `json:"key_len"`
	Checksum string `json:"checksum"`
}

type sidecarCore struct {
	Version int    `json:"version"`
	KDF     string `json:"kdf"`
	Salt    string `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

func (s Sidecar) core() sidecarCore {
	return sidecarCore{
		Version: s.Version,
		KDF:     s.KDF,
		Salt:    s.Salt,
		Time:    s.Time,
		Memory:  s.Memory,
		Threads: s.Threads,
		KeyLen:  s.KeyLen,
	}
}

func checksum(s Sidecar) string {
	payload, _ := json.Marshal(s.core())
	sum := blake2b.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// SidecarPath returns the sidecar path for a database path.
func SidecarPath(dbPath string) string {
	return dbPath + ".meta"
}

// CreateSidecar creates a new sidecar and returns the derived key.
func CreateSidecar(dbPath string, passphrase []byte) (Sidecar, []byte, error) {
	return CreateSidecarWithParams(dbPath, passphrase, DefaultTime, DefaultMemory, DefaultThreads)
}

// CreateSidecarWithParams is the testable form of CreateSidecar.
func CreateSidecarWithParams(dbPath string, passphrase []byte, kdfTime, kdfMemory uint32, kdfThreads uint8) (Sidecar, []byte, error) {
	if len(passphrase) < 12 {
		return Sidecar{}, nil, errors.New("passphrase must be at least 12 characters")
	}
	if err := validateParams(kdfTime, kdfMemory, kdfThreads, KeyLen); err != nil {
		return Sidecar{}, nil, err
	}

	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return Sidecar{}, nil, fmt.Errorf("generate salt: %w", err)
	}
	sidecar := Sidecar{
		Version: SidecarVersion,
		KDF:     KDFName,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Time:    kdfTime,
		Memory:  kdfMemory,
		Threads: kdfThreads,
		KeyLen:  KeyLen,
	}
	sidecar.Checksum = checksum(sidecar)
	if err := writeSidecar(SidecarPath(dbPath), sidecar); err != nil {
		return Sidecar{}, nil, err
	}
	key, err := DeriveKey(passphrase, sidecar)
	if err != nil {
		return Sidecar{}, nil, err
	}
	return sidecar, key, nil
}

// ReadSidecar reads and validates a sidecar.
func ReadSidecar(dbPath string) (Sidecar, error) {
	path := SidecarPath(dbPath)
	info, err := os.Stat(path)
	if err != nil {
		return Sidecar{}, fmt.Errorf("read sidecar: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Sidecar{}, fmt.Errorf("sidecar %s must not be accessible by group or others", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Sidecar{}, fmt.Errorf("read sidecar: %w", err)
	}
	var sidecar Sidecar
	if err := json.Unmarshal(data, &sidecar); err != nil {
		return Sidecar{}, fmt.Errorf("parse sidecar: %w", err)
	}
	if sidecar.Version != SidecarVersion {
		return Sidecar{}, fmt.Errorf("unsupported sidecar version %d", sidecar.Version)
	}
	if sidecar.KDF != KDFName {
		return Sidecar{}, fmt.Errorf("unsupported KDF %q", sidecar.KDF)
	}
	if err := validateParams(sidecar.Time, sidecar.Memory, sidecar.Threads, sidecar.KeyLen); err != nil {
		return Sidecar{}, err
	}
	if sidecar.Checksum == "" || subtle.ConstantTimeCompare([]byte(sidecar.Checksum), []byte(checksum(sidecar))) != 1 {
		return Sidecar{}, errors.New("sidecar checksum mismatch")
	}
	return sidecar, nil
}

// DeriveKey derives the SQLCipher key from the passphrase and sidecar.
func DeriveKey(passphrase []byte, sidecar Sidecar) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(sidecar.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("invalid salt length %d", len(salt))
	}
	key := argon2.IDKey(passphrase, salt, sidecar.Time, sidecar.Memory, sidecar.Threads, sidecar.KeyLen)
	if len(key) != KeyLen {
		return nil, fmt.Errorf("invalid derived key length %d", len(key))
	}
	return key, nil
}

func validateParams(kdfTime, kdfMemory uint32, kdfThreads uint8, keyLen uint32) error {
	if kdfTime < MinTime || kdfTime > MaxTime {
		return fmt.Errorf("argon2 time must be between %d and %d", MinTime, MaxTime)
	}
	if kdfMemory < MinMemory || kdfMemory > MaxMemory {
		return fmt.Errorf("argon2 memory must be between %d and %d KiB", MinMemory, MaxMemory)
	}
	if kdfThreads < MinThreads || kdfThreads > MaxThreads {
		return fmt.Errorf("argon2 threads must be between %d and %d", MinThreads, MaxThreads)
	}
	if keyLen != KeyLen {
		return fmt.Errorf("key length must be %d", KeyLen)
	}
	return nil
}

func writeSidecar(path string, sidecar Sidecar) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("sidecar already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create sidecar directory: %w", err)
	}
	payload, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	temp := path + ".tmp"
	if err := os.WriteFile(temp, payload, 0o600); err != nil {
		return fmt.Errorf("write sidecar: %w", err)
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("install sidecar: %w", err)
	}
	return nil
}

// Zero overwrites a byte slice.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RandomToken returns a 32-byte random token encoded as hex.
func RandomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// EqualToken compares tokens in constant time.
func EqualToken(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Now returns the canonical UTC timestamp used by the application.
func Now() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
