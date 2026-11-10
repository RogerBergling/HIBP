// Package remote implements the SSH transport and host-key policy.
package remote

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Target is a host connection target.
type Target struct {
	Address  string
	Port     int
	Username string
	KeyPath  string
}

// HostKey identifies an SSH host key.
type HostKey struct {
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
}

// KeyError is returned when a host key is unknown or changed.
type KeyError struct {
	Kind                string `json:"kind"`
	KeyType             string `json:"key_type"`
	Fingerprint         string `json:"fingerprint"`
	ExpectedType        string `json:"expected_type,omitempty"`
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
}

func (e *KeyError) Error() string {
	switch e.Kind {
	case "unknown":
		return fmt.Sprintf("unknown host key: %s %s", e.KeyType, e.Fingerprint)
	case "changed":
		return fmt.Sprintf("host key changed: got %s %s, expected %s %s", e.KeyType, e.Fingerprint, e.ExpectedType, e.ExpectedFingerprint)
	default:
		return "host key verification failed"
	}
}

func loadSigner(path string) (ssh.Signer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("SSH key path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("SSH key %s must not be accessible by group or others", abs)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("passphrase-protected SSH keys are not supported in this build; use ssh-agent or an unencrypted key with 0600 permissions")
		}
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}
	return signer, nil
}

func hostKeyCallback(expected *HostKey, captured *HostKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		actual := HostKey{KeyType: key.Type(), Fingerprint: ssh.FingerprintSHA256(key)}
		if captured != nil {
			*captured = actual
		}
		if expected == nil {
			return &KeyError{Kind: "unknown", KeyType: actual.KeyType, Fingerprint: actual.Fingerprint}
		}
		if expected.KeyType != actual.KeyType || expected.Fingerprint != actual.Fingerprint {
			return &KeyError{
				Kind:                "changed",
				KeyType:             actual.KeyType,
				Fingerprint:         actual.Fingerprint,
				ExpectedType:        expected.KeyType,
				ExpectedFingerprint: expected.Fingerprint,
			}
		}
		return nil
	}
}

func dial(ctx context.Context, target Target, callback ssh.HostKeyCallback) (*ssh.Client, error) {
	signer, err := loadSigner(target.KeyPath)
	if err != nil {
		return nil, err
	}
	port := target.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(target.Address, strconv.Itoa(port))
	config := &ssh.ClientConfig{
		User:            target.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: callback,
		Timeout:         10 * time.Second,
	}

	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

// Probe obtains the host key without trusting it. It is used by the trust flow.
func Probe(ctx context.Context, target Target) (HostKey, error) {
	var captured HostKey
	client, err := dial(ctx, target, hostKeyCallback(nil, &captured))
	if client != nil {
		_ = client.Close()
	}
	if captured.Fingerprint != "" {
		return captured, nil
	}
	if err == nil {
		return HostKey{}, errors.New("host did not present a key")
	}
	return HostKey{}, err
}

// Test verifies the host key and authenticates.
func Test(ctx context.Context, target Target, expected *HostKey) error {
	client, err := dial(ctx, target, hostKeyCallback(expected, nil))
	if client != nil {
		_ = client.Close()
	}
	return err
}

// Run executes a fixed command over SSH. The command string must not contain
// user-controlled fragments; callers use it for the fixed helper actions.
func Run(ctx context.Context, target Target, expected *HostKey, command string, timeout time.Duration) (string, int, error) {
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := dial(runCtx, target, hostKeyCallback(expected, nil))
	if err != nil {
		return "", 0, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", 0, fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := session.CombinedOutput(command)
		done <- result{output: output, err: err}
	}()

	select {
	case <-runCtx.Done():
		_ = session.Close()
		_ = client.Close()
		return "", 0, fmt.Errorf("command timed out after %s", timeout)
	case res := <-done:
		output := string(res.output)
		if res.err == nil {
			return output, 0, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(res.err, &exitErr) {
			return output, exitErr.ExitStatus(), nil
		}
		return output, 0, res.err
	}
}
