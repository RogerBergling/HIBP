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
	// Password is used only for manual, keyless fallback runs. It is never
	// stored in the database or written to logs.
	Password string
	// ProxyJump is an optional single-hop jump host.
	ProxyJump *JumpTarget
}

// JumpTarget is a single SSH jump host used to reach a target.
type JumpTarget struct {
	Address  string
	Port     int
	Username string
	KeyPath  string
	Password string
	HostKey  *HostKey
}

// HostKey identifies an SSH host key.
type HostKey struct {
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
}

// KeyError is returned when a host key is unknown or changed.
type KeyError struct {
	Kind                string `json:"kind"`
	Scope               string `json:"scope,omitempty"`
	KeyType             string `json:"key_type"`
	Fingerprint         string `json:"fingerprint"`
	ExpectedType        string `json:"expected_type,omitempty"`
	ExpectedFingerprint string `json:"expected_fingerprint,omitempty"`
}

func (e *KeyError) Error() string {
	label := "host"
	if e.Scope == "jump" {
		label = "jump host"
	}
	switch e.Kind {
	case "unknown":
		return fmt.Sprintf("%s key is unknown: %s %s", label, e.KeyType, e.Fingerprint)
	case "changed":
		return fmt.Sprintf("%s key changed: got %s %s, expected %s %s", label, e.KeyType, e.Fingerprint, e.ExpectedType, e.ExpectedFingerprint)
	default:
		return label + " key verification failed"
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

func authMethods(target Target) ([]ssh.AuthMethod, error) {
	if target.Password != "" {
		return []ssh.AuthMethod{
			ssh.Password(target.Password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for index := range answers {
					answers[index] = target.Password
				}
				return answers, nil
			}),
		}, nil
	}
	signer, err := loadSigner(target.KeyPath)
	if err != nil {
		return nil, err
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
}

func targetAddress(target Target) string {
	port := target.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(target.Address, strconv.Itoa(port))
}

func handshake(conn net.Conn, target Target, callback ssh.HostKeyCallback) (*ssh.Client, error) {
	auth, err := authMethods(target)
	if err != nil {
		return nil, err
	}
	address := targetAddress(target)
	config := &ssh.ClientConfig{
		User:            target.Username,
		Auth:            auth,
		HostKeyCallback: callback,
		Timeout:         10 * time.Second,
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(clientConn, chans, reqs), nil
}

func dialDirect(ctx context.Context, target Target, callback ssh.HostKeyCallback) (*ssh.Client, error) {
	address := targetAddress(target)
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}
	client, err := handshake(conn, target, callback)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

type connection struct {
	client *ssh.Client
	jump   *ssh.Client
}

func (c *connection) Close() error {
	var firstErr error
	if c.client != nil {
		firstErr = c.client.Close()
	}
	if c.jump != nil {
		if err := c.jump.Close(); firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func jumpHostKeyCallback(expected *HostKey, captured *HostKey) ssh.HostKeyCallback {
	callback := hostKeyCallback(expected, captured)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := callback(hostname, remote, key)
		var keyErr *KeyError
		if errors.As(err, &keyErr) {
			keyErr.Scope = "jump"
		}
		return err
	}
}

func jumpTarget(jump JumpTarget) Target {
	return Target{
		Address: jump.Address, Port: jump.Port, Username: jump.Username,
		KeyPath: jump.KeyPath, Password: jump.Password,
	}
}

func dial(ctx context.Context, target Target, callback ssh.HostKeyCallback) (*connection, error) {
	if target.ProxyJump == nil {
		client, err := dialDirect(ctx, target, callback)
		if err != nil {
			return nil, err
		}
		return &connection{client: client}, nil
	}
	jumpClient, err := dialDirect(ctx, jumpTarget(*target.ProxyJump), jumpHostKeyCallback(target.ProxyJump.HostKey, nil))
	if err != nil {
		return nil, err
	}
	proxyConn, err := jumpClient.Dial("tcp", targetAddress(target))
	if err != nil {
		_ = jumpClient.Close()
		return nil, fmt.Errorf("connect to %s through jump host: %w", targetAddress(target), err)
	}
	client, err := handshake(proxyConn, target, callback)
	if err != nil {
		_ = proxyConn.Close()
		_ = jumpClient.Close()
		return nil, err
	}
	return &connection{client: client, jump: jumpClient}, nil
}

// ProbeJump obtains a jump host key without trusting it.
func ProbeJump(ctx context.Context, jump JumpTarget) (HostKey, error) {
	var captured HostKey
	client, err := dialDirect(ctx, jumpTarget(jump), jumpHostKeyCallback(nil, &captured))
	if client != nil {
		_ = client.Close()
	}
	if captured.Fingerprint != "" {
		return captured, nil
	}
	if err == nil {
		return HostKey{}, errors.New("jump host did not present a key")
	}
	return HostKey{}, err
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
	return RunWithInput(ctx, target, expected, command, "", timeout)
}

// RunWithInput executes a fixed command and supplies input on stdin. It is used
// for sudo -S, so the sudo password never appears in argv, the environment, or
// the remote command string.
func RunWithInput(ctx context.Context, target Target, expected *HostKey, command, input string, timeout time.Duration) (string, int, error) {
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

	session, err := client.client.NewSession()
	if err != nil {
		return "", 0, fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()
	if input != "" {
		session.Stdin = strings.NewReader(input)
	}

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
