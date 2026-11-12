package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func startTestSSHServer(t *testing.T, hostSigner, authorized ssh.Signer, allowDirectTCP bool) (string, func()) {
	t.Helper()
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if ssh.FingerprintSHA256(key) == ssh.FingerprintSHA256(authorized.PublicKey()) {
				return nil, nil
			}
			return nil, errors.New("unauthorized key")
		},
	}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer serverConn.Close()
				go ssh.DiscardRequests(reqs)
				for newChannel := range chans {
					switch newChannel.ChannelType() {
					case "session":
						channel, requests, err := newChannel.Accept()
						if err != nil {
							continue
						}
						go func() {
							defer channel.Close()
							for request := range requests {
								if request.Type != "exec" {
									_ = request.Reply(false, nil)
									continue
								}
								_ = request.Reply(true, nil)
								_, _ = channel.Write([]byte("target-ok\n"))
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							}
						}()
					case "direct-tcpip":
						if !allowDirectTCP {
							_ = newChannel.Reject(ssh.Prohibited, "direct-tcpip disabled")
							continue
						}
						var payload struct {
							Host       string
							Port       uint32
							OriginHost string
							OriginPort uint32
						}
						if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
							_ = newChannel.Reject(ssh.ConnectionFailed, "bad direct-tcpip payload")
							continue
						}
						destination, err := net.Dial("tcp", net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port))))
						if err != nil {
							_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
							continue
						}
						channel, requests, err := newChannel.Accept()
						if err != nil {
							_ = destination.Close()
							continue
						}
						go ssh.DiscardRequests(requests)
						go func() {
							defer destination.Close()
							defer channel.Close()
							_, _ = io.Copy(channel, destination)
						}()
						go func() {
							_, _ = io.Copy(destination, channel)
							_ = destination.Close()
						}()
					default:
						_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel")
					}
				}
			}()
		}
	}()
	address := listener.Addr().String()
	return address, func() {
		_ = listener.Close()
		<-done
	}
}

func splitAddress(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestRunThroughProxyJump(t *testing.T) {
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}
	jumpSigner := testSigner(t)
	targetSigner := testSigner(t)
	dir := t.TempDir()
	block, err := ssh.MarshalPrivateKey(clientPrivate, "test")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	targetAddress, stopTarget := startTestSSHServer(t, targetSigner, clientSigner, false)
	defer stopTarget()
	jumpAddress, stopJump := startTestSSHServer(t, jumpSigner, clientSigner, true)
	defer stopJump()

	targetHost, targetPort := splitAddress(t, targetAddress)
	jumpHost, jumpPort := splitAddress(t, jumpAddress)
	target := Target{
		Address: targetHost, Port: targetPort, Username: "ops", KeyPath: keyPath,
		ProxyJump: &JumpTarget{
			Address: jumpHost, Port: jumpPort, Username: "jump", KeyPath: keyPath,
			HostKey: &HostKey{KeyType: jumpSigner.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(jumpSigner.PublicKey())},
		},
	}
	expectedTarget := &HostKey{KeyType: targetSigner.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(targetSigner.PublicKey())}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, code, err := Run(ctx, target, expectedTarget, "echo ok", 5*time.Second)
	if err != nil {
		t.Fatalf("run through jump failed: %v", err)
	}
	if code != 0 || output != "target-ok\n" {
		t.Fatalf("unexpected result: code=%d output=%q", code, output)
	}

	probe, err := ProbeJump(ctx, *target.ProxyJump)
	if err != nil {
		t.Fatalf("probe jump failed: %v", err)
	}
	if probe.KeyType != target.ProxyJump.HostKey.KeyType || probe.Fingerprint != target.ProxyJump.HostKey.Fingerprint {
		t.Fatalf("unexpected jump probe: %+v", probe)
	}

	bad := target
	bad.ProxyJump = &JumpTarget{
		Address: jumpHost, Port: jumpPort, Username: "jump", KeyPath: keyPath,
		HostKey: &HostKey{KeyType: jumpSigner.PublicKey().Type(), Fingerprint: "SHA256:wrong"},
	}
	err = Test(ctx, bad, expectedTarget)
	var keyErr *KeyError
	if !errors.As(err, &keyErr) || keyErr.Scope != "jump" || keyErr.Kind != "changed" {
		t.Fatalf("expected changed jump key error, got %v", err)
	}
	unknown := target
	unknown.ProxyJump = &JumpTarget{Address: jumpHost, Port: jumpPort, Username: "jump", KeyPath: keyPath}
	err = Test(ctx, unknown, expectedTarget)
	if !errors.As(err, &keyErr) || keyErr.Scope != "jump" || keyErr.Kind != "unknown" {
		t.Fatalf("expected unknown jump key error, got %v", err)
	}
}
