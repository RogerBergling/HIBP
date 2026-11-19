package server

import (
	"context"
	"time"

	"github.com/RogerBergling/hibp/internal/mailer"
	"github.com/RogerBergling/hibp/internal/remote"
	"github.com/RogerBergling/hibp/internal/store"
)

// demoHooks is implemented only in demo builds. The production binary gets a
// nil implementation from demo_stub.go, so fake SSH, fake email, and fake
// network probes are not compiled into release artifacts.
type demoHooks interface {
	AuthInfo() map[string]any
	RunHelper(ctx context.Context, host store.Host, action, input string, timeout time.Duration) (string, int, error)
	TestHost(ctx context.Context, host store.Host, password string) error
	ProbeHost(ctx context.Context, host store.Host, password string) (remote.HostKey, error)
	ProbeJump(ctx context.Context, jump remote.JumpTarget) (remote.HostKey, error)
	InstallHelper(ctx context.Context, host store.Host, binary []byte, sudoPassword string) (string, error)
	EvaluateNetworkMonitor(ctx context.Context, monitor store.Monitor) (status, message string)
	SendEmail(cfg mailer.Config, to []string, subject, body string) error
	AllowTOTPReplay() bool
}
