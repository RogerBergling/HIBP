//go:build !demo

package server

import "github.com/RogerBergling/hibp/internal/store"

// newDemoHooks returns nil in normal builds. The demo binary is built with the
// demo build tag and supplies the fake executor instead.
func newDemoHooks(_ *store.Store) demoHooks { return nil }
