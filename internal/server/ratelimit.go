package server

import (
	"sync"
	"time"
)

// attemptLimiter is a tiny in-memory fixed-window limiter. It is deliberately
// not shared across processes: HIBP is a single local server, and a restart
// clearing the counters is acceptable. The goal is to make password and TOTP
// guessing impractical, not to provide a distributed WAF.
type attemptLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	entries map[string]attemptEntry
}

type attemptEntry struct {
	count int
	reset time.Time
}

func newAttemptLimiter(limit int, window time.Duration) *attemptLimiter {
	return &attemptLimiter{limit: limit, window: window, entries: make(map[string]attemptEntry)}
}

func (l *attemptLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok || time.Now().After(entry.reset) {
		return true
	}
	return entry.count < l.limit
}

func (l *attemptLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	entry, ok := l.entries[key]
	if !ok || now.After(entry.reset) {
		entry = attemptEntry{reset: now.Add(l.window)}
	}
	entry.count++
	l.entries[key] = entry
}

func (l *attemptLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *attemptLimiter) retryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[key]
	if !ok {
		return 0
	}
	wait := time.Until(entry.reset)
	if wait < 0 {
		return 0
	}
	return wait
}
