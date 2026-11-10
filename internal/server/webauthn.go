package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webAuthnUser adapts a local HIBP account to the WebAuthn library. The user
// handle is the random database UUID, not the username, so renaming the account
// does not silently attach old passkeys to a different person.
type webAuthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webAuthnUser) WebAuthnName() string                       { return u.name }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Server) webAuthnUser(user store.User) (*webAuthnUser, error) {
	passkeys, err := s.store.ListPasskeys(user.ID)
	if err != nil {
		return nil, err
	}
	credentials := make([]webauthn.Credential, 0, len(passkeys))
	for _, passkey := range passkeys {
		var credential webauthn.Credential
		if err := json.Unmarshal([]byte(passkey.CredentialJSON), &credential); err != nil {
			return nil, fmt.Errorf("decode stored passkey %s: %w", passkey.ID, err)
		}
		if len(credential.ID) == 0 {
			credential.ID = passkey.CredentialID
		}
		credentials = append(credentials, credential)
	}
	return &webAuthnUser{
		id:          []byte(user.ID),
		name:        user.Username,
		displayName: user.Username,
		credentials: credentials,
	}, nil
}

// webAuthnConfig derives the relying-party ID and origin from the browser
// request. HIBP binds to loopback; the browser should use http://localhost.
// WebAuthn rejects IP-address RP IDs, so 127.0.0.1 gets a clear TOTP-only path.
func (s *Server) webAuthnConfig(r *http.Request) (string, string, error) {
	host := r.Host
	hostname := host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		hostname = parsed
	}
	hostname = strings.Trim(hostname, "[]")
	switch hostname {
	case "localhost":
	case "127.0.0.1", "::1":
		return "", "", errors.New("passkeys require http://localhost:<port>; 127.0.0.1 is not a valid WebAuthn RP ID")
	default:
		return "", "", errors.New("passkeys are only enabled for localhost")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return hostname, scheme + "://" + host, nil
}

func (s *Server) webAuthnForRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	rpID, origin, err := s.webAuthnConfig(r)
	if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "HIBP",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
	})
}

// webauthnCeremony stores the server-side challenge state between Begin and
// Finish. It is intentionally in memory: a restart invalidates in-flight
// ceremonies, which is the safe outcome. The browser simply starts again.
type webauthnCeremony struct {
	sessionID string
	userID    string
	kind      string
	data      webauthn.SessionData
	expires   time.Time
}

type ceremonyStore struct {
	mu      sync.Mutex
	entries map[string]webauthnCeremony
}

func newCeremonyStore() *ceremonyStore {
	return &ceremonyStore{entries: make(map[string]webauthnCeremony)}
}

func (c *ceremonyStore) put(sessionID, userID, kind string, data webauthn.SessionData) (string, error) {
	token, err := auth.NewSessionToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, id)
		}
	}
	c.entries[token] = webauthnCeremony{
		sessionID: sessionID,
		userID:    userID,
		kind:      kind,
		data:      data,
		expires:   now.Add(auth.PendingTTL),
	}
	return token, nil
}

func (c *ceremonyStore) take(id, sessionID, userID, kind string) (webauthn.SessionData, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	if !ok {
		return webauthn.SessionData{}, errors.New("passkey ceremony not found or expired")
	}
	delete(c.entries, id)
	if time.Now().After(entry.expires) {
		return webauthn.SessionData{}, errors.New("passkey ceremony expired")
	}
	if entry.sessionID != sessionID || entry.userID != userID || entry.kind != kind {
		return webauthn.SessionData{}, errors.New("passkey ceremony does not belong to this session")
	}
	return entry.data, nil
}
