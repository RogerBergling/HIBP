package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/RogerBergling/hibp/internal/auth"
	"github.com/RogerBergling/hibp/internal/crypto"
	"github.com/RogerBergling/hibp/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/skip2/go-qrcode"
)

const sessionCookieName = "hibp_session"

var errLoginRequired = errors.New("login required")

type authContextKey struct{}

type authContextValue struct {
	session *store.Session
	user    *store.User
}

func authFrom(r *http.Request) *authContextValue {
	if value, ok := r.Context().Value(authContextKey{}).(*authContextValue); ok {
		return value
	}
	return nil
}

func (s *Server) auditActor(r *http.Request) string {
	if value := authFrom(r); value != nil && value.user != nil {
		return value.user.Username
	}
	return "system"
}

type authUserView struct {
	Username     string `json:"username"`
	TOTPEnabled  bool   `json:"totp_enabled"`
	PasskeyCount int    `json:"passkey_count"`
	MFAEnabled   bool   `json:"mfa_enabled"`
}

func (s *Server) userView(user store.User) (authUserView, error) {
	count, err := s.store.CountPasskeys(user.ID)
	if err != nil {
		return authUserView{}, err
	}
	return authUserView{
		Username:     user.Username,
		TOTPEnabled:  user.TOTPEnabled,
		PasskeyCount: count,
		MFAEnabled:   user.TOTPEnabled || count > 0,
	}, nil
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	_ = s.store.DeleteExpiredSessions(crypto.Now())
	response := map[string]any{
		"setup_required":          false,
		"authenticated":           false,
		"mfa_required":            false,
		"mfa_enrollment_required": false,
	}
	_, _, waErr := s.webAuthnConfig(r)
	response["webauthn_available"] = waErr == nil
	if waErr != nil {
		response["webauthn_error"] = waErr.Error()
	}
	count, err := s.store.CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if count == 0 {
		response["setup_required"] = true
		writeJSON(w, http.StatusOK, response)
		return
	}
	session, user, err := s.loadSession(r)
	if err != nil {
		if _, cookieErr := r.Cookie(sessionCookieName); cookieErr == nil {
			s.clearSessionCookie(w, r)
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	view, err := s.userView(*user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response["user"] = view
	response["mfa_enrollment_required"] = !view.MFAEnabled
	if session.MFAVerified {
		response["authenticated"] = true
	} else {
		response["mfa_required"] = true
	}
	writeJSON(w, http.StatusOK, response)
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var request setupRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := auth.ValidateUsername(request.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := auth.ValidatePassword(request.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	count, err := s.store.CountUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if count > 0 {
		writeError(w, http.StatusConflict, "setup has already been completed")
		return
	}
	hash, err := auth.HashPassword(request.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	user, err := s.store.CreateUser(request.Username, hash)
	if err != nil {
		writeError(w, http.StatusConflict, "could not create the account: "+err.Error())
		return
	}
	if _, err := s.createSession(w, r, user.ID, false, auth.PendingTTL); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(user.Username, "setup", "user", user.ID, "account created; MFA enrollment required")
	view, _ := s.userView(user)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                      true,
		"mfa_required":            true,
		"mfa_enrollment_required": true,
		"user":                    view,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	username := strings.TrimSpace(request.Username)
	if username == "" || request.Password == "" {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	ipKey := "ip:" + clientIP(r)
	userKey := "user:" + strings.ToLower(username)
	if !s.loginIPLimiter.allow(ipKey) || !s.loginUserLimiter.allow(userKey) {
		w.Header().Set("Retry-After", "900")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "too many login attempts; try again later",
			"code":  "rate_limited",
		})
		return
	}
	user, err := s.store.GetUserByUsername(username)
	hash := s.dummyPasswordHash
	if err == nil {
		hash = user.PasswordHash
	}
	valid := auth.VerifyPassword(hash, request.Password)
	if err != nil || !valid {
		s.loginIPLimiter.fail(ipKey)
		s.loginUserLimiter.fail(userKey)
		_ = s.store.AddAudit("anonymous", "login-failed", "user", "", "invalid credentials")
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "invalid username or password",
			"code":  "invalid_credentials",
		})
		return
	}
	s.loginIPLimiter.reset(ipKey)
	s.loginUserLimiter.reset(userKey)
	if _, err := s.createSession(w, r, user.ID, false, auth.PendingTTL); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	view, err := s.userView(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(user.Username, "login-password", "user", user.ID, "password verified; MFA pending")
	_, _, waErr := s.webAuthnConfig(r)
	response := map[string]any{
		"ok":                      true,
		"mfa_required":            true,
		"mfa_enrollment_required": !view.MFAEnabled,
		"webauthn_available":      waErr == nil,
		"user":                    view,
	}
	if waErr != nil {
		response["webauthn_error"] = waErr.Error()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	if value != nil {
		_ = s.store.DeleteSession(value.session.ID)
		_ = s.store.AddAudit(value.user.Username, "logout", "user", value.user.ID, "")
	}
	s.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	view, err := s.userView(*value.user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _, waErr := s.webAuthnConfig(r)
	response := map[string]any{
		"user":               view,
		"mfa_verified":       value.session.MFAVerified,
		"webauthn_available": waErr == nil,
	}
	if waErr != nil {
		response["webauthn_error"] = waErr.Error()
	}
	writeJSON(w, http.StatusOK, response)
}

type mfaPasskeyView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
}

func (s *Server) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	passkeys, err := s.store.ListPasskeys(value.user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]mfaPasskeyView, 0, len(passkeys))
	for _, passkey := range passkeys {
		views = append(views, mfaPasskeyView{
			ID: passkey.ID, Name: passkey.Name, CreatedAt: passkey.CreatedAt, LastUsedAt: passkey.LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"username":     value.user.Username,
		"totp_enabled": value.user.TOTPEnabled,
		"totp_pending": value.user.TOTPPendingSecret != "",
		"passkeys":     views,
		"mfa_enabled":  value.user.TOTPEnabled || len(views) > 0,
	})
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	passkeyID := strings.TrimSpace(r.PathValue("id"))
	if passkeyID == "" {
		writeError(w, http.StatusBadRequest, "passkey id is required")
		return
	}
	passkeys, err := s.store.ListPasskeys(value.user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	found := false
	for _, passkey := range passkeys {
		if passkey.ID == passkeyID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}
	if len(passkeys) <= 1 && !value.user.TOTPEnabled {
		writeError(w, http.StatusConflict, "cannot remove the last MFA factor; configure TOTP or add another passkey first")
		return
	}
	if err := s.store.DeletePasskey(value.user.ID, passkeyID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(value.user.Username, "passkey-deleted", "user", value.user.ID, passkeyID)
	remaining, _ := s.store.CountPasskeys(value.user.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"passkey_count": remaining,
		"totp_enabled":  value.user.TOTPEnabled,
		"mfa_enabled":   value.user.TOTPEnabled || remaining > 0,
	})
}

func (s *Server) handleDeleteTOTP(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	if !value.user.TOTPEnabled {
		writeError(w, http.StatusBadRequest, "authenticator is not configured")
		return
	}
	count, err := s.store.CountPasskeys(value.user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if count == 0 {
		writeError(w, http.StatusConflict, "cannot remove the last MFA factor; add a passkey first")
		return
	}
	if err := s.store.ClearTOTP(value.user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.AddAudit(value.user.Username, "mfa-totp-removed", "user", value.user.ID, "authenticator removed")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"totp_enabled":  false,
		"passkey_count": count,
		"mfa_enabled":   count > 0,
	})
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

// totpEnrollmentAllowed reports whether a session that has not completed MFA
// may enroll a new TOTP factor. A password-only session may enroll TOTP only
// when the account has no other MFA factor. Without this check, a stolen
// password could add an attacker-controlled authenticator to a passkey-only
// account and then complete MFA with it.
func (s *Server) totpEnrollmentAllowed(value *authContextValue) (bool, error) {
	if value.session.MFAVerified {
		return true, nil
	}
	count, err := s.store.CountPasskeys(value.user.ID)
	if err != nil {
		return false, err
	}
	return count == 0 && !value.user.TOTPEnabled, nil
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	allowed, err := s.totpEnrollmentAllowed(value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "complete MFA before changing TOTP")
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.SetTOTPPendingSecret(value.user.ID, secret); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	uri := auth.TOTPURI("HIBP", value.user.Username, secret)
	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    uri,
		"qr_png": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	var request totpCodeRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	value := authFrom(r)
	key := "totp:" + value.user.ID
	if !s.mfaLimiter.allow(key) {
		w.Header().Set("Retry-After", "900")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "too many authenticator attempts; sign in again later",
			"code":  "rate_limited",
		})
		return
	}
	// A completed session may replace TOTP by verifying the pending secret.
	// A pending login must never be allowed to do that with only the password.
	target := ""
	pendingSecret := false
	switch {
	case value.session.MFAVerified && value.user.TOTPPendingSecret != "":
		target = value.user.TOTPPendingSecret
		pendingSecret = true
	case value.user.TOTPEnabled:
		target = value.user.TOTPSecret
	case value.user.TOTPPendingSecret != "":
		target = value.user.TOTPPendingSecret
		pendingSecret = true
	default:
		writeError(w, http.StatusBadRequest, "start authenticator setup first")
		return
	}
	step, ok := auth.ValidateTOTP(target, request.Code, time.Now())
	if !ok {
		s.mfaLimiter.fail(key)
		_ = s.store.AddAudit(value.user.Username, "mfa-failed", "user", value.user.ID, "invalid TOTP code")
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "invalid authenticator code",
			"code":  "invalid_code",
		})
		return
	}
	if !pendingSecret && step <= value.user.TOTPLastStep {
		s.mfaLimiter.fail(key)
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "authenticator code has already been used",
			"code":  "replayed_code",
		})
		return
	}
	if pendingSecret {
		if value.session.MFAVerified {
			if err := s.store.EnableTOTP(value.user.ID, target, step); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		} else {
			// Re-check atomically: a passkey may have been added after
			// /auth/totp/begin, and an older build may have left a pending
			// secret on a passkey-only account.
			enabled, err := s.store.EnableTOTPIfNoPasskeys(value.user.ID, target, step)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !enabled {
				writeError(w, http.StatusForbidden, "complete MFA before enrolling a new authenticator")
				return
			}
		}
	} else if err := s.store.SetTOTPLastStep(value.user.ID, step); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mfaLimiter.reset(key)
	if !value.session.MFAVerified {
		if err := s.completeMFA(w, r, value); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	_ = s.store.AddAudit(value.user.Username, "mfa-totp", "user", value.user.ID, "TOTP verified")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"mfa_verified": true,
		"totp_enabled": true,
	})
}

type passkeyRegisterFinishRequest struct {
	CeremonyID string          `json:"ceremony_id"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name"`
}

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	if !value.session.MFAVerified {
		count, err := s.store.CountPasskeys(value.user.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if count > 0 || value.user.TOTPEnabled {
			writeError(w, http.StatusForbidden, "complete MFA before adding a passkey")
			return
		}
	}
	wa, err := s.webAuthnForRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "passkey_unavailable"})
		return
	}
	waUser, err := s.webAuthnUser(*value.user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	creation, sessionData, err := wa.BeginRegistration(waUser)
	if err != nil {
		writeError(w, http.StatusBadRequest, "start passkey registration: "+err.Error())
		return
	}
	ceremonyID, err := s.ceremonies.put(value.session.ID, value.user.ID, "register", *sessionData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ceremony_id": ceremonyID,
		"publicKey":   creation.Response,
	})
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var request passkeyRegisterFinishRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if request.CeremonyID == "" || len(request.Credential) == 0 {
		writeError(w, http.StatusBadRequest, "ceremony_id and credential are required")
		return
	}
	value := authFrom(r)
	sessionData, err := s.ceremonies.take(request.CeremonyID, value.session.ID, value.user.ID, "register")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	wa, err := s.webAuthnForRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "passkey_unavailable"})
		return
	}
	waUser, err := s.webAuthnUser(*value.user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(request.Credential)
	if err != nil {
		writeError(w, http.StatusBadRequest, "parse passkey registration: "+err.Error())
		return
	}
	credential, err := wa.CreateCredential(waUser, sessionData, parsed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "verify passkey registration: "+err.Error())
		return
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := strings.TrimSpace(request.Name)
	if len(name) > 64 {
		name = name[:64]
	}
	if _, err := s.store.AddPasskey(value.user.ID, credential.ID, string(credentialJSON),
		int64(credential.Authenticator.SignCount), name); err != nil {
		writeError(w, http.StatusConflict, "could not store passkey: "+err.Error())
		return
	}
	if !value.session.MFAVerified {
		if err := s.completeMFA(w, r, value); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	_ = s.store.AddAudit(value.user.Username, "passkey-added", "user", value.user.ID, name)
	count, _ := s.store.CountPasskeys(value.user.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"mfa_verified":  true,
		"passkey_count": count,
	})
}

type passkeyLoginFinishRequest struct {
	CeremonyID string          `json:"ceremony_id"`
	Credential json.RawMessage `json:"credential"`
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	value := authFrom(r)
	if value.session.MFAVerified {
		writeError(w, http.StatusBadRequest, "already authenticated")
		return
	}
	count, err := s.store.CountPasskeys(value.user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if count == 0 {
		writeError(w, http.StatusBadRequest, "no passkeys are registered")
		return
	}
	wa, err := s.webAuthnForRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "passkey_unavailable"})
		return
	}
	waUser, err := s.webAuthnUser(*value.user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	assertion, sessionData, err := wa.BeginLogin(waUser)
	if err != nil {
		writeError(w, http.StatusBadRequest, "start passkey login: "+err.Error())
		return
	}
	ceremonyID, err := s.ceremonies.put(value.session.ID, value.user.ID, "login", *sessionData)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ceremony_id": ceremonyID,
		"publicKey":   assertion.Response,
	})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var request passkeyLoginFinishRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if request.CeremonyID == "" || len(request.Credential) == 0 {
		writeError(w, http.StatusBadRequest, "ceremony_id and credential are required")
		return
	}
	value := authFrom(r)
	if value.session.MFAVerified {
		writeError(w, http.StatusBadRequest, "already authenticated")
		return
	}
	sessionData, err := s.ceremonies.take(request.CeremonyID, value.session.ID, value.user.ID, "login")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	wa, err := s.webAuthnForRequest(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "code": "passkey_unavailable"})
		return
	}
	waUser, err := s.webAuthnUser(*value.user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(request.Credential)
	if err != nil {
		writeError(w, http.StatusBadRequest, "parse passkey login: "+err.Error())
		return
	}
	credential, err := wa.ValidateLogin(waUser, sessionData, parsed)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "passkey rejected: "+err.Error())
		return
	}
	if credential.Authenticator.CloneWarning {
		_ = s.store.AddAudit(value.user.Username, "passkey-clone-warning", "user", value.user.ID, "sign counter did not advance")
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "passkey sign counter did not advance; credential may be cloned",
			"code":  "passkey_clone_warning",
		})
		return
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.store.UpdatePasskeyUsage(value.user.ID, credential.ID, string(credentialJSON),
		int64(credential.Authenticator.SignCount)); err != nil {
		writeError(w, http.StatusUnauthorized, "passkey is no longer registered")
		return
	}
	if err := s.completeMFA(w, r, value); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mfaLimiter.reset("totp:" + value.user.ID)
	_ = s.store.AddAudit(value.user.Username, "login-passkey", "user", value.user.ID, "passkey verified")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"mfa_verified": true,
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return s.withSession(next, true)
}

func (s *Server) authPending(next http.HandlerFunc) http.HandlerFunc {
	return s.withSession(next, false)
}

func (s *Server) withSession(next http.HandlerFunc, requireMFA bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, user, err := s.loadSession(r)
		if err != nil {
			s.clearSessionCookie(w, r)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "sign in required",
				"code":  "login_required",
			})
			return
		}
		if requireMFA && !session.MFAVerified {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "two-factor authentication required",
				"code":  "mfa_required",
			})
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, &authContextValue{session: session, user: user})
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) loadSession(r *http.Request) (*store.Session, *store.User, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, nil, errLoginRequired
	}
	session, err := s.store.GetSessionByTokenHash(auth.HashSessionToken(cookie.Value))
	if err != nil {
		return nil, nil, errLoginRequired
	}
	now := time.Now().UTC()
	expires, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
	if err != nil || now.After(expires) {
		_ = s.store.DeleteSession(session.ID)
		return nil, nil, errLoginRequired
	}
	lastSeen, err := time.Parse(time.RFC3339Nano, session.LastSeenAt)
	if err != nil || now.Sub(lastSeen) > auth.SessionIdleTTL {
		_ = s.store.DeleteSession(session.ID)
		return nil, nil, errLoginRequired
	}
	user, err := s.store.GetUserByID(session.UserID)
	if err != nil {
		_ = s.store.DeleteSession(session.ID)
		return nil, nil, errLoginRequired
	}
	if now.Sub(lastSeen) >= time.Minute {
		session.LastSeenAt = crypto.Now()
		_ = s.store.TouchSession(session.ID, session.LastSeenAt)
	}
	return &session, &user, nil
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, userID string, mfaVerified bool, ttl time.Duration) (*store.Session, error) {
	token, err := auth.NewSessionToken()
	if err != nil {
		return nil, err
	}
	session, err := s.store.CreateSession(userID, auth.HashSessionToken(token), mfaVerified, ttl)
	if err != nil {
		return nil, err
	}
	s.setSessionCookie(w, r, token, ttl)
	return &session, nil
}

func (s *Server) completeMFA(w http.ResponseWriter, r *http.Request, value *authContextValue) error {
	if value.session.MFAVerified {
		return nil
	}
	if _, err := s.createSession(w, r, value.user.ID, true, auth.SessionTTL); err != nil {
		return err
	}
	return s.store.DeleteSession(value.session.ID)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(ttl.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   -1,
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
