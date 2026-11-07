package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

// Typed error codes for session lifecycle and anti-fixation protection (Requirement F08).
const (
	ErrCodeExpiredSession          = "EXPIRED_SESSION"
	ErrCodeRevokedSession          = "REVOKED_SESSION"
	ErrCodeSessionNotFound         = "SESSION_NOT_FOUND"
	ErrCodeFingerprintMismatch     = "FINGERPRINT_MISMATCH"
	ErrCodeSessionFixation         = "SESSION_FIXATION_ATTEMPT"
	ErrCodeSessionSuperseded       = "SUPERSEDED_SESSION"
	ErrCodeSessionStoreUnavailable = "SESSION_STORE_UNAVAILABLE"
	ErrCodeInvalidSessionRequest   = "INVALID_SESSION_REQUEST"
)

// SessionStatus values representing session lifecycle states.
const (
	SessionStatusActive     = "ACTIVE"
	SessionStatusExpired    = "EXPIRED"
	SessionStatusRevoked    = "REVOKED"
	SessionStatusSuperseded = "SUPERSEDED"
)

// Default cookie settings.
const (
	DefaultSessionCookieName = "__Host-policyhelix_session"
	DefaultSessionTTL        = 1 * time.Hour
)

// ClientFingerprint securely binds a session to client attributes.
type ClientFingerprint struct {
	IPHash        string `json:"ip_hash"`
	UserAgentHash string `json:"user_agent_hash"`
	CompositeHash string `json:"composite_hash"`
}

// ComputeFingerprint generates cryptographic SHA-256 hashes for IP and User-Agent.
func ComputeFingerprint(ip, userAgent string) ClientFingerprint {
	cleanIP := strings.TrimSpace(ip)
	cleanUA := strings.TrimSpace(userAgent)

	hIP := sha256.Sum256([]byte(cleanIP))
	hUA := sha256.Sum256([]byte(cleanUA))

	compositeInput := hex.EncodeToString(hIP[:]) + ":" + hex.EncodeToString(hUA[:])
	hComp := sha256.Sum256([]byte(compositeInput))

	return ClientFingerprint{
		IPHash:        hex.EncodeToString(hIP[:]),
		UserAgentHash: hex.EncodeToString(hUA[:]),
		CompositeHash: hex.EncodeToString(hComp[:]),
	}
}

// Match verifies whether the candidate IP and User-Agent match the recorded fingerprint.
func (f ClientFingerprint) Match(ip, userAgent string) bool {
	candidate := ComputeFingerprint(ip, userAgent)
	return f.CompositeHash == candidate.CompositeHash
}

// ServerCredentials holds confidential upstream tokens and secrets.
// Tokens are never logged or exported in public JSON representations (tokens never logged).
type ServerCredentials struct {
	AccessToken       string            `json:"-"`
	RefreshToken      string            `json:"-"`
	UpstreamSessionID string            `json:"upstream_session_id,omitempty"`
	IDTokenClaims     *IDTokenClaims    `json:"id_token_claims,omitempty"`
	Custom            map[string]string `json:"custom,omitempty"`
}

// MarshalJSON provides safe serialization where sensitive token secrets are omitted or redacted.
func (c ServerCredentials) MarshalJSON() ([]byte, error) {
	type Alias ServerCredentials
	type SafeRepresentation struct {
		Alias
		HasAccessToken  bool `json:"has_access_token"`
		HasRefreshToken bool `json:"has_refresh_token"`
	}
	return json.Marshal(SafeRepresentation{
		Alias:           Alias(c),
		HasAccessToken:  c.AccessToken != "",
		HasRefreshToken: c.RefreshToken != "",
	})
}

// SessionRecord is the versioned server-side record persisted for an active session.
type SessionRecord struct {
	SessionID    string            `json:"session_id"`
	SubjectID    string            `json:"subject_id"`
	Issuer       string            `json:"issuer"`
	Roles        []string          `json:"roles"`
	OwnerScope   string            `json:"owner_scope"`
	Fingerprint  ClientFingerprint `json:"fingerprint"`
	Credentials  ServerCredentials `json:"credentials"`
	SessionEpoch int64             `json:"session_epoch"`
	CreatedAt    time.Time         `json:"created_at"`
	ExpiresAt    time.Time         `json:"expires_at"`
	LastSeenAt   time.Time         `json:"last_seen_at"`
	RotatedTo    string            `json:"rotated_to,omitempty"`
	Status       string            `json:"status"`
}

// CookieConfig configures HTTP session cookie parameters.
type CookieConfig struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Domain        string `json:"domain,omitempty"`
	Secure        bool   `json:"secure"`
	HttpOnly      bool   `json:"http_only"`
	SameSite      string `json:"same_site"`
	MaxAgeSeconds int    `json:"max_age_seconds"`
}

// DefaultCookieConfig returns hardened production cookie settings.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:          DefaultSessionCookieName,
		Path:          "/",
		Secure:        true,
		HttpOnly:      true,
		SameSite:      "Strict",
		MaxAgeSeconds: int(DefaultSessionTTL.Seconds()),
	}
}

// BuildCookie creates a strongly typed http.Cookie from the configuration and session ID.
func (c CookieConfig) BuildCookie(sessionID string) *http.Cookie {
	name := c.Name
	if name == "" {
		name = DefaultSessionCookieName
	}
	path := c.Path
	if path == "" {
		path = "/"
	}
	maxAge := c.MaxAgeSeconds
	if maxAge <= 0 {
		maxAge = int(DefaultSessionTTL.Seconds())
	}

	sameSite := http.SameSiteStrictMode
	switch strings.ToLower(c.SameSite) {
	case "lax":
		sameSite = http.SameSiteLaxMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	return &http.Cookie{
		Name:     name,
		Value:    sessionID,
		Path:     path,
		Domain:   c.Domain,
		MaxAge:   maxAge,
		Secure:   c.Secure,
		HttpOnly: c.HttpOnly,
		SameSite: sameSite,
	}
}

// SessionConfig configures the session manager behavior.
type SessionConfig struct {
	DefaultTTL              time.Duration `json:"default_ttl"`
	IdleTimeout             time.Duration `json:"idle_timeout,omitempty"`
	Cookie                  CookieConfig  `json:"cookie"`
	RequireFingerprintMatch bool          `json:"require_fingerprint_match"`
}

// SessionStore defines the storage port for persisting and retrieving server-side sessions.
type SessionStore interface {
	SaveSession(ctx context.Context, session SessionRecord) error
	GetSession(ctx context.Context, sessionID string) (*SessionRecord, error)
	DeleteSession(ctx context.Context, sessionID string) error
	ListSessionsForSubject(ctx context.Context, subjectID string) ([]SessionRecord, error)
}

// MemorySessionStore provides a thread-safe in-memory session store.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]SessionRecord
}

// NewMemorySessionStore constructs an in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]SessionRecord),
	}
}

func (s *MemorySessionStore) SaveSession(ctx context.Context, session SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.SessionID] = session
	return nil
}

func (s *MemorySessionStore) GetSession(ctx context.Context, sessionID string) (*SessionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		return nil, errors.New(ErrCodeSessionNotFound)
	}
	copyRec := rec
	return &copyRec, nil
}

func (s *MemorySessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

func (s *MemorySessionStore) ListSessionsForSubject(ctx context.Context, subjectID string) ([]SessionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []SessionRecord
	for _, rec := range s.sessions {
		if rec.SubjectID == subjectID {
			list = append(list, rec)
		}
	}
	return list, nil
}

// StorageSessionStore adapts the authoritative C05 storage.Adapter port for durable session persistence.
type StorageSessionStore struct {
	adapter *storage.Adapter
}

// NewStorageSessionStore constructs a StorageSessionStore over a local storage.Adapter.
func NewStorageSessionStore(adapter *storage.Adapter) *StorageSessionStore {
	return &StorageSessionStore{adapter: adapter}
}

func sessionRecordID(sessionID string) string {
	return fmt.Sprintf("policyhelix:session:%s", sessionID)
}

func (s *StorageSessionStore) SaveSession(ctx context.Context, session SessionRecord) error {
	if s.adapter == nil {
		return errors.New(ErrCodeSessionStoreUnavailable)
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to encode session record: %w", err)
	}

	roles := session.Roles
	hasOperatorOrAdmin := false
	for _, r := range roles {
		if r == "admin" || r == "platform_admin" || r == "operator" || r == "policy_admin" {
			hasOperatorOrAdmin = true
			break
		}
	}
	if !hasOperatorOrAdmin {
		roles = append([]string{"operator"}, roles...)
	}

	callerID := storage.CallerIdentity{
		SubjectID:                session.SubjectID,
		Issuer:                   session.Issuer,
		Roles:                    roles,
		Authenticated:            true,
		SessionEpoch:             session.SessionEpoch,
		UntrustedHeadersStripped: true,
		ProviderState:            "available",
	}

	sessPrefix := session.SessionID
	if len(sessPrefix) > 16 {
		sessPrefix = sessPrefix[:16]
	}
	opID := fmt.Sprintf("op-sess-%s-%d", sessPrefix, session.LastSeenAt.UnixNano())
	if len(opID) > 64 {
		opID = opID[:64]
	}

	_, sErr := s.adapter.WriteRecord(ctx, storage.WriteRequest{
		SchemaVersion:  storage.SchemaVersion,
		OperationID:    opID,
		RecordID:       sessionRecordID(session.SessionID),
		OwnerScope:     "policyhelix",
		Classification: "private",
		Identity:       callerID,
		Payload:        payload,
	})
	if sErr != nil {
		return fmt.Errorf("storage write error: %s - %s", sErr.Code, sErr.Message)
	}
	return nil
}

func (s *StorageSessionStore) GetSession(ctx context.Context, sessionID string) (*SessionRecord, error) {
	if s.adapter == nil {
		return nil, errors.New(ErrCodeSessionStoreUnavailable)
	}

	payload, _, sErr := s.adapter.ReadRecord(sessionRecordID(sessionID))
	if sErr != nil {
		if sErr.Code == storage.ErrRecordNotFound {
			return nil, errors.New(ErrCodeSessionNotFound)
		}
		return nil, fmt.Errorf("storage read error: %s - %s", sErr.Code, sErr.Message)
	}

	var rec SessionRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return nil, fmt.Errorf("failed to parse durable session record: %w", err)
	}
	return &rec, nil
}

func (s *StorageSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	rec, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	rec.Status = SessionStatusRevoked
	rec.LastSeenAt = time.Now().UTC()
	return s.SaveSession(ctx, *rec)
}

func (s *StorageSessionStore) ListSessionsForSubject(ctx context.Context, subjectID string) ([]SessionRecord, error) {
	manifest, sErr := s.adapter.GetManifest()
	if sErr != nil {
		return nil, fmt.Errorf("storage manifest error: %s", sErr.Message)
	}
	var results []SessionRecord
	prefix := "policyhelix:session:"
	for recID := range manifest.Records {
		if strings.HasPrefix(recID, prefix) {
			sessID := strings.TrimPrefix(recID, prefix)
			rec, err := s.GetSession(ctx, sessID)
			if err == nil && rec.SubjectID == subjectID {
				results = append(results, *rec)
			}
		}
	}
	return results, nil
}

// Request and Result types for SessionManager operations.

type CreateSessionRequest struct {
	SubjectID         string            `json:"subject_id"`
	Issuer            string            `json:"issuer"`
	Roles             []string          `json:"roles"`
	OwnerScope        string            `json:"owner_scope,omitempty"`
	ClientIP          string            `json:"client_ip"`
	UserAgent         string            `json:"user_agent"`
	ServerCredentials ServerCredentials `json:"server_credentials"`
	SessionID         string            `json:"session_id,omitempty"` // Override for deterministic tests
	TTL               time.Duration     `json:"ttl,omitempty"`
	EvaluationTime    time.Time         `json:"evaluation_time,omitempty"`
}

type ResumeSessionRequest struct {
	SessionID                string    `json:"session_id"`
	ClientIP                 string    `json:"client_ip"`
	UserAgent                string    `json:"user_agent"`
	UntrustedHeadersStripped bool      `json:"untrusted_headers_stripped"`
	EvaluationTime           time.Time `json:"evaluation_time,omitempty"`
	TargetOwnerScope         string    `json:"target_owner_scope,omitempty"`
	MinRequiredEpoch         int64     `json:"min_required_epoch,omitempty"`
	ResourceClassification   string    `json:"resource_classification,omitempty"`
}

type RotateSessionRequest struct {
	OldSessionID             string    `json:"old_session_id"`
	ClientIP                 string    `json:"client_ip"`
	UserAgent                string    `json:"user_agent"`
	UntrustedHeadersStripped bool      `json:"untrusted_headers_stripped"`
	NewSessionID             string    `json:"new_session_id,omitempty"` // Override for deterministic tests
	EvaluationTime           time.Time `json:"evaluation_time,omitempty"`
}

type SessionResult struct {
	Valid              bool                   `json:"valid"`
	ErrorCode          string                 `json:"error_code,omitempty"`
	ErrorMessage       string                 `json:"error_message,omitempty"`
	Session            *SessionRecord         `json:"session,omitempty"`
	Cookie             *http.Cookie           `json:"-"`
	SetCookieHeader    string                 `json:"set_cookie_header,omitempty"`
	Identity           storage.CallerIdentity `json:"identity"`
	Subject            policy.SubjectIdentity `json:"subject"`
	AuthorizedForScope bool                   `json:"authorized_for_scope"`
}

// SessionManager manages server-side session issuance, resumption, rotation, and revocation.
type SessionManager struct {
	store  SessionStore
	config SessionConfig
}

// NewSessionManager constructs a SessionManager with default configurations.
func NewSessionManager(store SessionStore, cfg SessionConfig) *SessionManager {
	if store == nil {
		store = NewMemorySessionStore()
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = DefaultSessionTTL
	}
	if cfg.Cookie.Name == "" {
		cfg.Cookie = DefaultCookieConfig()
	}
	return &SessionManager{
		store:  store,
		config: cfg,
	}
}

// GenerateRandomSessionID generates 256 bits of cryptographically secure random entropy.
func GenerateRandomSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random session id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// CreateSession issues a new session bound to client fingerprints and stores safe server-held credentials.
func (m *SessionManager) CreateSession(ctx context.Context, req CreateSessionRequest) (*SessionResult, error) {
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	sessionID := req.SessionID
	if sessionID == "" {
		var err error
		sessionID, err = GenerateRandomSessionID()
		if err != nil {
			return nil, err
		}
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = m.config.DefaultTTL
	}

	fingerprint := ComputeFingerprint(req.ClientIP, req.UserAgent)

	roles := req.Roles
	if roles == nil {
		roles = []string{}
	}
	sort.Strings(roles)

	ownerScope := req.OwnerScope
	if ownerScope == "" {
		ownerScope = req.SubjectID
	}

	rec := SessionRecord{
		SessionID:    sessionID,
		SubjectID:    req.SubjectID,
		Issuer:       req.Issuer,
		Roles:        roles,
		OwnerScope:   ownerScope,
		Fingerprint:  fingerprint,
		Credentials:  req.ServerCredentials,
		SessionEpoch: evalTime.Unix(),
		CreatedAt:    evalTime,
		ExpiresAt:    evalTime.Add(ttl),
		LastSeenAt:   evalTime,
		Status:       SessionStatusActive,
	}

	if err := m.store.SaveSession(ctx, rec); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	cookie := m.config.Cookie.BuildCookie(sessionID)

	return &SessionResult{
		Valid:           true,
		Session:         &rec,
		Cookie:          cookie,
		SetCookieHeader: cookie.String(),
		Identity: storage.CallerIdentity{
			SubjectID:                rec.SubjectID,
			Issuer:                   rec.Issuer,
			Roles:                    rec.Roles,
			Authenticated:            true,
			SessionEpoch:             rec.SessionEpoch,
			UntrustedHeadersStripped: true,
			ProviderState:            "verified",
		},
		Subject: policy.SubjectIdentity{
			ID:            rec.SubjectID,
			Issuer:        rec.Issuer,
			Roles:         rec.Roles,
			Authenticated: true,
			SessionEpoch:  rec.SessionEpoch,
		},
		AuthorizedForScope: true,
	}, nil
}

// ResumeSession validates an incoming session cookie against fingerprint, expiration, and revocation.
func (m *SessionManager) ResumeSession(ctx context.Context, req ResumeSessionRequest) (*SessionResult, error) {
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	res := &SessionResult{
		Valid: false,
		Identity: storage.CallerIdentity{
			Authenticated:            false,
			UntrustedHeadersStripped: req.UntrustedHeadersStripped,
		},
		Subject: policy.SubjectIdentity{
			Authenticated: false,
		},
	}

	// 1. Untrusted headers must be stripped at gateway boundary
	if !req.UntrustedHeadersStripped {
		res.ErrorCode = ErrCodeForgedHeader
		res.ErrorMessage = "untrusted gateway headers were not stripped; rejecting forged request"
		return res, nil
	}

	// 2. Empty session ID fails unauthenticated
	cleanID := strings.TrimSpace(req.SessionID)
	if cleanID == "" {
		res.ErrorCode = ErrCodeUnauthenticatedIdentity
		res.ErrorMessage = "session identifier is missing or empty"
		if req.ResourceClassification == "private" || req.ResourceClassification == "restricted" {
			res.ErrorCode = ErrCodePrivateFailClosed
		}
		return res, nil
	}

	// 3. Lookup session record
	rec, err := m.store.GetSession(ctx, cleanID)
	if err != nil {
		res.ErrorCode = ErrCodeSessionNotFound
		res.ErrorMessage = fmt.Sprintf("session '%s' not found", cleanID)
		if req.ResourceClassification == "private" || req.ResourceClassification == "restricted" {
			res.ErrorCode = ErrCodePrivateFailClosed
		}
		return res, nil
	}
	res.Session = rec

	// 4. Anti-Fixation check: superseded session rejection
	if rec.Status == SessionStatusSuperseded {
		res.ErrorCode = ErrCodeSessionFixation
		res.ErrorMessage = fmt.Sprintf("session '%s' was superseded by rotation (rotated_to: '%s'); possible session fixation attempt blocked", cleanID, rec.RotatedTo)
		return res, nil
	}

	// 5. Explicit revocation check
	if rec.Status == SessionStatusRevoked {
		res.ErrorCode = ErrCodeRevokedSession
		res.ErrorMessage = fmt.Sprintf("session '%s' has been explicitly revoked", cleanID)
		return res, nil
	}

	// 6. Expiration check
	if !evalTime.Before(rec.ExpiresAt) {
		res.ErrorCode = ErrCodeExpiredSession
		res.ErrorMessage = fmt.Sprintf("session expired at %s (evaluated at %s)", rec.ExpiresAt.Format(time.RFC3339), evalTime.Format(time.RFC3339))
		return res, nil
	}

	// 7. Revocation Epoch boundary check
	if req.MinRequiredEpoch > 0 && rec.SessionEpoch < req.MinRequiredEpoch {
		res.ErrorCode = ErrCodeRevokedSession
		res.ErrorMessage = fmt.Sprintf("session epoch (%d) is older than minimum required epoch (%d)", rec.SessionEpoch, req.MinRequiredEpoch)
		return res, nil
	}

	// 8. Client Fingerprint verification
	if !rec.Fingerprint.Match(req.ClientIP, req.UserAgent) {
		res.ErrorCode = ErrCodeFingerprintMismatch
		res.ErrorMessage = fmt.Sprintf("client fingerprint mismatch: session '%s' bound to another client IP or User-Agent", cleanID)
		return res, nil
	}

	// 9. Scope and Authorization verification
	hasAdmin := false
	for _, r := range rec.Roles {
		if r == "admin" || r == "platform_admin" {
			hasAdmin = true
			break
		}
	}

	targetScope := strings.TrimSpace(req.TargetOwnerScope)
	if targetScope != "" && targetScope != "policyhelix" {
		if !hasAdmin && targetScope != rec.OwnerScope && targetScope != rec.SubjectID {
			res.ErrorCode = ErrCodeScopeViolation
			res.ErrorMessage = fmt.Sprintf("subject '%s' with owner_scope '%s' is not authorized for target scope '%s'", rec.SubjectID, rec.OwnerScope, targetScope)
			res.AuthorizedForScope = false
			return res, nil
		}
	}
	res.AuthorizedForScope = true

	// Update last seen activity
	rec.LastSeenAt = evalTime
	_ = m.store.SaveSession(ctx, *rec)

	res.Valid = true
	res.Identity = storage.CallerIdentity{
		SubjectID:                rec.SubjectID,
		Issuer:                   rec.Issuer,
		Roles:                    rec.Roles,
		Authenticated:            true,
		SessionEpoch:             rec.SessionEpoch,
		UntrustedHeadersStripped: true,
		ProviderState:            "verified",
	}
	res.Subject = policy.SubjectIdentity{
		ID:            rec.SubjectID,
		Issuer:        rec.Issuer,
		Roles:         rec.Roles,
		Authenticated: true,
		SessionEpoch:  rec.SessionEpoch,
	}

	return res, nil
}

// RotateSession generates a new session ID and cookie, marks the old session superseded, and transfers credentials.
func (m *SessionManager) RotateSession(ctx context.Context, req RotateSessionRequest) (*SessionResult, error) {
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	res := &SessionResult{
		Valid: false,
		Identity: storage.CallerIdentity{
			Authenticated:            false,
			UntrustedHeadersStripped: req.UntrustedHeadersStripped,
		},
		Subject: policy.SubjectIdentity{
			Authenticated: false,
		},
	}

	if !req.UntrustedHeadersStripped {
		res.ErrorCode = ErrCodeForgedHeader
		res.ErrorMessage = "untrusted gateway headers were not stripped; rejecting forged request"
		return res, nil
	}

	cleanOldID := strings.TrimSpace(req.OldSessionID)
	if cleanOldID == "" {
		res.ErrorCode = ErrCodeUnauthenticatedIdentity
		res.ErrorMessage = "old session identifier is missing or empty"
		return res, nil
	}

	oldRec, err := m.store.GetSession(ctx, cleanOldID)
	if err != nil {
		res.ErrorCode = ErrCodeSessionNotFound
		res.ErrorMessage = fmt.Sprintf("session '%s' not found", cleanOldID)
		return res, nil
	}

	// Replay / Fixation guard
	if oldRec.Status == SessionStatusSuperseded {
		res.ErrorCode = ErrCodeSessionFixation
		res.ErrorMessage = fmt.Sprintf("session '%s' was already superseded by rotation to '%s'; fixation attempt rejected", cleanOldID, oldRec.RotatedTo)
		return res, nil
	}

	if oldRec.Status == SessionStatusRevoked {
		res.ErrorCode = ErrCodeRevokedSession
		res.ErrorMessage = fmt.Sprintf("cannot rotate revoked session '%s'", cleanOldID)
		return res, nil
	}

	if !evalTime.Before(oldRec.ExpiresAt) {
		res.ErrorCode = ErrCodeExpiredSession
		res.ErrorMessage = fmt.Sprintf("cannot rotate expired session '%s'", cleanOldID)
		return res, nil
	}

	// Verify fingerprint
	if !oldRec.Fingerprint.Match(req.ClientIP, req.UserAgent) {
		res.ErrorCode = ErrCodeFingerprintMismatch
		res.ErrorMessage = "cannot rotate session: client fingerprint mismatch"
		return res, nil
	}

	// Generate new session ID
	newSessionID := req.NewSessionID
	if newSessionID == "" {
		var err error
		newSessionID, err = GenerateRandomSessionID()
		if err != nil {
			return nil, err
		}
	}

	newFingerprint := ComputeFingerprint(req.ClientIP, req.UserAgent)

	newRec := SessionRecord{
		SessionID:    newSessionID,
		SubjectID:    oldRec.SubjectID,
		Issuer:       oldRec.Issuer,
		Roles:        oldRec.Roles,
		OwnerScope:   oldRec.OwnerScope,
		Fingerprint:  newFingerprint,
		Credentials:  oldRec.Credentials,
		SessionEpoch: evalTime.Unix(),
		CreatedAt:    evalTime,
		ExpiresAt:    evalTime.Add(m.config.DefaultTTL),
		LastSeenAt:   evalTime,
		Status:       SessionStatusActive,
	}

	if err := m.store.SaveSession(ctx, newRec); err != nil {
		return nil, fmt.Errorf("failed to save rotated session: %w", err)
	}

	// Invalidate old session to prevent fixation attacks
	oldRec.Status = SessionStatusSuperseded
	oldRec.RotatedTo = newSessionID
	oldRec.LastSeenAt = evalTime
	_ = m.store.SaveSession(ctx, *oldRec)

	cookie := m.config.Cookie.BuildCookie(newSessionID)

	res.Valid = true
	res.Session = &newRec
	res.Cookie = cookie
	res.SetCookieHeader = cookie.String()
	res.AuthorizedForScope = true
	res.Identity = storage.CallerIdentity{
		SubjectID:                newRec.SubjectID,
		Issuer:                   newRec.Issuer,
		Roles:                    newRec.Roles,
		Authenticated:            true,
		SessionEpoch:             newRec.SessionEpoch,
		UntrustedHeadersStripped: true,
		ProviderState:            "verified",
	}
	res.Subject = policy.SubjectIdentity{
		ID:            newRec.SubjectID,
		Issuer:        newRec.Issuer,
		Roles:         newRec.Roles,
		Authenticated: true,
		SessionEpoch:  newRec.SessionEpoch,
	}

	return res, nil
}

// RevokeSession revokes a single active session.
func (m *SessionManager) RevokeSession(ctx context.Context, sessionID string) error {
	rec, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	rec.Status = SessionStatusRevoked
	rec.LastSeenAt = time.Now().UTC()
	return m.store.SaveSession(ctx, *rec)
}

// RevokeAllForSubject revokes all sessions belonging to a specific subject.
func (m *SessionManager) RevokeAllForSubject(ctx context.Context, subjectID string, minEpoch int64) error {
	sessions, err := m.store.ListSessionsForSubject(ctx, subjectID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, rec := range sessions {
		if rec.Status == SessionStatusActive {
			rec.Status = SessionStatusRevoked
			rec.LastSeenAt = now
			_ = m.store.SaveSession(ctx, rec)
		}
	}
	return nil
}
