package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/storage"
)

// Bounded stale authorization window invariants (Requirement F09 / C15).
const (
	MaxRevocationStaleWindow = 30 * time.Second
	DefaultRevocationWindow  = 30 * time.Second

	ErrCodeWidenedPermissionDenied   = "WIDENED_PERMISSION_DENIED"
	ErrCodePrivateResourceFailClosed = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrCodeReplayedIdentity          = "REPLAYED_IDENTITY_REJECTED"
	ErrCodeStaleWindowExceeded       = "STALE_AUTHORIZATION_WINDOW_EXCEEDED"
	ErrCodeInvalidRevocationRequest  = "INVALID_REVOCATION_REQUEST"
)

var (
	ErrRevocationNotFound = errors.New("revocation record not found")
)

// RevocationRecord represents a durable session, subject-epoch, or scope-epoch revocation entry.
type RevocationRecord struct {
	SessionID        string    `json:"session_id,omitempty"`
	SubjectID        string    `json:"subject_id,omitempty"`
	OwnerScope       string    `json:"owner_scope,omitempty"`
	MinRequiredEpoch int64     `json:"min_required_epoch,omitempty"`
	RevokedAt        time.Time `json:"revoked_at"`
	DeadlineAt       time.Time `json:"deadline_at"`
	Reason           string    `json:"reason"`
	RevokedBy        string    `json:"revoked_by,omitempty"`
}

// RevocationEvent is returned when a session, subject, or scope is revoked.
type RevocationEvent struct {
	TargetType       string    `json:"target_type"`
	TargetID         string    `json:"target_id"`
	MinRequiredEpoch int64     `json:"min_required_epoch,omitempty"`
	RevokedAt        time.Time `json:"revoked_at"`
	DeadlineAt       time.Time `json:"deadline_at"`
	MaxStaleSeconds  int       `json:"max_stale_seconds"`
	Reason           string    `json:"reason"`
	RevokedBy        string    `json:"revoked_by,omitempty"`
}

// RevocationStore defines the persistence interface for bounded-window revocation records and monotonic epochs.
type RevocationStore interface {
	SaveSessionRevocation(ctx context.Context, record RevocationRecord) error
	GetSessionRevocation(ctx context.Context, sessionID string) (*RevocationRecord, error)
	SaveSubjectRevocation(ctx context.Context, record RevocationRecord) error
	GetSubjectRevocation(ctx context.Context, subjectID string) (*RevocationRecord, error)
	SaveScopeRevocation(ctx context.Context, record RevocationRecord) error
	GetScopeRevocation(ctx context.Context, ownerScope string) (*RevocationRecord, error)
}

// MemoryRevocationStore is an in-memory thread-safe implementation of RevocationStore.
type MemoryRevocationStore struct {
	mu       sync.RWMutex
	sessions map[string]RevocationRecord
	subjects map[string]RevocationRecord
	scopes   map[string]RevocationRecord
}

// NewMemoryRevocationStore creates a new in-memory revocation store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{
		sessions: make(map[string]RevocationRecord),
		subjects: make(map[string]RevocationRecord),
		scopes:   make(map[string]RevocationRecord),
	}
}

func (m *MemoryRevocationStore) SaveSessionRevocation(_ context.Context, record RevocationRecord) error {
	if strings.TrimSpace(record.SessionID) == "" {
		return errors.New("session_id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[record.SessionID] = record
	return nil
}

func (m *MemoryRevocationStore) GetSessionRevocation(_ context.Context, sessionID string) (*RevocationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.sessions[sessionID]
	if !ok {
		return nil, ErrRevocationNotFound
	}
	cp := rec
	return &cp, nil
}

func (m *MemoryRevocationStore) SaveSubjectRevocation(_ context.Context, record RevocationRecord) error {
	if strings.TrimSpace(record.SubjectID) == "" {
		return errors.New("subject_id is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.subjects[record.SubjectID]
	if ok && existing.MinRequiredEpoch > record.MinRequiredEpoch {
		record.MinRequiredEpoch = existing.MinRequiredEpoch
	}
	m.subjects[record.SubjectID] = record
	return nil
}

func (m *MemoryRevocationStore) GetSubjectRevocation(_ context.Context, subjectID string) (*RevocationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.subjects[subjectID]
	if !ok {
		return nil, ErrRevocationNotFound
	}
	cp := rec
	return &cp, nil
}

func (m *MemoryRevocationStore) SaveScopeRevocation(_ context.Context, record RevocationRecord) error {
	if strings.TrimSpace(record.OwnerScope) == "" {
		return errors.New("owner_scope is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.scopes[record.OwnerScope]
	if ok && existing.MinRequiredEpoch > record.MinRequiredEpoch {
		record.MinRequiredEpoch = existing.MinRequiredEpoch
	}
	m.scopes[record.OwnerScope] = record
	return nil
}

func (m *MemoryRevocationStore) GetScopeRevocation(_ context.Context, ownerScope string) (*RevocationRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.scopes[ownerScope]
	if !ok {
		return nil, ErrRevocationNotFound
	}
	cp := rec
	return &cp, nil
}

// StorageRevocationStore persists revocation records to the local authoritative storage port (ADR-0003).
type StorageRevocationStore struct {
	adapter *storage.Adapter
	cache   *MemoryRevocationStore
}

// NewStorageRevocationStore creates a durable revocation store backed by storage.Adapter.
func NewStorageRevocationStore(adapter *storage.Adapter) *StorageRevocationStore {
	return &StorageRevocationStore{
		adapter: adapter,
		cache:   NewMemoryRevocationStore(),
	}
}

func (s *StorageRevocationStore) writeDurable(ctx context.Context, recordID string, rec RevocationRecord) error {
	if s.adapter == nil {
		return errors.New("storage adapter is nil")
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	actor := rec.RevokedBy
	if strings.TrimSpace(actor) == "" {
		actor = "system:revocation-enforcer"
	}
	opID := fmt.Sprintf("op-rev-%s-%d", recordID, time.Now().UTC().UnixNano())
	if len(opID) > 64 {
		opID = opID[:64]
	}
	_, sErr := s.adapter.WriteRecord(ctx, storage.WriteRequest{
		SchemaVersion:  storage.SchemaVersion,
		OperationID:    opID,
		RecordID:       "policyhelix:" + recordID,
		OwnerScope:     "policyhelix",
		Classification: "private",
		Identity: storage.CallerIdentity{
			SubjectID:                actor,
			Issuer:                   "https://auth.policyhelix.local",
			Roles:                    []string{"operator", "admin"},
			Authenticated:            true,
			SessionEpoch:             rec.RevokedAt.Unix(),
			UntrustedHeadersStripped: true,
			ProviderState:            "available",
		},
		Payload: payload,
	})
	if sErr != nil {
		return fmt.Errorf("storage write error: %s - %s", sErr.Code, sErr.Message)
	}
	return nil
}

func (s *StorageRevocationStore) readDurable(_ context.Context, recordID string) (*RevocationRecord, error) {
	if s.adapter == nil {
		return nil, errors.New("storage adapter is nil")
	}
	payload, _, sErr := s.adapter.ReadRecord("policyhelix:" + recordID)
	if sErr != nil {
		if sErr.Code == storage.ErrRecordNotFound {
			return nil, ErrRevocationNotFound
		}
		return nil, fmt.Errorf("storage read error: %s - %s", sErr.Code, sErr.Message)
	}
	var rec RevocationRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *StorageRevocationStore) SaveSessionRevocation(ctx context.Context, record RevocationRecord) error {
	if strings.TrimSpace(record.SessionID) == "" {
		return errors.New("session_id is required")
	}
	if err := s.writeDurable(ctx, "revoke:session:"+record.SessionID, record); err != nil {
		return err
	}
	return s.cache.SaveSessionRevocation(ctx, record)
}

func (s *StorageRevocationStore) GetSessionRevocation(ctx context.Context, sessionID string) (*RevocationRecord, error) {
	if rec, err := s.cache.GetSessionRevocation(ctx, sessionID); err == nil {
		return rec, nil
	}
	rec, err := s.readDurable(ctx, "revoke:session:"+sessionID)
	if err != nil {
		return nil, err
	}
	_ = s.cache.SaveSessionRevocation(ctx, *rec)
	return rec, nil
}

func (s *StorageRevocationStore) SaveSubjectRevocation(ctx context.Context, record RevocationRecord) error {
	if strings.TrimSpace(record.SubjectID) == "" {
		return errors.New("subject_id is required")
	}
	if existing, err := s.GetSubjectRevocation(ctx, record.SubjectID); err == nil && existing != nil {
		if existing.MinRequiredEpoch > record.MinRequiredEpoch {
			record.MinRequiredEpoch = existing.MinRequiredEpoch
		}
	}
	if err := s.writeDurable(ctx, "revoke:subject:"+record.SubjectID, record); err != nil {
		return err
	}
	return s.cache.SaveSubjectRevocation(ctx, record)
}

func (s *StorageRevocationStore) GetSubjectRevocation(ctx context.Context, subjectID string) (*RevocationRecord, error) {
	if rec, err := s.cache.GetSubjectRevocation(ctx, subjectID); err == nil {
		return rec, nil
	}
	rec, err := s.readDurable(ctx, "revoke:subject:"+subjectID)
	if err != nil {
		return nil, err
	}
	_ = s.cache.SaveSubjectRevocation(ctx, *rec)
	return rec, nil
}

func (s *StorageRevocationStore) SaveScopeRevocation(ctx context.Context, record RevocationRecord) error {
	if strings.TrimSpace(record.OwnerScope) == "" {
		return errors.New("owner_scope is required")
	}
	if existing, err := s.GetScopeRevocation(ctx, record.OwnerScope); err == nil && existing != nil {
		if existing.MinRequiredEpoch > record.MinRequiredEpoch {
			record.MinRequiredEpoch = existing.MinRequiredEpoch
		}
	}
	if err := s.writeDurable(ctx, "revoke:scope:"+record.OwnerScope, record); err != nil {
		return err
	}
	return s.cache.SaveScopeRevocation(ctx, record)
}

func (s *StorageRevocationStore) GetScopeRevocation(ctx context.Context, ownerScope string) (*RevocationRecord, error) {
	if rec, err := s.cache.GetScopeRevocation(ctx, ownerScope); err == nil {
		return rec, nil
	}
	rec, err := s.readDurable(ctx, "revoke:scope:"+ownerScope)
	if err != nil {
		return nil, err
	}
	_ = s.cache.SaveScopeRevocation(ctx, *rec)
	return rec, nil
}

// RevocationConfig configures bounded stale authorization window enforcement.
type RevocationConfig struct {
	StaleWindowSeconds int      `json:"stale_window_seconds,omitempty"`
	AllowedPaths       []string `json:"allowed_paths,omitempty"`
	AllowedProviders   []string `json:"allowed_providers,omitempty"`
}

type workerAuthLease struct {
	session    SessionRecord
	verifiedAt time.Time
	expiresAt  time.Time
}

// RevocationEnforcer enforces the <=30-second bounded stale authorization window and fail-closed access checks.
type RevocationEnforcer struct {
	sessionMgr  *SessionManager
	revStore    RevocationStore
	staleWindow time.Duration
	config      RevocationConfig

	mu          sync.RWMutex
	leases      map[string]workerAuthLease
	usedReqIDs  map[string]time.Time
	revokedFast map[string]RevocationRecord
}

// NewRevocationEnforcer initializes a RevocationEnforcer and rejects stale windows exceeding 30 seconds.
func NewRevocationEnforcer(sessionMgr *SessionManager, revStore RevocationStore, cfg RevocationConfig) (*RevocationEnforcer, error) {
	if sessionMgr == nil {
		return nil, errors.New("session manager is required")
	}
	if revStore == nil {
		revStore = NewMemoryRevocationStore()
	}

	window := DefaultRevocationWindow
	if cfg.StaleWindowSeconds < 0 {
		return nil, fmt.Errorf("%s: stale_window_seconds cannot be negative (%d)", ErrCodeStaleWindowExceeded, cfg.StaleWindowSeconds)
	}
	if cfg.StaleWindowSeconds > 0 {
		window = time.Duration(cfg.StaleWindowSeconds) * time.Second
	}
	if window > MaxRevocationStaleWindow {
		return nil, fmt.Errorf("%s: configured stale window %v exceeds maximum 30-second bound (%v)", ErrCodeStaleWindowExceeded, window, MaxRevocationStaleWindow)
	}

	return &RevocationEnforcer{
		sessionMgr:  sessionMgr,
		revStore:    revStore,
		staleWindow: window,
		config:      cfg,
		leases:      make(map[string]workerAuthLease),
		usedReqIDs:  make(map[string]time.Time),
		revokedFast: make(map[string]RevocationRecord),
	}, nil
}

// StaleWindow returns the active bounded authorization window duration (guaranteed <= 30s).
func (e *RevocationEnforcer) StaleWindow() time.Duration {
	return e.staleWindow
}

// PrimeWorkerLease seeds a worker authorization lease bounded strictly by the configured <=30s stale window.
func (e *RevocationEnforcer) PrimeWorkerLease(sess SessionRecord, verifiedAt time.Time) {
	if verifiedAt.IsZero() {
		verifiedAt = time.Now().UTC()
	} else {
		verifiedAt = verifiedAt.UTC()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.leases[sess.SessionID] = workerAuthLease{
		session:    sess,
		verifiedAt: verifiedAt,
		expiresAt:  verifiedAt.Add(e.staleWindow),
	}
}

// RevokeSession explicitly revokes a session, persists the revocation, and invalidates worker leases.
func (e *RevocationEnforcer) RevokeSession(ctx context.Context, sessionID, reason, actor string, evalTime time.Time) (*RevocationEvent, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, fmt.Errorf("%s: session_id is required", ErrCodeInvalidRevocationRequest)
	}
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}
	if strings.TrimSpace(reason) == "" {
		reason = "explicit_session_revocation"
	}

	var subjectID, ownerScope string
	if sess, err := e.sessionMgr.store.GetSession(ctx, sessionID); err == nil && sess != nil {
		subjectID = sess.SubjectID
		ownerScope = sess.OwnerScope
	}
	_ = e.sessionMgr.RevokeSession(ctx, sessionID)

	deadline := evalTime.Add(e.staleWindow)
	rec := RevocationRecord{
		SessionID:  sessionID,
		SubjectID:  subjectID,
		OwnerScope: ownerScope,
		RevokedAt:  evalTime,
		DeadlineAt: deadline,
		Reason:     reason,
		RevokedBy:  actor,
	}
	if err := e.revStore.SaveSessionRevocation(ctx, rec); err != nil {
		return nil, err
	}

	e.mu.Lock()
	delete(e.leases, sessionID)
	e.revokedFast[sessionID] = rec
	e.mu.Unlock()

	return &RevocationEvent{
		TargetType:      "session",
		TargetID:        sessionID,
		RevokedAt:       evalTime,
		DeadlineAt:      deadline,
		MaxStaleSeconds: int(e.staleWindow.Seconds()),
		Reason:          reason,
		RevokedBy:       actor,
	}, nil
}

// RevokeSubject advances the monotonic subject revocation epoch so all sessions with SessionEpoch < minEpoch stop within <=30s.
func (e *RevocationEnforcer) RevokeSubject(ctx context.Context, subjectID string, minEpoch int64, reason, actor string, evalTime time.Time) (*RevocationEvent, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, fmt.Errorf("%s: subject_id is required", ErrCodeInvalidRevocationRequest)
	}
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}
	if minEpoch <= 0 {
		minEpoch = evalTime.Unix() + 1
	}
	if strings.TrimSpace(reason) == "" {
		reason = "subject_epoch_revocation"
	}

	deadline := evalTime.Add(e.staleWindow)
	rec := RevocationRecord{
		SubjectID:        subjectID,
		MinRequiredEpoch: minEpoch,
		RevokedAt:        evalTime,
		DeadlineAt:       deadline,
		Reason:           reason,
		RevokedBy:        actor,
	}
	if err := e.revStore.SaveSubjectRevocation(ctx, rec); err != nil {
		return nil, err
	}

	e.mu.Lock()
	for sid, lease := range e.leases {
		if lease.session.SubjectID == subjectID && lease.session.SessionEpoch < minEpoch {
			delete(e.leases, sid)
		}
	}
	e.mu.Unlock()

	return &RevocationEvent{
		TargetType:       "subject",
		TargetID:         subjectID,
		MinRequiredEpoch: minEpoch,
		RevokedAt:        evalTime,
		DeadlineAt:       deadline,
		MaxStaleSeconds:  int(e.staleWindow.Seconds()),
		Reason:           reason,
		RevokedBy:        actor,
	}, nil
}

// RevokeScope advances the monotonic owner_scope revocation epoch so all prior sessions in that scope stop within <=30s.
func (e *RevocationEnforcer) RevokeScope(ctx context.Context, ownerScope string, minEpoch int64, reason, actor string, evalTime time.Time) (*RevocationEvent, error) {
	ownerScope = strings.TrimSpace(ownerScope)
	if ownerScope == "" {
		return nil, fmt.Errorf("%s: owner_scope is required", ErrCodeInvalidRevocationRequest)
	}
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}
	if minEpoch <= 0 {
		minEpoch = evalTime.Unix() + 1
	}
	if strings.TrimSpace(reason) == "" {
		reason = "scope_epoch_revocation"
	}

	deadline := evalTime.Add(e.staleWindow)
	rec := RevocationRecord{
		OwnerScope:       ownerScope,
		MinRequiredEpoch: minEpoch,
		RevokedAt:        evalTime,
		DeadlineAt:       deadline,
		Reason:           reason,
		RevokedBy:        actor,
	}
	if err := e.revStore.SaveScopeRevocation(ctx, rec); err != nil {
		return nil, err
	}

	e.mu.Lock()
	for sid, lease := range e.leases {
		if lease.session.OwnerScope == ownerScope && lease.session.SessionEpoch < minEpoch {
			delete(e.leases, sid)
		}
	}
	e.mu.Unlock()

	return &RevocationEvent{
		TargetType:       "scope",
		TargetID:         ownerScope,
		MinRequiredEpoch: minEpoch,
		RevokedAt:        evalTime,
		DeadlineAt:       deadline,
		MaxStaleSeconds:  int(e.staleWindow.Seconds()),
		Reason:           reason,
		RevokedBy:        actor,
	}, nil
}

// AccessCheckRequest represents an authorization and bounded-revocation check for a sensitive or private resource.
type AccessCheckRequest struct {
	RequestID                string            `json:"request_id,omitempty"`
	SingleUseRequest         bool              `json:"single_use_request,omitempty"`
	SessionID                string            `json:"session_id"`
	ClientIP                 string            `json:"client_ip"`
	UserAgent                string            `json:"user_agent"`
	UntrustedHeadersStripped bool              `json:"untrusted_headers_stripped"`
	ForgedHeaders            map[string]string `json:"forged_headers,omitempty"`
	ProviderUnavailable      bool              `json:"provider_unavailable,omitempty"`
	ProviderState            string            `json:"provider_state,omitempty"`
	TargetOwnerScope         string            `json:"target_owner_scope,omitempty"`
	ObjectScope              string            `json:"object_scope,omitempty"`
	RequestedPath            string            `json:"requested_path,omitempty"`
	RequestedProvider        string            `json:"requested_provider,omitempty"`
	ResourceClassification   string            `json:"resource_classification,omitempty"`
	EvaluationTime           time.Time         `json:"evaluation_time,omitempty"`
}

// AccessCheckResult captures the fail-closed decision, side-effect guard, and bounded revocation window telemetry.
type AccessCheckResult struct {
	Allow               bool                    `json:"allow"`
	Valid               bool                    `json:"valid"`
	Status              string                  `json:"status"`
	ErrorCode           string                  `json:"error_code,omitempty"`
	ErrorMessage        string                  `json:"error_message,omitempty"`
	SideEffectsExecuted bool                    `json:"side_effects_executed"`
	Revoked             bool                    `json:"revoked"`
	StoppedWithinBound  bool                    `json:"stopped_within_bound"`
	MaxStaleSeconds     int                     `json:"max_stale_seconds"`
	ElapsedSinceRevoke  float64                 `json:"elapsed_since_revoke_seconds,omitempty"`
	Session             *SessionRecord          `json:"session,omitempty"`
	Identity            *storage.CallerIdentity `json:"identity,omitempty"`
}

func (e *RevocationEnforcer) denyBeforeSideEffects(code, msg string, revoked, stoppedWithinBound bool, elapsed float64) *AccessCheckResult {
	return &AccessCheckResult{
		Allow:               false,
		Valid:               false,
		Status:              "denied",
		ErrorCode:           code,
		ErrorMessage:        msg,
		SideEffectsExecuted: false,
		Revoked:             revoked,
		StoppedWithinBound:  stoppedWithinBound,
		MaxStaleSeconds:     int(e.staleWindow.Seconds()),
		ElapsedSinceRevoke:  elapsed,
	}
}

// CheckAccess evaluates identity, anti-replay, scope, path/provider permissions, and <=30s revocation freshness before any side effects.
func (e *RevocationEnforcer) CheckAccess(ctx context.Context, req AccessCheckRequest) (*AccessCheckResult, error) {
	if e.sessionMgr == nil || e.revStore == nil {
		return e.denyBeforeSideEffects(ErrCodeProviderUnavailable, "Fail closed: session or revocation store is not initialized", false, true, 0), nil
	}

	now := req.EvaluationTime
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	// 1. Reject forged or unstripped client identity headers before any lookup or side effects.
	if !req.UntrustedHeadersStripped || len(req.ForgedHeaders) > 0 {
		return e.denyBeforeSideEffects(ErrCodeForgedHeader, "Fail closed: untrusted or forged identity headers were not stripped by the edge adapter", false, true, 0), nil
	}

	// 2. Reject when upstream identity/revocation provider is unavailable.
	if req.ProviderUnavailable || strings.EqualFold(strings.TrimSpace(req.ProviderState), "unavailable") {
		return e.denyBeforeSideEffects(ErrCodeProviderUnavailable, "Fail closed: identity or revocation provider is unavailable", false, true, 0), nil
	}

	// 3. Reject missing identity before side effects.
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		return e.denyBeforeSideEffects(ErrCodeUnauthenticatedIdentity, "Fail closed: missing session identity", false, true, 0), nil
	}

	// 4. Reject single-use request replay before side effects.
	if req.SingleUseRequest && strings.TrimSpace(req.RequestID) != "" {
		reqID := strings.TrimSpace(req.RequestID)
		e.mu.Lock()
		if _, exists := e.usedReqIDs[reqID]; exists {
			e.mu.Unlock()
			return e.denyBeforeSideEffects(ErrCodeReplayedIdentity, fmt.Sprintf("Fail closed: replayed single-use request_id '%s' rejected", reqID), false, true, 0), nil
		}
		e.usedReqIDs[reqID] = now
		e.mu.Unlock()
	}

	// 5. Fast-path explicit session revocation check in memory and durable revocation store.
	e.mu.RLock()
	fastRev, fastOK := e.revokedFast[sessionID]
	e.mu.RUnlock()
	if fastOK && !now.Before(fastRev.RevokedAt) {
		return e.denyBeforeSideEffects(ErrCodeRevokedSession, fmt.Sprintf("Fail closed: session '%s' was revoked (%s)", sessionID, fastRev.Reason), true, true, now.Sub(fastRev.RevokedAt).Seconds()), nil
	}

	if revRec, err := e.revStore.GetSessionRevocation(ctx, sessionID); err == nil && revRec != nil {
		if !now.Before(revRec.RevokedAt) {
			e.mu.Lock()
			delete(e.leases, sessionID)
			e.revokedFast[sessionID] = *revRec
			e.mu.Unlock()
			return e.denyBeforeSideEffects(ErrCodeRevokedSession, fmt.Sprintf("Fail closed: session '%s' is revoked in authoritative store (%s)", sessionID, revRec.Reason), true, true, now.Sub(revRec.RevokedAt).Seconds()), nil
		}
	} else if err != nil && !errors.Is(err, ErrRevocationNotFound) {
		return e.denyBeforeSideEffects(ErrCodeProviderUnavailable, fmt.Sprintf("Fail closed: revocation store read error: %v", err), false, true, 0), nil
	}

	// 6. Resume and validate the authoritative session via SessionManager.
	targetScope := strings.TrimSpace(req.TargetOwnerScope)
	if targetScope == "" {
		targetScope = strings.TrimSpace(req.ObjectScope)
	}
	resumed, err := e.sessionMgr.ResumeSession(ctx, ResumeSessionRequest{
		SessionID:                sessionID,
		ClientIP:                 req.ClientIP,
		UserAgent:                req.UserAgent,
		UntrustedHeadersStripped: req.UntrustedHeadersStripped,
		TargetOwnerScope:         targetScope,
		ResourceClassification:   req.ResourceClassification,
		EvaluationTime:           now,
	})
	if err != nil {
		return e.denyBeforeSideEffects(ErrCodeProviderUnavailable, fmt.Sprintf("Fail closed: session resume error: %v", err), false, true, 0), nil
	}
	if !resumed.Valid || resumed.Session == nil {
		code := resumed.ErrorCode
		isRevoked := code == ErrCodeRevokedSession
		if code == ErrCodeSessionNotFound && strings.EqualFold(strings.TrimSpace(req.ResourceClassification), "private") {
			code = ErrCodePrivateResourceFailClosed
		}
		return e.denyBeforeSideEffects(code, resumed.ErrorMessage, isRevoked, true, 0), nil
	}

	sess := *resumed.Session

	// 7. Enforce secondary object_scope boundary if both TargetOwnerScope and ObjectScope are specified.
	if strings.TrimSpace(req.ObjectScope) != "" && strings.TrimSpace(req.ObjectScope) != sess.OwnerScope {
		return e.denyBeforeSideEffects(ErrCodeScopeViolation, fmt.Sprintf("Fail closed: session owner_scope '%s' cannot access unrelated object_scope '%s'", sess.OwnerScope, req.ObjectScope), false, true, 0), nil
	}

	// 8. Check subject-wide monotonic epoch revocation.
	if subjRev, err := e.revStore.GetSubjectRevocation(ctx, sess.SubjectID); err == nil && subjRev != nil {
		if !now.Before(subjRev.RevokedAt) && sess.SessionEpoch < subjRev.MinRequiredEpoch {
			e.mu.Lock()
			delete(e.leases, sessionID)
			e.mu.Unlock()
			return e.denyBeforeSideEffects(ErrCodeRevokedSession, fmt.Sprintf("Fail closed: subject '%s' epoch %d is below minimum required epoch %d (%s)", sess.SubjectID, sess.SessionEpoch, subjRev.MinRequiredEpoch, subjRev.Reason), true, true, now.Sub(subjRev.RevokedAt).Seconds()), nil
		}
	} else if err != nil && !errors.Is(err, ErrRevocationNotFound) {
		return e.denyBeforeSideEffects(ErrCodeProviderUnavailable, fmt.Sprintf("Fail closed: subject revocation lookup failed: %v", err), false, true, 0), nil
	}

	// 9. Check owner_scope monotonic epoch revocation.
	if scopeRev, err := e.revStore.GetScopeRevocation(ctx, sess.OwnerScope); err == nil && scopeRev != nil {
		if !now.Before(scopeRev.RevokedAt) && sess.SessionEpoch < scopeRev.MinRequiredEpoch {
			e.mu.Lock()
			delete(e.leases, sessionID)
			e.mu.Unlock()
			return e.denyBeforeSideEffects(ErrCodeRevokedSession, fmt.Sprintf("Fail closed: owner_scope '%s' epoch %d is below minimum required epoch %d (%s)", sess.OwnerScope, sess.SessionEpoch, scopeRev.MinRequiredEpoch, scopeRev.Reason), true, true, now.Sub(scopeRev.RevokedAt).Seconds()), nil
		}
	} else if err != nil && !errors.Is(err, ErrRevocationNotFound) {
		return e.denyBeforeSideEffects(ErrCodeProviderUnavailable, fmt.Sprintf("Fail closed: scope revocation lookup failed: %v", err), false, true, 0), nil
	}

	// 10. Reject widened path or provider permissions before side effects.
	if err := e.validatePathAndProviderPermission(sess, req.RequestedPath, req.RequestedProvider); err != nil {
		return e.denyBeforeSideEffects(ErrCodeWidenedPermissionDenied, err.Error(), false, true, 0), nil
	}

	// 11. Refresh bounded worker authorization lease (never exceeding 30s).
	e.PrimeWorkerLease(sess, now)

	idCopy := resumed.Identity
	return &AccessCheckResult{
		Allow: true, Valid: true, Status: "allowed",
		SideEffectsExecuted: true, Revoked: false, StoppedWithinBound: true,
		MaxStaleSeconds: int(e.staleWindow.Seconds()), Session: &sess, Identity: &idCopy,
	}, nil
}

func (e *RevocationEnforcer) validatePathAndProviderPermission(sess SessionRecord, reqPath, reqProvider string) error {
	if trimmedPath := strings.TrimSpace(reqPath); trimmedPath != "" {
		if strings.Contains(trimmedPath, "..") {
			return fmt.Errorf("Fail closed: path traversal detected in requested_path '%s'", trimmedPath)
		}
		cleaned := path.Clean("/" + strings.TrimPrefix(trimmedPath, "/"))
		var allowedPrefixes []string
		if customPrefix := strings.TrimSpace(sess.Credentials.Custom["allowed_path_prefix"]); customPrefix != "" {
			allowedPrefixes = append(allowedPrefixes, customPrefix)
		} else if len(e.config.AllowedPaths) > 0 {
			allowedPrefixes = append(allowedPrefixes, e.config.AllowedPaths...)
		}
		if len(allowedPrefixes) > 0 {
			matched := false
			for _, p := range allowedPrefixes {
				cleanPrefix := path.Clean("/" + strings.TrimPrefix(strings.TrimSpace(p), "/"))
				if cleaned == cleanPrefix || strings.HasPrefix(cleaned, cleanPrefix+"/") {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("Fail closed: requested_path '%s' widens session path permissions (%v)", trimmedPath, allowedPrefixes)
			}
		}
	}

	if trimmedProvider := strings.TrimSpace(reqProvider); trimmedProvider != "" {
		var allowedProviders []string
		if customProv := strings.TrimSpace(sess.Credentials.Custom["allowed_provider"]); customProv != "" {
			allowedProviders = append(allowedProviders, customProv)
		} else if len(e.config.AllowedProviders) > 0 {
			allowedProviders = append(allowedProviders, e.config.AllowedProviders...)
		}
		if len(allowedProviders) > 0 {
			matched := false
			for _, prov := range allowedProviders {
				if strings.EqualFold(trimmedProvider, strings.TrimSpace(prov)) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("Fail closed: requested_provider '%s' widens session provider permissions (%v)", trimmedProvider, allowedProviders)
			}
		}
	}
	return nil
}

// WorkloadStep represents a single chronological action in a C15 workload fixture.
type WorkloadStep struct {
	StepID           string              `json:"step_id"`
	StepType         string              `json:"step_type"`
	Timestamp        time.Time           `json:"timestamp"`
	Access           *AccessCheckRequest `json:"access,omitempty"`
	RevokeTarget     string              `json:"revoke_target,omitempty"`
	MinRequiredEpoch int64               `json:"min_required_epoch,omitempty"`
	Reason           string              `json:"reason,omitempty"`
	Actor            string              `json:"actor,omitempty"`
}

// WorkloadStepOutcome records the deterministic result of a single step in a workload execution.
type WorkloadStepOutcome struct {
	StepID              string             `json:"step_id"`
	StepType            string             `json:"step_type"`
	Timestamp           time.Time          `json:"timestamp"`
	AccessResult        *AccessCheckResult `json:"access_result,omitempty"`
	RevocationEvent     *RevocationEvent   `json:"revocation_event,omitempty"`
	StoppedWithinBound  bool               `json:"stopped_within_bound"`
	SideEffectsExecuted bool               `json:"side_effects_executed"`
}

// WorkloadExpected defines expected assertion fields in C15 fixtures.
type WorkloadExpected struct {
	Allow                    bool   `json:"allow"`
	Valid                    bool   `json:"valid"`
	Status                   string `json:"status,omitempty"`
	ErrorCode                string `json:"error_code,omitempty"`
	SideEffectsExecuted      bool   `json:"side_effects_executed"`
	Revoked                  bool   `json:"revoked"`
	StoppedWithinBound       bool   `json:"stopped_within_bound"`
	MaxStaleSeconds          int    `json:"max_stale_seconds,omitempty"`
	TotalChecks              int    `json:"total_checks,omitempty"`
	AllowedBeforeRevokeCount int    `json:"allowed_before_revoke_count,omitempty"`
	DeniedAfterRevokeCount   int    `json:"denied_after_revoke_count,omitempty"`
}

// WorkloadRevocationSpec represents a C15 fixture or CLI/HTTP workload evaluation specification.
type WorkloadRevocationSpec struct {
	FixtureID       string              `json:"fixture_id,omitempty"`
	CommitID        string              `json:"commit_id,omitempty"`
	Description     string              `json:"description,omitempty"`
	SchemaVersion   string              `json:"schema_version,omitempty"`
	Config          RevocationConfig    `json:"config"`
	PreloadSessions []SessionRecord     `json:"preload_sessions,omitempty"`
	PreloadRevokes  []RevocationRecord  `json:"preload_revokes,omitempty"`
	Check           *AccessCheckRequest `json:"check,omitempty"`
	WorkloadSteps   []WorkloadStep      `json:"workload_steps,omitempty"`
	Expected        WorkloadExpected    `json:"expected,omitempty"`
}

// WorkloadEvaluationReport is the structured output of EvaluateWorkloadSpec.
type WorkloadEvaluationReport struct {
	FixtureID                string                `json:"fixture_id,omitempty"`
	CommitID                 string                `json:"commit_id,omitempty"`
	Allow                    bool                  `json:"allow"`
	Valid                    bool                  `json:"valid"`
	Status                   string                `json:"status"`
	ErrorCode                string                `json:"error_code,omitempty"`
	ErrorMessage             string                `json:"error_message,omitempty"`
	SideEffectsExecuted      bool                  `json:"side_effects_executed"`
	Revoked                  bool                  `json:"revoked"`
	StoppedWithinBound       bool                  `json:"stopped_within_bound"`
	MaxStaleSeconds          int                   `json:"max_stale_seconds"`
	TotalChecks              int                   `json:"total_checks"`
	AllowedBeforeRevokeCount int                   `json:"allowed_before_revoke_count"`
	DeniedAfterRevokeCount   int                   `json:"denied_after_revoke_count"`
	StepOutcomes             []WorkloadStepOutcome `json:"step_outcomes,omitempty"`
}

// EvaluateWorkloadSpec executes a C15 single check or multi-step target workload against a RevocationEnforcer.
func EvaluateWorkloadSpec(ctx context.Context, spec WorkloadRevocationSpec, sessStore SessionStore, revStore RevocationStore) (*WorkloadEvaluationReport, error) {
	if sessStore == nil {
		sessStore = NewMemorySessionStore()
	}
	if revStore == nil {
		revStore = NewMemoryRevocationStore()
	}

	mgr := NewSessionManager(sessStore, SessionConfig{})
	enforcer, err := NewRevocationEnforcer(mgr, revStore, spec.Config)
	if err != nil {
		return &WorkloadEvaluationReport{
			FixtureID: spec.FixtureID, CommitID: spec.CommitID, Status: "denied",
			ErrorCode: ErrCodeStaleWindowExceeded, ErrorMessage: err.Error(),
			MaxStaleSeconds: int(MaxRevocationStaleWindow.Seconds()),
		}, nil
	}

	for _, s := range spec.PreloadSessions {
		if err := sessStore.SaveSession(ctx, s); err != nil {
			return nil, err
		}
		if s.Status == SessionStatusActive {
			enforcer.PrimeWorkerLease(s, s.LastSeenAt)
		}
	}

	for _, r := range spec.PreloadRevokes {
		if strings.TrimSpace(r.SessionID) != "" {
			if err := revStore.SaveSessionRevocation(ctx, r); err != nil {
				return nil, err
			}
			enforcer.mu.Lock()
			delete(enforcer.leases, r.SessionID)
			enforcer.revokedFast[r.SessionID] = r
			enforcer.mu.Unlock()
		}
		if strings.TrimSpace(r.SubjectID) != "" && r.MinRequiredEpoch > 0 {
			if err := revStore.SaveSubjectRevocation(ctx, r); err != nil {
				return nil, err
			}
		}
		if strings.TrimSpace(r.OwnerScope) != "" && r.MinRequiredEpoch > 0 {
			if err := revStore.SaveScopeRevocation(ctx, r); err != nil {
				return nil, err
			}
		}
	}

	if spec.Check != nil && len(spec.WorkloadSteps) == 0 {
		res, err := enforcer.CheckAccess(ctx, *spec.Check)
		if err != nil {
			return nil, err
		}
		allowedBefore, deniedAfter := 0, 0
		if res.Allow {
			allowedBefore = 1
		} else if res.Revoked {
			deniedAfter = 1
		}
		return &WorkloadEvaluationReport{
			FixtureID: spec.FixtureID, CommitID: spec.CommitID,
			Allow: res.Allow, Valid: res.Valid, Status: res.Status,
			ErrorCode: res.ErrorCode, ErrorMessage: res.ErrorMessage,
			SideEffectsExecuted: res.SideEffectsExecuted, Revoked: res.Revoked,
			StoppedWithinBound: res.StoppedWithinBound, MaxStaleSeconds: res.MaxStaleSeconds,
			TotalChecks: 1, AllowedBeforeRevokeCount: allowedBefore, DeniedAfterRevokeCount: deniedAfter,
		}, nil
	}

	report := &WorkloadEvaluationReport{
		FixtureID: spec.FixtureID, CommitID: spec.CommitID,
		StoppedWithinBound: true, MaxStaleSeconds: int(enforcer.StaleWindow().Seconds()),
	}

	recordRevokeStep := func(step WorkloadStep, ev *RevocationEvent, err error) error {
		if err != nil {
			return err
		}
		report.Revoked = true
		report.StepOutcomes = append(report.StepOutcomes, WorkloadStepOutcome{
			StepID: step.StepID, StepType: step.StepType, Timestamp: step.Timestamp,
			RevocationEvent: ev, StoppedWithinBound: true,
		})
		return nil
	}

	for _, step := range spec.WorkloadSteps {
		stepTime := step.Timestamp
		switch step.StepType {
		case "revoke_session":
			ev, err := enforcer.RevokeSession(ctx, step.RevokeTarget, step.Reason, step.Actor, stepTime)
			if err := recordRevokeStep(step, ev, err); err != nil {
				return nil, err
			}
		case "revoke_subject":
			ev, err := enforcer.RevokeSubject(ctx, step.RevokeTarget, step.MinRequiredEpoch, step.Reason, step.Actor, stepTime)
			if err := recordRevokeStep(step, ev, err); err != nil {
				return nil, err
			}
		case "revoke_scope":
			ev, err := enforcer.RevokeScope(ctx, step.RevokeTarget, step.MinRequiredEpoch, step.Reason, step.Actor, stepTime)
			if err := recordRevokeStep(step, ev, err); err != nil {
				return nil, err
			}
		case "access":
			if step.Access == nil {
				return nil, fmt.Errorf("workload step '%s' missing access payload", step.StepID)
			}
			req := *step.Access
			if req.EvaluationTime.IsZero() && !stepTime.IsZero() {
				req.EvaluationTime = stepTime
			}
			res, err := enforcer.CheckAccess(ctx, req)
			if err != nil {
				return nil, err
			}
			report.TotalChecks++
			if res.Allow {
				report.AllowedBeforeRevokeCount++
			}
			if res.Revoked {
				report.Revoked = true
				if !res.Allow && !res.SideEffectsExecuted {
					report.DeniedAfterRevokeCount++
				} else {
					report.StoppedWithinBound = false
				}
			}
			if !res.StoppedWithinBound {
				report.StoppedWithinBound = false
			}
			report.Allow, report.Valid, report.Status = res.Allow, res.Valid, res.Status
			report.ErrorCode, report.ErrorMessage = res.ErrorCode, res.ErrorMessage
			report.SideEffectsExecuted = res.SideEffectsExecuted
			report.StepOutcomes = append(report.StepOutcomes, WorkloadStepOutcome{
				StepID: step.StepID, StepType: step.StepType, Timestamp: req.EvaluationTime,
				AccessResult: res, StoppedWithinBound: res.StoppedWithinBound, SideEffectsExecuted: res.SideEffectsExecuted,
			})
		default:
			return nil, fmt.Errorf("unsupported workload step_type '%s'", step.StepType)
		}
	}

	return report, nil
}
