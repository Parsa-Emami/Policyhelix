package bundles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	// ActivationSchemaVersion is the versioned schema of persisted activation records and results.
	ActivationSchemaVersion = "1"

	// ActivePolicyRecordID is the single durable record that holds the active policy bundle.
	// The owner scope and classification are fixed so an activation can never write into another
	// tenant's scope or downgrade the record's private classification.
	ActivePolicyRecordID       = "policyhelix:active-policy-bundle"
	ActivePolicyOwnerScope     = "policyhelix"
	ActivePolicyClassification = "private"
)

// Activation status values returned by Activate and Restore.
const (
	ActivationStatusActivated = "activated"
	ActivationStatusReplayed  = "replayed"
	ActivationStatusRejected  = "rejected"
	ActivationStatusRestored  = "restored"
	ActivationStatusEmpty     = "empty"
)

// Typed error codes for the activation lifecycle. Bundle rejections reuse the C11 verification codes.
const (
	ErrCodeInvalidActivationRequest  = "INVALID_ACTIVATION_REQUEST"
	ErrCodeActivationStoreUnavail    = "ACTIVATION_STORE_UNAVAILABLE"
	ErrCodeActivationCommitUnconfirm = "ACTIVATION_COMMIT_UNCONFIRMED"
	ErrCodeCorruptActivationState    = "CORRUPT_ACTIVATION_STATE"
	ErrCodeActivationCancelled       = "ACTIVATION_CANCELLED"
)

var activationIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)

// ActivationRecord is the versioned durable payload written for every accepted activation.
// It is deterministic for a given operation so a retried write is recognised as a replay.
type ActivationRecord struct {
	SchemaVersion   string                   `json:"schema_version"`
	OperationID     string                   `json:"operation_id"`
	Bundle          policy.LocalPolicyBundle `json:"bundle"`
	BundleDigest    string                   `json:"bundle_digest"`
	HighestRevision int64                    `json:"highest_revision"`
	Actor           string                   `json:"actor"`
}

// StoredActivation pairs a durable activation record with the storage metadata that committed it.
type StoredActivation struct {
	Record          ActivationRecord
	StorageRevision int64
	ObjectDigest    string
	OperationID     string
	CommittedAt     string
}

// ActivationCommit is the typed receipt of a durable activation write.
type ActivationCommit struct {
	OperationID     string
	StorageRevision int64
	ObjectDigest    string
	Replayed        bool
	CommittedAt     string
}

// ActivationStoreError is the boundary-safe form of a storage rejection. NotFound distinguishes an
// empty activation slot from an unreadable or corrupt one.
type ActivationStoreError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	NotFound  bool   `json:"-"`
}

func (e *ActivationStoreError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ActivationStore is the durable authority port used by ActivationManager. Implementations must make
// CommitActivation atomic: after a crash either the previous record or the new record is visible.
type ActivationStore interface {
	CommitActivation(ctx context.Context, record ActivationRecord, identity storage.CallerIdentity) (*ActivationCommit, error)
	LoadActivation() (*StoredActivation, error)
}

// StorageActivationStore stores the single active policy record in the C05 authoritative storage port.
type StorageActivationStore struct {
	adapter *storage.Adapter
}

// NewStorageActivationStore adapts the local authoritative storage port to the activation port.
func NewStorageActivationStore(adapter *storage.Adapter) *StorageActivationStore {
	return &StorageActivationStore{adapter: adapter}
}

// CommitActivation durably writes the activation record through the atomic manifest publication protocol.
func (s *StorageActivationStore) CommitActivation(ctx context.Context, record ActivationRecord, identity storage.CallerIdentity) (*ActivationCommit, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, &ActivationStoreError{
			Code:    ErrCodeCorruptActivationState,
			Message: fmt.Sprintf("failed to encode activation record: %v", err),
		}
	}

	receipt, sErr := s.adapter.WriteRecord(ctx, storage.WriteRequest{
		SchemaVersion:  storage.SchemaVersion,
		OperationID:    record.OperationID,
		RecordID:       ActivePolicyRecordID,
		OwnerScope:     ActivePolicyOwnerScope,
		Classification: ActivePolicyClassification,
		Identity:       identity,
		Payload:        payload,
	})
	if sErr != nil {
		return nil, storeErrorFromStorage(sErr)
	}

	return &ActivationCommit{
		OperationID:     receipt.OperationID,
		StorageRevision: receipt.Revision,
		ObjectDigest:    receipt.ObjectDigest,
		Replayed:        receipt.Replayed,
		CommittedAt:     receipt.CommittedAt,
	}, nil
}

// LoadActivation reads and digest-verifies the durable activation record, if one was committed.
func (s *StorageActivationStore) LoadActivation() (*StoredActivation, error) {
	payload, entry, sErr := s.adapter.ReadRecord(ActivePolicyRecordID)
	if sErr != nil {
		return nil, storeErrorFromStorage(sErr)
	}

	var record ActivationRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, &ActivationStoreError{
			Code:    ErrCodeCorruptActivationState,
			Message: fmt.Sprintf("durable activation record is not valid JSON: %v", err),
		}
	}

	return &StoredActivation{
		Record:          record,
		StorageRevision: entry.Revision,
		ObjectDigest:    entry.ObjectDigest,
		OperationID:     entry.OperationID,
		CommittedAt:     entry.UpdatedAt,
	}, nil
}

func storeErrorFromStorage(sErr *storage.StorageError) *ActivationStoreError {
	if sErr == nil {
		return nil
	}
	return &ActivationStoreError{
		Code:      sErr.Code,
		Message:   sErr.Message,
		Retryable: sErr.Retryable,
		NotFound:  sErr.Code == storage.ErrRecordNotFound,
	}
}

// ActivationRequest is the versioned input for atomically switching the active policy bundle.
// Trust anchors and the verification clock are manager configuration, not request input, so a caller
// can neither introduce its own key nor backdate freshness verification.
type ActivationRequest struct {
	SchemaVersion string                   `json:"schema_version,omitempty"`
	OperationID   string                   `json:"operation_id"`
	Identity      storage.CallerIdentity   `json:"identity"`
	Bundle        policy.LocalPolicyBundle `json:"bundle"`
}

// ActivationResult is the typed outcome of an activation attempt. Active reports whether a valid
// durable authority is in force after the attempt, not whether the candidate was accepted.
type ActivationResult struct {
	SchemaVersion   string `json:"schema_version"`
	Status          string `json:"status"`
	Durable         bool   `json:"durable"`
	Replayed        bool   `json:"replayed"`
	Active          bool   `json:"active"`
	Retryable       bool   `json:"retryable"`
	OperationID     string `json:"operation_id,omitempty"`
	BundleID        string `json:"bundle_id,omitempty"`
	Issuer          string `json:"issuer,omitempty"`
	SignerKeyID     string `json:"signer_key_id,omitempty"`
	Revision        int64  `json:"revision,omitempty"`
	HighestRevision int64  `json:"highest_revision,omitempty"`
	Digest          string `json:"digest,omitempty"`
	StorageRevision int64  `json:"storage_revision,omitempty"`
	ActivatedAt     string `json:"activated_at,omitempty"`
	CheckedAt       string `json:"checked_at,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
	Message         string `json:"message,omitempty"`
}

// ActivationState is the typed restore outcome after a restart.
type ActivationState struct {
	SchemaVersion   string `json:"schema_version"`
	Status          string `json:"status"`
	Active          bool   `json:"active"`
	OperationID     string `json:"operation_id,omitempty"`
	BundleID        string `json:"bundle_id,omitempty"`
	Issuer          string `json:"issuer,omitempty"`
	SignerKeyID     string `json:"signer_key_id,omitempty"`
	Revision        int64  `json:"revision,omitempty"`
	HighestRevision int64  `json:"highest_revision,omitempty"`
	Digest          string `json:"digest,omitempty"`
	StorageRevision int64  `json:"storage_revision,omitempty"`
	RestoredAt      string `json:"restored_at,omitempty"`
	CheckedAt       string `json:"checked_at,omitempty"`
	ErrorCode       string `json:"error_code,omitempty"`
	Message         string `json:"message,omitempty"`
}

// ActivationManager owns the transition between a verified candidate and the durable active authority.
// It never writes before verification passes and never advertises an activation it could not read back.
type ActivationManager struct {
	mu              sync.RWMutex
	store           ActivationStore
	keyring         *Keyring
	evaluator       *policy.BundleEvaluator
	Now             func() time.Time
	restored        bool
	blocked         bool
	state           ActivationState
	record          *ActivationRecord
	stored          *StoredActivation
	highestRevision int64
}

// NewActivationManager creates an activation manager bound to a durable store and trusted keyring.
func NewActivationManager(store ActivationStore, keyring *Keyring) *ActivationManager {
	if keyring == nil {
		keyring = NewKeyring()
	}
	return &ActivationManager{
		store:     store,
		keyring:   keyring,
		evaluator: keyring.NewEvaluator(),
		Now:       func() time.Time { return time.Now().UTC() },
	}
}

// Restore reloads the durable authority after a restart. The previous bundle and highest accepted
// revision are exposed only when the complete record verifies; an unreadable or inconsistent record
// blocks further activation until it is repaired.
func (m *ActivationManager) Restore(ctx context.Context) ActivationState {
	if ctx == nil {
		ctx = context.Background()
	}
	checkedAt := m.Now().UTC().Format(time.RFC3339)
	if ctx.Err() != nil {
		return ActivationState{
			SchemaVersion: ActivationSchemaVersion,
			Status:        ActivationStatusRejected,
			CheckedAt:     checkedAt,
			ErrorCode:     ErrCodeActivationCancelled,
			Message:       "activation restore cancelled before reading durable state",
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked()
}

// Activate verifies, durably commits and then switches to the candidate bundle. Any rejection leaves
// the previous authority and the highest accepted revision untouched.
func (m *ActivationManager) Activate(ctx context.Context, req ActivationRequest) ActivationResult {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activateLocked(ctx, req)
}

// Active returns the currently restored authoritative bundle, if one is in force.
func (m *ActivationManager) Active() (policy.LocalPolicyBundle, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.state.Active || m.evaluator == nil {
		return policy.LocalPolicyBundle{}, false
	}
	return m.evaluator.ActiveBundle()
}

// HighestRevision returns the durable highest accepted revision, including after authority expired.
func (m *ActivationManager) HighestRevision() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.highestRevision
}

// Evaluate authorizes a request against the restored authority and fails closed without one.
func (m *ActivationManager) Evaluate(ctx context.Context, input policy.BundleEvalInput) policy.BundleDecision {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.state.Active || m.evaluator == nil {
		return policy.BundleDecision{
			Allow:          false,
			Classification: policy.ResourceClassPrivate,
			Reasons:        []string{policy.ErrCodeNoActiveBundle},
			Obligations:    []policy.PolicyObligation{},
			Error: &policy.BundleError{
				Code:      policy.ErrCodeNoActiveBundle,
				Message:   "No durably restored active policy bundle; failing closed",
				Retryable: false,
			},
			WithinDeadline: true,
		}
	}
	return m.evaluator.Evaluate(ctx, input)
}

func (m *ActivationManager) restoreLocked() ActivationState {
	now := m.Now().UTC()
	checkedAt := now.Format(time.RFC3339)

	m.restored = true
	m.blocked = false
	m.record = nil
	m.stored = nil
	m.highestRevision = 0
	m.evaluator = m.keyring.NewEvaluator()
	m.state = ActivationState{
		SchemaVersion: ActivationSchemaVersion,
		Status:        ActivationStatusEmpty,
		CheckedAt:     checkedAt,
	}

	stored, err := m.store.LoadActivation()
	if err != nil {
		var storeErr *ActivationStoreError
		if errors.As(err, &storeErr) && storeErr.NotFound {
			return m.state
		}
		m.blocked = true
		m.state.Status = ActivationStatusRejected
		m.state.ErrorCode = activationStoreErrorCode(err)
		m.state.Message = err.Error()
		return m.state
	}

	record := stored.Record
	m.state = ActivationState{
		SchemaVersion:   ActivationSchemaVersion,
		Status:          ActivationStatusRejected,
		OperationID:     record.OperationID,
		BundleID:        record.Bundle.BundleID,
		Issuer:          record.Bundle.Issuer,
		SignerKeyID:     record.Bundle.SignerKeyID,
		Revision:        record.Bundle.Revision,
		HighestRevision: record.HighestRevision,
		Digest:          record.BundleDigest,
		StorageRevision: stored.StorageRevision,
		RestoredAt:      stored.CommittedAt,
		CheckedAt:       checkedAt,
	}

	if code, message := validateActivationRecord(*stored); code != "" {
		m.blocked = true
		m.state.ErrorCode = code
		m.state.Message = message
		return m.state
	}

	m.record = &record
	m.stored = stored
	m.highestRevision = record.HighestRevision

	verification := verifyAt(record.Bundle, m.keyring, now, 0, BundleVerification{})
	if !verification.Verified {
		m.state.ErrorCode = verification.ErrorCode
		m.state.Message = fmt.Sprintf("durable authority rejected on restore: %s", verification.Message)
		return m.state
	}
	if _, bErr := m.evaluator.ValidateBundle(record.Bundle, now); bErr != nil {
		m.state.ErrorCode = bErr.Code
		m.state.Message = fmt.Sprintf("durable authority failed structural validation on restore: %s", bErr.Message)
		return m.state
	}
	if bErr := m.evaluator.LoadBundle(record.Bundle, now); bErr != nil {
		m.state.ErrorCode = bErr.Code
		m.state.Message = fmt.Sprintf("durable authority could not be installed on restore: %s", bErr.Message)
		return m.state
	}

	m.state.Status = ActivationStatusRestored
	m.state.Active = true
	m.state.ErrorCode = ""
	m.state.Message = ""
	return m.state
}

func (m *ActivationManager) activateLocked(ctx context.Context, req ActivationRequest) ActivationResult {
	now := m.Now().UTC()
	result := ActivationResult{
		SchemaVersion: ActivationSchemaVersion,
		Status:        ActivationStatusRejected,
		OperationID:   strings.TrimSpace(req.OperationID),
		BundleID:      strings.TrimSpace(req.Bundle.BundleID),
		Issuer:        strings.TrimSpace(req.Bundle.Issuer),
		SignerKeyID:   strings.TrimSpace(req.Bundle.SignerKeyID),
		Revision:      req.Bundle.Revision,
		Digest:        strings.TrimSpace(req.Bundle.Digest),
		CheckedAt:     now.Format(time.RFC3339),
	}
	if ctx.Err() != nil {
		result.ErrorCode = ErrCodeActivationCancelled
		result.Message = "activation cancelled before verification"
		result.Retryable = true
		result.Active = m.state.Active
		result.HighestRevision = m.highestRevision
		return result
	}

	schemaVersion := strings.TrimSpace(req.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = ActivationSchemaVersion
	}
	if schemaVersion != ActivationSchemaVersion {
		result.ErrorCode = ErrCodeInvalidActivationRequest
		result.Message = fmt.Sprintf("unsupported activation schema_version '%s'; expected '%s'", schemaVersion, ActivationSchemaVersion)
		result.Active = m.state.Active
		result.HighestRevision = m.highestRevision
		return result
	}

	// The storage security gate is applied before any replay handling so unauthenticated or
	// unauthorised callers can never receive an activation outcome.
	securityProbe := storage.WriteRequest{
		SchemaVersion:  storage.SchemaVersion,
		OperationID:    req.OperationID,
		RecordID:       ActivePolicyRecordID,
		OwnerScope:     ActivePolicyOwnerScope,
		Classification: ActivePolicyClassification,
		Identity:       req.Identity,
		Payload:        json.RawMessage(`{}`),
	}
	if sErr := storage.ValidateIdentityAndScope(securityProbe); sErr != nil {
		result.ErrorCode = sErr.Code
		result.Message = sErr.Message
		result.Retryable = sErr.Retryable
		result.Active = m.state.Active
		result.HighestRevision = m.highestRevision
		return result
	}

	if !m.restored {
		m.restoreLocked()
	}
	result.Active = m.state.Active
	result.HighestRevision = m.highestRevision
	if m.blocked {
		result.ErrorCode = ErrCodeCorruptActivationState
		result.Message = "durable activation state is corrupt or unreadable; refusing to overwrite it"
		return result
	}

	evalTime := now
	result.CheckedAt = evalTime.Format(time.RFC3339)

	// A retried operation whose record is still the durable authority is an idempotent replay.
	// The durable record, not the retried candidate, supplies the returned evidence.
	if m.record != nil && m.record.OperationID == req.OperationID {
		if !m.state.Active {
			result.ErrorCode = m.state.ErrorCode
			result.Message = fmt.Sprintf("operation '%s' is already committed but its durable authority is not currently active: %s", req.OperationID, m.state.Message)
			return result
		}
		if m.record.BundleDigest != strings.TrimSpace(req.Bundle.Digest) ||
			m.record.HighestRevision != req.Bundle.Revision ||
			m.record.Actor != req.Identity.SubjectID {
			result.ErrorCode = storage.ErrOperationConflict
			result.Message = fmt.Sprintf("operation_id '%s' is already committed with different bundle content or actor", req.OperationID)
			return result
		}
		if failure := verifyTrustEvidence(req.Bundle, m.keyring); failure != nil {
			result.ErrorCode = failure.code
			result.Message = failure.message
			return result
		}
		return m.replayedResult(*m.stored)
	}

	verification := verifyAt(req.Bundle, m.keyring, evalTime, m.highestRevision, BundleVerification{})
	if !verification.Verified {
		result.ErrorCode = verification.ErrorCode
		result.Message = verification.Message
		return result
	}

	if _, bErr := m.evaluator.ValidateBundle(req.Bundle, evalTime); bErr != nil {
		result.ErrorCode = bErr.Code
		result.Message = bErr.Message
		return result
	}

	record := ActivationRecord{
		SchemaVersion:   ActivationSchemaVersion,
		OperationID:     req.OperationID,
		Bundle:          req.Bundle,
		BundleDigest:    strings.TrimSpace(req.Bundle.Digest),
		HighestRevision: req.Bundle.Revision,
		Actor:           req.Identity.SubjectID,
	}

	commit, err := m.store.CommitActivation(ctx, record, req.Identity)
	if err != nil {
		result.ErrorCode = activationStoreErrorCode(err)
		result.Message = err.Error()
		var storeErr *ActivationStoreError
		if errors.As(err, &storeErr) {
			result.Retryable = storeErr.Retryable
		}
		return result
	}
	result.StorageRevision = commit.StorageRevision

	stored, loadErr := m.store.LoadActivation()
	if loadErr != nil {
		result.ErrorCode = ErrCodeActivationCommitUnconfirm
		result.Message = fmt.Sprintf("activation write could not be read back; retry the same operation_id: %v", loadErr)
		result.Retryable = true
		return result
	}
	if code, message := validateActivationRecord(*stored); code != "" {
		result.ErrorCode = code
		result.Message = message
		return result
	}
	if stored.Record.OperationID != req.OperationID ||
		stored.Record.BundleDigest != record.BundleDigest ||
		stored.Record.HighestRevision != record.HighestRevision {
		result.ErrorCode = ErrCodeActivationCommitUnconfirm
		result.Message = "read-back activation record does not match the committed request; retry the same operation_id"
		result.Retryable = true
		return result
	}

	if bErr := m.evaluator.LoadBundle(stored.Record.Bundle, evalTime); bErr != nil {
		result.ErrorCode = ErrCodeActivationCommitUnconfirm
		result.Message = fmt.Sprintf("durable activation committed but could not be installed in memory: %s", bErr.Message)
		result.Retryable = true
		return result
	}

	m.record = &stored.Record
	m.stored = stored
	m.highestRevision = stored.Record.HighestRevision
	m.state = ActivationState{
		SchemaVersion:   ActivationSchemaVersion,
		Status:          ActivationStatusRestored,
		Active:          true,
		OperationID:     stored.Record.OperationID,
		BundleID:        stored.Record.Bundle.BundleID,
		Issuer:          stored.Record.Bundle.Issuer,
		SignerKeyID:     stored.Record.Bundle.SignerKeyID,
		Revision:        stored.Record.Bundle.Revision,
		HighestRevision: stored.Record.HighestRevision,
		Digest:          stored.Record.BundleDigest,
		StorageRevision: stored.StorageRevision,
		RestoredAt:      stored.CommittedAt,
		CheckedAt:       result.CheckedAt,
	}

	result.Status = ActivationStatusActivated
	result.Durable = true
	result.Replayed = commit.Replayed
	result.Active = true
	result.Retryable = false
	result.ErrorCode = ""
	result.Message = ""
	result.ActivatedAt = commit.CommittedAt
	result.StorageRevision = stored.StorageRevision
	result.HighestRevision = stored.Record.HighestRevision
	return result
}

func (m *ActivationManager) replayedResult(stored StoredActivation) ActivationResult {
	return ActivationResult{
		SchemaVersion:   ActivationSchemaVersion,
		Status:          ActivationStatusReplayed,
		Durable:         true,
		Replayed:        true,
		Active:          true,
		OperationID:     stored.Record.OperationID,
		BundleID:        stored.Record.Bundle.BundleID,
		Issuer:          stored.Record.Bundle.Issuer,
		SignerKeyID:     stored.Record.Bundle.SignerKeyID,
		Revision:        stored.Record.Bundle.Revision,
		HighestRevision: stored.Record.HighestRevision,
		Digest:          stored.Record.BundleDigest,
		StorageRevision: stored.StorageRevision,
		ActivatedAt:     stored.CommittedAt,
		CheckedAt:       m.state.CheckedAt,
	}
}

// validateActivationRecord rejects an internally inconsistent durable record before it can become
// authority. A rejected record blocks activation instead of silently resetting the revision floor.
func validateActivationRecord(stored StoredActivation) (string, string) {
	record := stored.Record
	corrupt := func(message string) (string, string) {
		return ErrCodeCorruptActivationState, message
	}

	if record.SchemaVersion != ActivationSchemaVersion {
		return corrupt(fmt.Sprintf("unsupported activation record schema_version '%s'", record.SchemaVersion))
	}
	if !activationIDPattern.MatchString(record.OperationID) {
		return corrupt(fmt.Sprintf("activation record operation_id '%s' is invalid", record.OperationID))
	}
	if stored.OperationID != record.OperationID {
		return corrupt(fmt.Sprintf("activation record operation_id '%s' does not match storage entry '%s'", record.OperationID, stored.OperationID))
	}
	if strings.TrimSpace(record.Actor) == "" {
		return corrupt("activation record is missing the authenticated actor")
	}
	if record.HighestRevision < 1 || record.HighestRevision != record.Bundle.Revision {
		return corrupt(fmt.Sprintf("activation record highest_revision %d does not match bundle revision %d", record.HighestRevision, record.Bundle.Revision))
	}
	computedDigest := policy.ComputeCanonicalBundleDigest(record.Bundle)
	if record.BundleDigest == "" || record.BundleDigest != record.Bundle.Digest || record.BundleDigest != computedDigest {
		return corrupt("activation record bundle digest does not match the persisted bundle content")
	}
	return "", ""
}

func activationStoreErrorCode(err error) string {
	var storeErr *ActivationStoreError
	if errors.As(err, &storeErr) {
		return storeErr.Code
	}
	return ErrCodeActivationStoreUnavail
}
