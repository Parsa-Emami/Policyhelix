package bundles

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	// TrustKeySchemaVersion is the schema version for durable trust key rotation records and results.
	TrustKeySchemaVersion = "1"

	// TrustKeyRecordID is the single durable record storing operator-controlled trust anchors and removed keys.
	TrustKeyRecordID       = "policyhelix:trust-keyring-state"
	TrustKeyOwnerScope     = "policyhelix"
	TrustKeyClassification = "private"
)

// Status values returned by KeyRotationManager operations (Requirement F19).
const (
	KeyRotationStatusRotated  = "rotated"
	KeyRotationStatusReplayed = "replayed"
	KeyRotationStatusRejected = "rejected"
	KeyRotationStatusRestored = "restored"
	KeyRotationStatusEmpty    = "empty"
)

// Typed error codes for trust key rotation and removed-key enforcement (Requirement F19).
const (
	ErrCodeInvalidKeyRotation   = "INVALID_KEY_ROTATION_REQUEST"
	ErrCodeRemovedKeyRejected   = "REMOVED_SIGNER_KEY_REJECTED"
	ErrCodeEmptyTrustedKeySet   = "EMPTY_TRUSTED_KEY_SET"
	ErrCodeRollbackGapDetected  = "ROLLBACK_GAP_REVISION_VIOLATION"
	ErrCodeProviderUnavailable  = "PROVIDER_UNAVAILABLE"
	ErrCodeCorruptKeyRotation   = "CORRUPT_KEY_ROTATION_STATE"
	ErrCodeKeyRotationUnconfirm = "KEY_ROTATION_COMMIT_UNCONFIRMED"
	ErrCodeKeyRotationCancelled = "KEY_ROTATION_CANCELLED"
)

// TrustKeyStateRecord is the durable, versioned state of the operator-controlled trust keyring,
// explicitly removed key IDs, and the monotonic bundle revision floor.
type TrustKeyStateRecord struct {
	SchemaVersion   string       `json:"schema_version"`
	OperationID     string       `json:"operation_id"`
	KeySetEpoch     int64        `json:"key_set_epoch"`
	TrustedKeys     []TrustedKey `json:"trusted_keys"`
	RemovedKeyIDs   []string     `json:"removed_key_ids"`
	HighestRevision int64        `json:"highest_revision"`
	Actor           string       `json:"actor"`
	UpdatedAt       string       `json:"updated_at"`
}

// StoredKeyState pairs a durable TrustKeyStateRecord with the storage metadata that committed it.
type StoredKeyState struct {
	Record          TrustKeyStateRecord
	StorageRevision int64
	ObjectDigest    string
	OperationID     string
	CommittedAt     string
}

// KeyStateStore is the durable authority port used by KeyRotationManager.
type KeyStateStore interface {
	CommitKeyState(ctx context.Context, record TrustKeyStateRecord, identity storage.CallerIdentity) (*ActivationCommit, error)
	LoadKeyState() (*StoredKeyState, error)
}

// StorageKeyStateStore adapts the C05 authoritative storage port to persist TrustKeyStateRecord.
type StorageKeyStateStore struct {
	adapter *storage.Adapter
}

// NewStorageKeyStateStore constructs a durable KeyStateStore backed by a storage.Adapter.
func NewStorageKeyStateStore(adapter *storage.Adapter) *StorageKeyStateStore {
	return &StorageKeyStateStore{adapter: adapter}
}

// CommitKeyState writes the trust key state record atomically via the storage adapter.
func (s *StorageKeyStateStore) CommitKeyState(ctx context.Context, record TrustKeyStateRecord, identity storage.CallerIdentity) (*ActivationCommit, error) {
	if s == nil || s.adapter == nil {
		return nil, &ActivationStoreError{
			Code:    ErrCodeActivationStoreUnavail,
			Message: "trust key state storage adapter is unavailable",
		}
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, &ActivationStoreError{
			Code:    ErrCodeCorruptKeyRotation,
			Message: fmt.Sprintf("failed to encode trust key state record: %v", err),
		}
	}

	receipt, sErr := s.adapter.WriteRecord(ctx, storage.WriteRequest{
		SchemaVersion:  storage.SchemaVersion,
		OperationID:    record.OperationID,
		RecordID:       TrustKeyRecordID,
		OwnerScope:     TrustKeyOwnerScope,
		Classification: TrustKeyClassification,
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

// LoadKeyState reads and digest-verifies the durable trust key state record.
func (s *StorageKeyStateStore) LoadKeyState() (*StoredKeyState, error) {
	if s == nil || s.adapter == nil {
		return nil, &ActivationStoreError{
			Code:    ErrCodeActivationStoreUnavail,
			Message: "trust key state storage adapter is unavailable",
		}
	}
	payload, entry, sErr := s.adapter.ReadRecord(TrustKeyRecordID)
	if sErr != nil {
		return nil, storeErrorFromStorage(sErr)
	}

	var record TrustKeyStateRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, &ActivationStoreError{
			Code:    ErrCodeCorruptKeyRotation,
			Message: fmt.Sprintf("durable trust key state record is not valid JSON: %v", err),
		}
	}

	return &StoredKeyState{
		Record:          record,
		StorageRevision: entry.Revision,
		ObjectDigest:    entry.ObjectDigest,
		OperationID:     entry.OperationID,
		CommittedAt:     entry.UpdatedAt,
	}, nil
}

// KeyRotationRequest is the operator-controlled input for rotating the trust keyring
// and optionally activating a successor bundle without a rollback gap.
type KeyRotationRequest struct {
	SchemaVersion       string                   `json:"schema_version,omitempty"`
	OperationID         string                   `json:"operation_id"`
	BundleOperationID   string                   `json:"bundle_operation_id,omitempty"`
	Identity            storage.CallerIdentity   `json:"identity"`
	EvaluationTime      string                   `json:"evaluation_time,omitempty"`
	ProviderUnavailable bool                     `json:"provider_unavailable,omitempty"`
	TrustedKeys         []TrustedKey             `json:"trusted_keys"`
	RemoveKeyIDs        []string                 `json:"remove_key_ids,omitempty"`
	CandidateBundle     *policy.LocalPolicyBundle `json:"candidate_bundle,omitempty"`
}

// KeyRotationResult is the typed outcome of an operator-controlled trust key rotation.
type KeyRotationResult struct {
	SchemaVersion     string   `json:"schema_version"`
	Status            string   `json:"status"`
	Valid             bool     `json:"valid"`
	Durable           bool     `json:"durable"`
	Replayed          bool     `json:"replayed"`
	Active            bool     `json:"active"`
	Retryable         bool     `json:"retryable"`
	OperationID       string   `json:"operation_id,omitempty"`
	KeySetEpoch       int64    `json:"key_set_epoch"`
	TrustedKeyIDs     []string `json:"trusted_key_ids"`
	RemovedKeyIDs     []string `json:"removed_key_ids"`
	ActiveBundleID    string   `json:"active_bundle_id,omitempty"`
	ActiveSignerKeyID string   `json:"active_signer_key_id,omitempty"`
	ActiveRevision    int64    `json:"active_revision,omitempty"`
	HighestRevision   int64    `json:"highest_revision"`
	StorageRevision   int64    `json:"storage_revision,omitempty"`
	CheckedAt         string   `json:"checked_at,omitempty"`
	ErrorCode         string   `json:"error_code,omitempty"`
	Message           string   `json:"message,omitempty"`
}

// KeyRotationState represents the restored trust keyring and active bundle state after restart.
type KeyRotationState struct {
	SchemaVersion     string       `json:"schema_version"`
	Status            string       `json:"status"`
	Valid             bool         `json:"valid"`
	Active            bool         `json:"active"`
	KeySetEpoch       int64        `json:"key_set_epoch"`
	TrustedKeys       []TrustedKey `json:"trusted_keys"`
	TrustedKeyIDs     []string     `json:"trusted_key_ids"`
	RemovedKeyIDs     []string     `json:"removed_key_ids"`
	ActiveBundleID    string       `json:"active_bundle_id,omitempty"`
	ActiveSignerKeyID string       `json:"active_signer_key_id,omitempty"`
	ActiveRevision    int64        `json:"active_revision,omitempty"`
	HighestRevision   int64        `json:"highest_revision"`
	StorageRevision   int64        `json:"storage_revision,omitempty"`
	CheckedAt         string       `json:"checked_at,omitempty"`
	ErrorCode         string       `json:"error_code,omitempty"`
	Message           string       `json:"message,omitempty"`
}

// KeyRotationManager coordinates operator-controlled trust key rotation, removed-key revocation
// enforcement, and atomic bundle activation without rollback gaps.
type KeyRotationManager struct {
	mu          sync.RWMutex
	keyStore    KeyStateStore
	actStore    ActivationStore
	keyring     *Keyring
	removedKeys map[string]bool
	actMgr      *ActivationManager
	Now         func() time.Time
	restored    bool
	blocked     bool
	keyRecord   *TrustKeyStateRecord
	keyStored   *StoredKeyState
	keyEpoch    int64
}

// NewKeyRotationManager constructs a KeyRotationManager bound to durable key and activation stores
// and an initial bootstrap keyring.
func NewKeyRotationManager(keyStore KeyStateStore, actStore ActivationStore, initialKeyring *Keyring) *KeyRotationManager {
	if initialKeyring == nil {
		initialKeyring = NewKeyring()
	}
	nowFn := func() time.Time { return time.Now().UTC() }
	actMgr := NewActivationManager(actStore, initialKeyring)
	actMgr.Now = nowFn
	return &KeyRotationManager{
		keyStore:    keyStore,
		actStore:    actStore,
		keyring:     initialKeyring,
		removedKeys: make(map[string]bool),
		actMgr:      actMgr,
		Now:         nowFn,
	}
}

// NewKeyRotationManagerFromAdapter constructs a KeyRotationManager using a storage.Adapter for both
// trust key state and bundle activation records.
func NewKeyRotationManagerFromAdapter(adapter *storage.Adapter, initialKeyring *Keyring) *KeyRotationManager {
	return NewKeyRotationManager(
		NewStorageKeyStateStore(adapter),
		NewStorageActivationStore(adapter),
		initialKeyring,
	)
}

// ValidateTrustedKeySet validates that the proposed trust set is non-empty, contains valid 32-byte
// Ed25519 public keys and issuers, has no duplicate key IDs, and does not overlap with removed keys.
func ValidateTrustedKeySet(keys []TrustedKey, removeKeyIDs []string) ([]TrustedKey, []string, string, string) {
	if len(keys) == 0 {
		return nil, nil, ErrCodeEmptyTrustedKeySet, "operator trust key set must contain at least one trusted Ed25519 public key"
	}

	removedSet := make(map[string]bool, len(removeKeyIDs))
	cleanedRemoved := make([]string, 0, len(removeKeyIDs))
	for _, rID := range removeKeyIDs {
		trimmed := strings.TrimSpace(rID)
		if trimmed == "" {
			return nil, nil, ErrCodeInvalidKeyRotation, "remove_key_ids must not contain empty strings"
		}
		if !activationIDPattern.MatchString(trimmed) {
			return nil, nil, ErrCodeInvalidKeyRotation, fmt.Sprintf("invalid removed key ID '%s'", trimmed)
		}
		if !removedSet[trimmed] {
			removedSet[trimmed] = true
			cleanedRemoved = append(cleanedRemoved, trimmed)
		}
	}
	sort.Strings(cleanedRemoved)

	seenKeys := make(map[string]TrustedKey, len(keys))
	keyIDs := make([]string, 0, len(keys))
	for _, tk := range keys {
		id := strings.TrimSpace(tk.SignerKeyID)
		issuer := strings.TrimSpace(tk.Issuer)
		pubHex := strings.TrimSpace(tk.PublicKeyHex)

		if id == "" || !activationIDPattern.MatchString(id) {
			return nil, nil, ErrCodeInvalidKeyRotation, fmt.Sprintf("invalid signer_key_id '%s' in trusted_keys", tk.SignerKeyID)
		}
		if issuer == "" {
			return nil, nil, ErrCodeInvalidKeyRotation, fmt.Sprintf("trusted key '%s' is missing required issuer", id)
		}
		if removedSet[id] {
			return nil, nil, ErrCodeInvalidKeyRotation, fmt.Sprintf("signer_key_id '%s' cannot be simultaneously in trusted_keys and remove_key_ids", id)
		}
		if _, dup := seenKeys[id]; dup {
			return nil, nil, ErrCodeInvalidKeyRotation, fmt.Sprintf("duplicate signer_key_id '%s' in trusted_keys", id)
		}

		pubBytes, err := hex.DecodeString(pubHex)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return nil, nil, ErrCodeInvalidKeyRotation, fmt.Sprintf("trusted key '%s' has malformed Ed25519 public_key_hex (expected 32 bytes / 64 hex chars)", id)
		}

		seenKeys[id] = TrustedKey{
			SignerKeyID:  id,
			Issuer:       issuer,
			PublicKeyHex: strings.ToLower(pubHex),
		}
		keyIDs = append(keyIDs, id)
	}
	sort.Strings(keyIDs)

	cleanedKeys := make([]TrustedKey, 0, len(keyIDs))
	for _, id := range keyIDs {
		cleanedKeys = append(cleanedKeys, seenKeys[id])
	}

	return cleanedKeys, cleanedRemoved, "", ""
}

// Restore reloads both the durable operator-controlled trust keyring and the active policy bundle.
// If the restored active bundle was signed by a key that has been removed in the durable trust state,
// the active bundle is rejected and the manager fails closed while preserving HighestRevision.
func (m *KeyRotationManager) Restore(ctx context.Context) KeyRotationState {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLocked(ctx)
}

func (m *KeyRotationManager) restoreLocked(ctx context.Context) KeyRotationState {
	now := m.Now().UTC()
	checkedAt := now.Format(time.RFC3339)
	if ctx.Err() != nil {
		return KeyRotationState{
			SchemaVersion: TrustKeySchemaVersion,
			Status:        KeyRotationStatusRejected,
			Valid:         false,
			CheckedAt:     checkedAt,
			ErrorCode:     ErrCodeKeyRotationCancelled,
			Message:       "trust key rotation restore cancelled before reading durable state",
		}
	}

	m.restored = true
	m.blocked = false
	m.keyRecord = nil
	m.keyStored = nil
	m.keyEpoch = 0

	// 1. Load durable trust key state if present
	if m.keyStore != nil {
		storedKey, err := m.keyStore.LoadKeyState()
		if err != nil {
			var storeErr *ActivationStoreError
			if !(errors.As(err, &storeErr) && storeErr.NotFound) {
				m.blocked = true
				return KeyRotationState{
					SchemaVersion: TrustKeySchemaVersion,
					Status:        KeyRotationStatusRejected,
					Valid:         false,
					CheckedAt:     checkedAt,
					ErrorCode:     activationStoreErrorCode(err),
					Message:       err.Error(),
				}
			}
		} else if storedKey != nil {
			if code, msg := validateKeyStateRecord(*storedKey); code != "" {
				m.blocked = true
				return KeyRotationState{
					SchemaVersion: TrustKeySchemaVersion,
					Status:        KeyRotationStatusRejected,
					Valid:         false,
					CheckedAt:     checkedAt,
					ErrorCode:     code,
					Message:       msg,
				}
			}
			rec := storedKey.Record
			m.keyRecord = &rec
			m.keyStored = storedKey
			m.keyEpoch = rec.KeySetEpoch
			m.keyring = NewKeyring(rec.TrustedKeys...)
			m.removedKeys = make(map[string]bool, len(rec.RemovedKeyIDs))
			for _, id := range rec.RemovedKeyIDs {
				m.removedKeys[id] = true
			}
		}
	}

	// 2. Synchronize ActivationManager with the active keyring and restore durable bundle
	m.actMgr.mu.Lock()
	m.actMgr.keyring = m.keyring
	m.actMgr.Now = m.Now
	var actState ActivationState
	if m.actStore != nil {
		actState = m.actMgr.restoreLocked()
	} else {
		m.actMgr.restored = true
		m.actMgr.evaluator = m.keyring.NewEvaluator()
		m.actMgr.state = ActivationState{
			SchemaVersion: ActivationSchemaVersion,
			Status:        ActivationStatusEmpty,
			CheckedAt:     checkedAt,
		}
		actState = m.actMgr.state
	}
	if m.keyRecord != nil && m.keyRecord.HighestRevision > m.actMgr.highestRevision {
		m.actMgr.highestRevision = m.keyRecord.HighestRevision
	}
	highestRev := m.actMgr.highestRevision

	// Verify that if a bundle is active, its signer key was not explicitly removed
	if actState.Active && m.removedKeys[actState.SignerKeyID] {
		m.actMgr.state.Active = false
		m.actMgr.state.Status = ActivationStatusRejected
		m.actMgr.state.ErrorCode = ErrCodeRemovedKeyRejected
		m.actMgr.state.Message = fmt.Sprintf("active bundle signer_key_id '%s' was removed by operator key rotation", actState.SignerKeyID)
		m.actMgr.evaluator = m.keyring.NewEvaluator()
		actState = m.actMgr.state
	}
	m.actMgr.mu.Unlock()

	if m.actMgr.blocked {
		m.blocked = true
		return KeyRotationState{
			SchemaVersion:   TrustKeySchemaVersion,
			Status:          KeyRotationStatusRejected,
			Valid:           false,
			Active:          false,
			KeySetEpoch:     m.keyEpoch,
			TrustedKeys:     m.keyring.TrustedKeys(),
			TrustedKeyIDs:   m.trustedKeyIDsLocked(),
			RemovedKeyIDs:   m.removedKeyIDsLocked(),
			HighestRevision: highestRev,
			CheckedAt:       checkedAt,
			ErrorCode:       actState.ErrorCode,
			Message:         actState.Message,
		}
	}

	status := KeyRotationStatusRestored
	if m.keyRecord == nil && actState.Status == ActivationStatusEmpty {
		status = KeyRotationStatusEmpty
	}

	state := KeyRotationState{
		SchemaVersion:   TrustKeySchemaVersion,
		Status:          status,
		Valid:           true,
		Active:          actState.Active,
		KeySetEpoch:     m.keyEpoch,
		TrustedKeys:     m.keyring.TrustedKeys(),
		TrustedKeyIDs:   m.trustedKeyIDsLocked(),
		RemovedKeyIDs:   m.removedKeyIDsLocked(),
		HighestRevision: highestRev,
		CheckedAt:       checkedAt,
	}
	if m.keyStored != nil {
		state.StorageRevision = m.keyStored.StorageRevision
	}
	if actState.Active {
		state.ActiveBundleID = actState.BundleID
		state.ActiveSignerKeyID = actState.SignerKeyID
		state.ActiveRevision = actState.Revision
	}
	return state
}

// RotateKeys executes an operator-controlled trust key rotation, permanently recording removed key IDs,
// preserving the monotonic revision floor without rollback gap, and optionally activating a successor bundle.
func (m *KeyRotationManager) RotateKeys(ctx context.Context, req KeyRotationRequest) KeyRotationResult {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rotateKeysLocked(ctx, req)
}

func (m *KeyRotationManager) rotateKeysLocked(ctx context.Context, req KeyRotationRequest) KeyRotationResult {
	evalTime := m.Now().UTC()
	if strings.TrimSpace(req.EvaluationTime) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.EvaluationTime))
		if err != nil {
			return m.rejectedResultLocked(req.OperationID, evalTime, ErrCodeInvalidKeyRotation, fmt.Sprintf("evaluation_time must be valid RFC3339: %v", err), false)
		}
		evalTime = parsed.UTC()
	}
	checkedAt := evalTime.Format(time.RFC3339)

	if ctx.Err() != nil {
		return m.rejectedResultLocked(req.OperationID, evalTime, ErrCodeKeyRotationCancelled, "trust key rotation cancelled before execution", true)
	}

	schemaVersion := strings.TrimSpace(req.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = TrustKeySchemaVersion
	}
	if schemaVersion != TrustKeySchemaVersion {
		return m.rejectedResultLocked(req.OperationID, evalTime, ErrCodeInvalidKeyRotation, fmt.Sprintf("unsupported key rotation schema_version '%s'; expected '%s'", schemaVersion, TrustKeySchemaVersion), false)
	}

	opID := strings.TrimSpace(req.OperationID)
	if opID == "" || !activationIDPattern.MatchString(opID) {
		return m.rejectedResultLocked(opID, evalTime, ErrCodeInvalidKeyRotation, "operation_id is required and must match valid identifier pattern", false)
	}

	if req.ProviderUnavailable || strings.EqualFold(strings.TrimSpace(req.Identity.ProviderState), "unavailable") {
		return m.rejectedResultLocked(opID, evalTime, ErrCodeProviderUnavailable, "required identity or policy provider is unavailable; failing closed", true)
	}

	// 1. Enforce operator authorization and private scope security gate before any mutation or replay
	securityProbe := storage.WriteRequest{
		SchemaVersion:  storage.SchemaVersion,
		OperationID:    opID,
		RecordID:       TrustKeyRecordID,
		OwnerScope:     TrustKeyOwnerScope,
		Classification: TrustKeyClassification,
		Identity:       req.Identity,
		Payload:        json.RawMessage(`{}`),
	}
	if sErr := storage.ValidateIdentityAndScope(securityProbe); sErr != nil {
		return m.rejectedResultLocked(opID, evalTime, sErr.Code, sErr.Message, sErr.Retryable)
	}

	if !m.restored {
		m.restoreLocked(ctx)
	}
	if m.blocked {
		return m.rejectedResultLocked(opID, evalTime, ErrCodeCorruptKeyRotation, "durable trust key or activation state is corrupt; refusing to overwrite", false)
	}

	// 2. Validate proposed trusted keys and removed key IDs
	cleanedKeys, cleanedRemoved, errCode, errMsg := ValidateTrustedKeySet(req.TrustedKeys, req.RemoveKeyIDs)
	if errCode != "" {
		return m.rejectedResultLocked(opID, evalTime, errCode, errMsg, false)
	}

	// Merge previously removed keys that are not explicitly re-authorized by the operator,
	// and mark any previously trusted key omitted from the new trust set as removed.
	combinedRemoved := make(map[string]bool)
	newKeyMap := make(map[string]TrustedKey, len(cleanedKeys))
	for _, tk := range cleanedKeys {
		newKeyMap[tk.SignerKeyID] = tk
	}
	for prevRemoved := range m.removedKeys {
		if _, readded := newKeyMap[prevRemoved]; !readded {
			combinedRemoved[prevRemoved] = true
		}
	}
	for _, curKey := range m.keyring.TrustedKeys() {
		if _, stillPresent := newKeyMap[curKey.SignerKeyID]; !stillPresent {
			combinedRemoved[curKey.SignerKeyID] = true
		}
	}
	for _, rID := range cleanedRemoved {
		combinedRemoved[rID] = true
	}

	// Ensure none of the proposed TrustedKeys is in the explicit remove request
	for _, rID := range cleanedRemoved {
		if _, exists := newKeyMap[rID]; exists {
			return m.rejectedResultLocked(opID, evalTime, ErrCodeInvalidKeyRotation, fmt.Sprintf("key '%s' cannot be both trusted and removed", rID), false)
		}
	}

	mergedRemovedList := make([]string, 0, len(combinedRemoved))
	for rID := range combinedRemoved {
		mergedRemovedList = append(mergedRemovedList, rID)
	}
	sort.Strings(mergedRemovedList)

	currentHighest := m.HighestRevisionLocked()

	// 3. Check for idempotent operation replay
	if m.keyRecord != nil && m.keyRecord.OperationID == opID {
		if m.keyRecord.Actor != req.Identity.SubjectID || !equalTrustedKeys(m.keyRecord.TrustedKeys, cleanedKeys) {
			return m.rejectedResultLocked(opID, evalTime, storage.ErrOperationConflict, fmt.Sprintf("operation_id '%s' was already committed with different trust keys or actor", opID), false)
		}
		res := m.currentResultLocked(opID, checkedAt)
		res.Status = KeyRotationStatusReplayed
		res.Replayed = true
		return res
	}

	candidateKeyring := NewKeyring(cleanedKeys...)

	// 4. If a CandidateBundle is supplied with the rotation, verify it against the NEW trust set
	// and the existing monotonic revision floor BEFORE committing the key rotation.
	if req.CandidateBundle != nil {
		cand := *req.CandidateBundle
		if combinedRemoved[strings.TrimSpace(cand.SignerKeyID)] {
			return m.rejectedResultLocked(opID, evalTime, ErrCodeRemovedKeyRejected, fmt.Sprintf("candidate bundle signer_key_id '%s' has been removed from trust set", cand.SignerKeyID), false)
		}
		verification := verifyAt(cand, candidateKeyring, evalTime, currentHighest, BundleVerification{})
		if !verification.Verified {
			return m.rejectedResultLocked(opID, evalTime, verification.ErrorCode, verification.Message, false)
		}
		candEval := candidateKeyring.NewEvaluator()
		if _, bErr := candEval.ValidateBundle(cand, evalTime); bErr != nil {
			return m.rejectedResultLocked(opID, evalTime, bErr.Code, bErr.Message, false)
		}
	}

	newHighest := currentHighest
	if req.CandidateBundle != nil && req.CandidateBundle.Revision > newHighest {
		newHighest = req.CandidateBundle.Revision
	}

	nextEpoch := m.keyEpoch + 1
	record := TrustKeyStateRecord{
		SchemaVersion:   TrustKeySchemaVersion,
		OperationID:     opID,
		KeySetEpoch:     nextEpoch,
		TrustedKeys:     cleanedKeys,
		RemovedKeyIDs:   mergedRemovedList,
		HighestRevision: newHighest,
		Actor:           req.Identity.SubjectID,
		UpdatedAt:       checkedAt,
	}

	// 5. Commit trust key state durably
	var storageRev int64
	replayedCommit := false
	if m.keyStore != nil {
		commit, err := m.keyStore.CommitKeyState(ctx, record, req.Identity)
		if err != nil {
			retryable := false
			var storeErr *ActivationStoreError
			if errors.As(err, &storeErr) {
				retryable = storeErr.Retryable
			}
			return m.rejectedResultLocked(opID, evalTime, activationStoreErrorCode(err), err.Error(), retryable)
		}
		storageRev = commit.StorageRevision
		replayedCommit = commit.Replayed

		storedKey, loadErr := m.keyStore.LoadKeyState()
		if loadErr != nil {
			return m.rejectedResultLocked(opID, evalTime, ErrCodeKeyRotationUnconfirm, fmt.Sprintf("key rotation write could not be read back: %v", loadErr), true)
		}
		if code, msg := validateKeyStateRecord(*storedKey); code != "" {
			return m.rejectedResultLocked(opID, evalTime, code, msg, false)
		}
		m.keyStored = storedKey
	}

	// 6. Update in-memory trust anchors and synchronize ActivationManager
	m.keyRecord = &record
	m.keyEpoch = nextEpoch
	m.keyring = candidateKeyring
	m.removedKeys = combinedRemoved

	m.actMgr.mu.Lock()
	m.actMgr.keyring = candidateKeyring
	m.actMgr.Now = func() time.Time { return evalTime }
	if newHighest > m.actMgr.highestRevision {
		m.actMgr.highestRevision = newHighest
	}

	// If no replacement bundle was provided, verify whether the currently active bundle's signer was removed.
	// If its signer was removed, immediately deactivate in-memory authority (fail closed) while retaining HighestRevision.
	if req.CandidateBundle == nil && m.actMgr.state.Active {
		activeSigner := m.actMgr.state.SignerKeyID
		if combinedRemoved[activeSigner] || !candidateKeyring.HasKey(activeSigner) {
			m.actMgr.state.Active = false
			m.actMgr.state.Status = ActivationStatusRejected
			m.actMgr.state.ErrorCode = ErrCodeRemovedKeyRejected
			m.actMgr.state.Message = fmt.Sprintf("active bundle signer '%s' removed by operator rotation; failing closed until a bundle signed by the new trust set is activated", activeSigner)
			m.actMgr.evaluator = candidateKeyring.NewEvaluator()
		} else {
			// Rebuild evaluator with updated trusted issuers/signers and reload active bundle
			newEval := candidateKeyring.NewEvaluator()
			if m.actMgr.record != nil {
				_ = newEval.LoadBundle(m.actMgr.record.Bundle, evalTime)
			}
			m.actMgr.evaluator = newEval
		}
	}
	m.actMgr.mu.Unlock()

	// 7. If a CandidateBundle was provided, atomically activate it through ActivationManager
	if req.CandidateBundle != nil {
		bundleOpID := strings.TrimSpace(req.BundleOperationID)
		if bundleOpID == "" {
			bundleOpID = opID + "-bundle"
		}
		m.actMgr.mu.Lock()
		m.actMgr.highestRevision = currentHighest
		m.actMgr.evaluator = candidateKeyring.NewEvaluator()
		if m.actStore != nil {
			actRes := m.actMgr.activateLocked(ctx, ActivationRequest{
				SchemaVersion: ActivationSchemaVersion,
				OperationID:   bundleOpID,
				Identity:      req.Identity,
				Bundle:        *req.CandidateBundle,
			})
			m.actMgr.mu.Unlock()
			if actRes.Status == ActivationStatusRejected {
				return m.rejectedResultLocked(opID, evalTime, actRes.ErrorCode, actRes.Message, actRes.Retryable)
			}
		} else {
			if bErr := m.actMgr.evaluator.LoadBundle(*req.CandidateBundle, evalTime); bErr != nil {
				m.actMgr.mu.Unlock()
				return m.rejectedResultLocked(opID, evalTime, bErr.Code, bErr.Message, false)
			}
			m.actMgr.highestRevision = req.CandidateBundle.Revision
			m.actMgr.state = ActivationState{
				SchemaVersion:   ActivationSchemaVersion,
				Status:          ActivationStatusRestored,
				Active:          true,
				OperationID:     bundleOpID,
				BundleID:        req.CandidateBundle.BundleID,
				Issuer:          req.CandidateBundle.Issuer,
				SignerKeyID:     req.CandidateBundle.SignerKeyID,
				Revision:        req.CandidateBundle.Revision,
				HighestRevision: req.CandidateBundle.Revision,
				Digest:          req.CandidateBundle.Digest,
				CheckedAt:       checkedAt,
			}
			m.actMgr.mu.Unlock()
		}
	}

	res := m.currentResultLocked(opID, checkedAt)
	res.Status = KeyRotationStatusRotated
	if replayedCommit {
		res.Status = KeyRotationStatusReplayed
		res.Replayed = true
	}
	res.StorageRevision = storageRev
	return res
}

// ActivateBundle attempts to activate a candidate policy bundle under the current operator-controlled
// trust keyring. Any bundle signed by a removed key or with a revision <= HighestRevision is rejected
// without altering the existing valid authority or revision floor.
func (m *KeyRotationManager) ActivateBundle(ctx context.Context, req ActivationRequest, evalTimeStr string) ActivationResult {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.restored {
		m.restoreLocked(ctx)
	}

	evalTime := m.Now().UTC()
	if strings.TrimSpace(evalTimeStr) != "" {
		if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(evalTimeStr)); err == nil {
			evalTime = parsed.UTC()
		}
	}

	signerID := strings.TrimSpace(req.Bundle.SignerKeyID)
	highestRev := m.HighestRevisionLocked()

	// Check security gate first so unauthenticated callers cannot probe key state
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
		return ActivationResult{
			SchemaVersion:   ActivationSchemaVersion,
			Status:          ActivationStatusRejected,
			Active:          m.actMgr.state.Active,
			Retryable:       sErr.Retryable,
			OperationID:     strings.TrimSpace(req.OperationID),
			BundleID:        strings.TrimSpace(req.Bundle.BundleID),
			Issuer:          strings.TrimSpace(req.Bundle.Issuer),
			SignerKeyID:     signerID,
			Revision:        req.Bundle.Revision,
			HighestRevision: highestRev,
			Digest:          strings.TrimSpace(req.Bundle.Digest),
			CheckedAt:       evalTime.Format(time.RFC3339),
			ErrorCode:       sErr.Code,
			Message:         sErr.Message,
		}
	}

	// Explicitly block removed keys from activating any old or new signed bundle (Requirement F19)
	if signerID != "" && m.removedKeys[signerID] {
		return ActivationResult{
			SchemaVersion:   ActivationSchemaVersion,
			Status:          ActivationStatusRejected,
			Active:          m.actMgr.state.Active,
			OperationID:     strings.TrimSpace(req.OperationID),
			BundleID:        strings.TrimSpace(req.Bundle.BundleID),
			Issuer:          strings.TrimSpace(req.Bundle.Issuer),
			SignerKeyID:     signerID,
			Revision:        req.Bundle.Revision,
			HighestRevision: highestRev,
			Digest:          strings.TrimSpace(req.Bundle.Digest),
			CheckedAt:       evalTime.Format(time.RFC3339),
			ErrorCode:       ErrCodeRemovedKeyRejected,
			Message:         fmt.Sprintf("signer_key_id '%s' was removed from the operator trust set and cannot activate any bundle", signerID),
		}
	}

	m.actMgr.mu.Lock()
	m.actMgr.keyring = m.keyring
	m.actMgr.Now = func() time.Time { return evalTime }
	if highestRev > m.actMgr.highestRevision {
		m.actMgr.highestRevision = highestRev
	}
	res := m.actMgr.activateLocked(ctx, req)
	newHighest := m.actMgr.highestRevision
	m.actMgr.mu.Unlock()

	if m.keyRecord != nil && newHighest > m.keyRecord.HighestRevision {
		m.keyRecord.HighestRevision = newHighest
	}
	return res
}

// Evaluate authorizes an input against the currently active policy bundle and rotated trust set.
// Fails closed if no valid bundle is active or if the input is unauthenticated on a private route.
func (m *KeyRotationManager) Evaluate(ctx context.Context, input policy.BundleEvalInput) policy.BundleDecision {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.actMgr.Evaluate(ctx, input)
}

// ActiveBundle returns the currently active policy bundle and whether a valid authority is in force.
func (m *KeyRotationManager) ActiveBundle() (policy.LocalPolicyBundle, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.actMgr.Active()
}

// State returns a snapshot of the current trust key set, removed keys, and active bundle metadata.
func (m *KeyRotationManager) State() KeyRotationState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := m.Now().UTC().Format(time.RFC3339)
	highestRev := m.HighestRevisionLocked()
	actBundle, active := m.actMgr.Active()

	status := KeyRotationStatusRestored
	if m.keyEpoch == 0 && !active {
		status = KeyRotationStatusEmpty
	}
	state := KeyRotationState{
		SchemaVersion:   TrustKeySchemaVersion,
		Status:          status,
		Valid:           !m.blocked,
		Active:          active,
		KeySetEpoch:     m.keyEpoch,
		TrustedKeys:     m.keyring.TrustedKeys(),
		TrustedKeyIDs:   m.trustedKeyIDsLocked(),
		RemovedKeyIDs:   m.removedKeyIDsLocked(),
		HighestRevision: highestRev,
		CheckedAt:       now,
	}
	if m.keyStored != nil {
		state.StorageRevision = m.keyStored.StorageRevision
	}
	if active {
		state.ActiveBundleID = actBundle.BundleID
		state.ActiveSignerKeyID = actBundle.SignerKeyID
		state.ActiveRevision = actBundle.Revision
	}
	return state
}

// HighestRevisionLocked returns the highest accepted revision across both key rotation and activation state.
func (m *KeyRotationManager) HighestRevisionLocked() int64 {
	rev := m.actMgr.highestRevision
	if m.keyRecord != nil && m.keyRecord.HighestRevision > rev {
		rev = m.keyRecord.HighestRevision
	}
	return rev
}

// HasKey reports whether signerKeyID is present in the Keyring.
func (k *Keyring) HasKey(signerKeyID string) bool {
	if k == nil {
		return false
	}
	_, ok := k.keys[strings.TrimSpace(signerKeyID)]
	return ok
}

func (m *KeyRotationManager) trustedKeyIDsLocked() []string {
	tks := m.keyring.TrustedKeys()
	ids := make([]string, 0, len(tks))
	for _, tk := range tks {
		ids = append(ids, tk.SignerKeyID)
	}
	return ids
}

func (m *KeyRotationManager) removedKeyIDsLocked() []string {
	ids := make([]string, 0, len(m.removedKeys))
	for id := range m.removedKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (m *KeyRotationManager) currentResultLocked(opID, checkedAt string) KeyRotationResult {
	actBundle, active := m.actMgr.Active()
	res := KeyRotationResult{
		SchemaVersion:   TrustKeySchemaVersion,
		Status:          KeyRotationStatusRotated,
		Valid:           true,
		Durable:         m.keyStore != nil,
		Active:          active,
		OperationID:     opID,
		KeySetEpoch:     m.keyEpoch,
		TrustedKeyIDs:   m.trustedKeyIDsLocked(),
		RemovedKeyIDs:   m.removedKeyIDsLocked(),
		HighestRevision: m.HighestRevisionLocked(),
		CheckedAt:       checkedAt,
	}
	if active {
		res.ActiveBundleID = actBundle.BundleID
		res.ActiveSignerKeyID = actBundle.SignerKeyID
		res.ActiveRevision = actBundle.Revision
	}
	return res
}

func (m *KeyRotationManager) rejectedResultLocked(opID string, evalTime time.Time, errCode, message string, retryable bool) KeyRotationResult {
	actBundle, active := m.actMgr.Active()
	res := KeyRotationResult{
		SchemaVersion:   TrustKeySchemaVersion,
		Status:          KeyRotationStatusRejected,
		Valid:           false,
		Durable:         m.keyStore != nil && m.keyStored != nil,
		Active:          active,
		Retryable:       retryable,
		OperationID:     opID,
		KeySetEpoch:     m.keyEpoch,
		TrustedKeyIDs:   m.trustedKeyIDsLocked(),
		RemovedKeyIDs:   m.removedKeyIDsLocked(),
		HighestRevision: m.HighestRevisionLocked(),
		CheckedAt:       evalTime.Format(time.RFC3339),
		ErrorCode:       errCode,
		Message:         message,
	}
	if active {
		res.ActiveBundleID = actBundle.BundleID
		res.ActiveSignerKeyID = actBundle.SignerKeyID
		res.ActiveRevision = actBundle.Revision
	}
	return res
}

func validateKeyStateRecord(stored StoredKeyState) (string, string) {
	rec := stored.Record
	corrupt := func(msg string) (string, string) {
		return ErrCodeCorruptKeyRotation, msg
	}
	if rec.SchemaVersion != TrustKeySchemaVersion {
		return corrupt(fmt.Sprintf("unsupported trust key record schema_version '%s'", rec.SchemaVersion))
	}
	if !activationIDPattern.MatchString(rec.OperationID) {
		return corrupt(fmt.Sprintf("trust key record operation_id '%s' is invalid", rec.OperationID))
	}
	if stored.OperationID != "" && stored.OperationID != rec.OperationID {
		return corrupt(fmt.Sprintf("trust key record operation_id '%s' does not match storage entry '%s'", rec.OperationID, stored.OperationID))
	}
	if rec.KeySetEpoch < 1 {
		return corrupt("trust key record key_set_epoch must be >= 1")
	}
	if rec.HighestRevision < 0 {
		return corrupt("trust key record highest_revision must be >= 0")
	}
	if strings.TrimSpace(rec.Actor) == "" {
		return corrupt("trust key record is missing authenticated actor")
	}
	if _, _, code, msg := ValidateTrustedKeySet(rec.TrustedKeys, rec.RemovedKeyIDs); code != "" {
		return corrupt(fmt.Sprintf("persisted trust key set invalid (%s): %s", code, msg))
	}
	return "", ""
}

func equalTrustedKeys(a, b []TrustedKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].SignerKeyID != b[i].SignerKeyID ||
			a[i].Issuer != b[i].Issuer ||
			!strings.EqualFold(a[i].PublicKeyHex, b[i].PublicKeyHex) {
			return false
		}
	}
	return true
}

// KeyRotationFixture defines a declarative test/CLI fixture for C25 key rotation and activation scenarios.
type KeyRotationFixture struct {
	FixtureID           string                    `json:"fixture_id"`
	CommitID            string                    `json:"commit_id,omitempty"`
	Description         string                    `json:"description,omitempty"`
	SchemaVersion       string                    `json:"schema_version"`
	EvaluationTime      string                    `json:"evaluation_time,omitempty"`
	InitialTrustedKeys  []TrustedKey              `json:"initial_trusted_keys"`
	PreloadActivation   *ActivationRequest        `json:"preload_activation,omitempty"`
	Rotations           []KeyRotationRequest      `json:"rotations,omitempty"`
	PostActivations     []ActivationRequest       `json:"post_activations,omitempty"`
	SimulateRestart     bool                      `json:"simulate_restart,omitempty"`
	PostRestartActivate *ActivationRequest        `json:"post_restart_activate,omitempty"`
	Evaluation          *policy.BundleEvalInput   `json:"evaluation,omitempty"`
	Expected            KeyRotationFixtureExpect  `json:"expected"`
}

// KeyRotationFixtureExpect captures expected outcomes for a KeyRotationFixture.
type KeyRotationFixtureExpect struct {
	RotationStatus          string   `json:"rotation_status,omitempty"`
	RotationValid           *bool    `json:"rotation_valid,omitempty"`
	RotationErrorCode       string   `json:"rotation_error_code,omitempty"`
	PostActivationStatus    string   `json:"post_activation_status,omitempty"`
	PostActivationErrorCode string   `json:"post_activation_error_code,omitempty"`
	PostRestartErrorCode    string   `json:"post_restart_error_code,omitempty"`
	KeySetEpoch             int64    `json:"key_set_epoch,omitempty"`
	TrustedKeyIDs           []string `json:"trusted_key_ids,omitempty"`
	RemovedKeyIDs           []string `json:"removed_key_ids,omitempty"`
	Active                  *bool    `json:"active,omitempty"`
	ActiveSignerKeyID       string   `json:"active_signer_key_id,omitempty"`
	ActiveRevision          int64    `json:"active_revision,omitempty"`
	HighestRevision         int64    `json:"highest_revision,omitempty"`
	Allow                   *bool    `json:"allow,omitempty"`
	DecisionReasonCode      string   `json:"decision_reason_code,omitempty"`
}

// KeyRotationScenarioReport is the structured execution output of RunKeyRotationFixture.
type KeyRotationScenarioReport struct {
	FixtureID            string                 `json:"fixture_id,omitempty"`
	SchemaVersion        string                 `json:"schema_version"`
	Passed               bool                   `json:"passed"`
	Status               string                 `json:"status"`
	ErrorCode            string                 `json:"error_code,omitempty"`
	Message              string                 `json:"message,omitempty"`
	LastRotation         *KeyRotationResult     `json:"last_rotation,omitempty"`
	LastActivation       *ActivationResult      `json:"last_activation,omitempty"`
	PostRestartActivation *ActivationResult     `json:"post_restart_activation,omitempty"`
	State                KeyRotationState       `json:"state"`
	Decision             *policy.BundleDecision `json:"decision,omitempty"`
}

// RunKeyRotationFixture executes a KeyRotationFixture against a durable storage directory
// (including optional simulated restart) and validates all expected invariants.
func RunKeyRotationFixture(ctx context.Context, storageDir string, fx KeyRotationFixture) (KeyRotationScenarioReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	report := KeyRotationScenarioReport{
		FixtureID:     fx.FixtureID,
		SchemaVersion: TrustKeySchemaVersion,
		Status:        KeyRotationStatusRejected,
	}

	if strings.TrimSpace(fx.SchemaVersion) != "" && strings.TrimSpace(fx.SchemaVersion) != TrustKeySchemaVersion {
		report.ErrorCode = ErrCodeInvalidKeyRotation
		report.Message = fmt.Sprintf("unsupported fixture schema_version '%s'", fx.SchemaVersion)
		return report, fmt.Errorf("%s: %s", report.ErrorCode, report.Message)
	}

	evalTime := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	if strings.TrimSpace(fx.EvaluationTime) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(fx.EvaluationTime))
		if err != nil {
			report.ErrorCode = ErrCodeInvalidKeyRotation
			report.Message = fmt.Sprintf("invalid evaluation_time: %v", err)
			return report, fmt.Errorf("%s: %s", report.ErrorCode, report.Message)
		}
		evalTime = parsed.UTC()
	}

	openMgr := func() (*storage.Adapter, *KeyRotationManager, error) {
		ad, _, err := storage.Open(storageDir)
		if err != nil {
			return nil, nil, err
		}
		mgr := NewKeyRotationManagerFromAdapter(ad, NewKeyring(fx.InitialTrustedKeys...))
		mgr.Now = func() time.Time { return evalTime }
		return ad, mgr, nil
	}

	ad, mgr, err := openMgr()
	if err != nil {
		report.ErrorCode = ErrCodeActivationStoreUnavail
		report.Message = err.Error()
		return report, err
	}
	defer func() {
		if ad != nil {
			_ = ad.Close()
		}
	}()

	// 1. Preload initial activation if specified
	if fx.PreloadActivation != nil {
		preRes := mgr.ActivateBundle(ctx, *fx.PreloadActivation, fx.EvaluationTime)
		if preRes.Status == ActivationStatusRejected {
			report.LastActivation = &preRes
			report.ErrorCode = preRes.ErrorCode
			report.Message = fmt.Sprintf("preload activation failed: %s", preRes.Message)
			return report, fmt.Errorf("%s: %s", report.ErrorCode, report.Message)
		}
		report.LastActivation = &preRes
	}

	// 2. Execute rotation steps
	for _, rotReq := range fx.Rotations {
		if rotReq.EvaluationTime == "" {
			rotReq.EvaluationTime = fx.EvaluationTime
		}
		rotRes := mgr.RotateKeys(ctx, rotReq)
		report.LastRotation = &rotRes
		if !rotRes.Valid {
			report.ErrorCode = rotRes.ErrorCode
			report.Message = rotRes.Message
		}
	}

	// 3. Execute post-rotation bundle activation attempts
	for _, actReq := range fx.PostActivations {
		actRes := mgr.ActivateBundle(ctx, actReq, fx.EvaluationTime)
		report.LastActivation = &actRes
		if actRes.Status == ActivationStatusRejected && report.ErrorCode == "" {
			report.ErrorCode = actRes.ErrorCode
			report.Message = actRes.Message
		}
	}

	// 4. Simulate process restart and recovery if requested
	if fx.SimulateRestart {
		_ = ad.Close()
		ad = nil

		ad2, mgr2, err := openMgr()
		if err != nil {
			report.ErrorCode = ErrCodeActivationStoreUnavail
			report.Message = fmt.Sprintf("restart storage open failed: %v", err)
			return report, err
		}
		ad = ad2
		mgr = mgr2

		restoredState := mgr.Restore(ctx)
		report.State = restoredState
		if !restoredState.Valid {
			report.ErrorCode = restoredState.ErrorCode
			report.Message = restoredState.Message
		}

		if fx.PostRestartActivate != nil {
			postRes := mgr.ActivateBundle(ctx, *fx.PostRestartActivate, fx.EvaluationTime)
			report.PostRestartActivation = &postRes
			if postRes.Status == ActivationStatusRejected && report.ErrorCode == "" {
				report.ErrorCode = postRes.ErrorCode
				report.Message = postRes.Message
			}
		}
	} else {
		report.State = mgr.State()
	}

	// 5. Evaluate authorization input if provided
	if fx.Evaluation != nil {
		evalInput := *fx.Evaluation
		if evalInput.EvalTime == "" {
			evalInput.EvalTime = evalTime.Format(time.RFC3339)
		}
		dec := mgr.Evaluate(ctx, evalInput)
		report.Decision = &dec
	}

	// 6. Verify expected assertions
	if err := verifyKeyRotationExpectations(fx.Expected, &report); err != nil {
		report.Passed = false
		report.Status = KeyRotationStatusRejected
		return report, err
	}

	report.Passed = true
	if report.LastRotation != nil {
		report.Status = report.LastRotation.Status
	} else {
		report.Status = report.State.Status
	}
	return report, nil
}

func verifyKeyRotationExpectations(exp KeyRotationFixtureExpect, rep *KeyRotationScenarioReport) error {
	if exp.RotationStatus != "" {
		if rep.LastRotation == nil || rep.LastRotation.Status != exp.RotationStatus {
			got := "<nil>"
			if rep.LastRotation != nil {
				got = rep.LastRotation.Status
			}
			return fmt.Errorf("expected rotation_status=%s, got %s (err=%s: %s)", exp.RotationStatus, got, rep.ErrorCode, rep.Message)
		}
	}
	if exp.RotationValid != nil {
		if rep.LastRotation == nil || rep.LastRotation.Valid != *exp.RotationValid {
			return fmt.Errorf("expected rotation_valid=%v", *exp.RotationValid)
		}
	}
	if exp.RotationErrorCode != "" {
		if rep.LastRotation == nil || rep.LastRotation.ErrorCode != exp.RotationErrorCode {
			got := "<nil>"
			if rep.LastRotation != nil {
				got = rep.LastRotation.ErrorCode
			}
			return fmt.Errorf("expected rotation_error_code=%s, got %s", exp.RotationErrorCode, got)
		}
	}
	if exp.PostActivationStatus != "" {
		if rep.LastActivation == nil || rep.LastActivation.Status != exp.PostActivationStatus {
			got := "<nil>"
			if rep.LastActivation != nil {
				got = rep.LastActivation.Status
			}
			return fmt.Errorf("expected post_activation_status=%s, got %s", exp.PostActivationStatus, got)
		}
	}
	if exp.PostActivationErrorCode != "" {
		if rep.LastActivation == nil || rep.LastActivation.ErrorCode != exp.PostActivationErrorCode {
			got := "<nil>"
			if rep.LastActivation != nil {
				got = rep.LastActivation.ErrorCode
			}
			return fmt.Errorf("expected post_activation_error_code=%s, got %s", exp.PostActivationErrorCode, got)
		}
	}
	if exp.PostRestartErrorCode != "" {
		if rep.PostRestartActivation == nil || rep.PostRestartActivation.ErrorCode != exp.PostRestartErrorCode {
			got := "<nil>"
			if rep.PostRestartActivation != nil {
				got = rep.PostRestartActivation.ErrorCode
			}
			return fmt.Errorf("expected post_restart_error_code=%s, got %s", exp.PostRestartErrorCode, got)
		}
	}
	if exp.KeySetEpoch > 0 && rep.State.KeySetEpoch != exp.KeySetEpoch {
		return fmt.Errorf("expected key_set_epoch=%d, got %d", exp.KeySetEpoch, rep.State.KeySetEpoch)
	}
	if len(exp.TrustedKeyIDs) > 0 && !equalStringSlices(rep.State.TrustedKeyIDs, exp.TrustedKeyIDs) {
		return fmt.Errorf("expected trusted_key_ids=%v, got %v", exp.TrustedKeyIDs, rep.State.TrustedKeyIDs)
	}
	if len(exp.RemovedKeyIDs) > 0 && !equalStringSlices(rep.State.RemovedKeyIDs, exp.RemovedKeyIDs) {
		return fmt.Errorf("expected removed_key_ids=%v, got %v", exp.RemovedKeyIDs, rep.State.RemovedKeyIDs)
	}
	if exp.Active != nil && rep.State.Active != *exp.Active {
		return fmt.Errorf("expected active=%v, got %v", *exp.Active, rep.State.Active)
	}
	if exp.ActiveSignerKeyID != "" && rep.State.ActiveSignerKeyID != exp.ActiveSignerKeyID {
		return fmt.Errorf("expected active_signer_key_id=%s, got %s", exp.ActiveSignerKeyID, rep.State.ActiveSignerKeyID)
	}
	if exp.ActiveRevision > 0 && rep.State.ActiveRevision != exp.ActiveRevision {
		return fmt.Errorf("expected active_revision=%d, got %d", exp.ActiveRevision, rep.State.ActiveRevision)
	}
	if exp.HighestRevision > 0 && rep.State.HighestRevision != exp.HighestRevision {
		return fmt.Errorf("expected highest_revision=%d, got %d", exp.HighestRevision, rep.State.HighestRevision)
	}
	if exp.Allow != nil {
		if rep.Decision == nil {
			return fmt.Errorf("expected decision allow=%v, but decision is nil", *exp.Allow)
		}
		if rep.Decision.Allow != *exp.Allow {
			return fmt.Errorf("expected decision allow=%v, got %v (reasons=%v)", *exp.Allow, rep.Decision.Allow, rep.Decision.Reasons)
		}
	}
	if exp.DecisionReasonCode != "" {
		if rep.Decision == nil {
			return fmt.Errorf("expected decision_reason_code=%s, but decision is nil", exp.DecisionReasonCode)
		}
		found := false
		for _, r := range rep.Decision.Reasons {
			if r == exp.DecisionReasonCode {
				found = true
				break
			}
		}
		if !found && rep.Decision.Error != nil && rep.Decision.Error.Code == exp.DecisionReasonCode {
			found = true
		}
		if !found {
			return fmt.Errorf("expected decision_reason_code=%s in reasons=%v", exp.DecisionReasonCode, rep.Decision.Reasons)
		}
	}
	return nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
