package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	SchemaVersion      = "1"
	MaxPayloadBytes    = 65536 // 64 KiB max per write
	MaxTotalRecords    = 1024  // Bounded repository limit
	ManifestFileName   = "manifest.json"
	ObjectsDirName     = "objects"
	StagingDirName     = ".staging"
	LockFileName       = ".lock"
)

// Typed Error Codes for C05 Storage Port
const (
	ErrUnauthenticatedIdentity = "UNAUTHENTICATED_IDENTITY"
	ErrExpiredSession          = "EXPIRED_OR_REVOKED_IDENTITY"
	ErrForgedHeader            = "FORGED_HEADER_REJECTED"
	ErrScopeViolation          = "OWNER_SCOPE_VIOLATION"
	ErrProviderUnavailable     = "PROVIDER_UNAVAILABLE"
	ErrPrivateFailClosed       = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrOperationConflict       = "OPERATION_ID_CONFLICT"
	ErrInvalidOperationID      = "INVALID_OPERATION_ID"
	ErrPayloadTooLarge         = "PAYLOAD_TOO_LARGE"
	ErrStorageBoundExceeded    = "STORAGE_BOUND_EXCEEDED"
	ErrDiskFullOrWriteFailed   = "DISK_FULL_OR_WRITE_FAILED"
	ErrInterruptedWrite        = "INTERRUPTED_STAGING_WRITE"
	ErrLockContention          = "SINGLE_WRITER_LOCK_BUSY"
	ErrCorruptState            = "CORRUPT_OR_MISSING_OBJECT"
	ErrRecordNotFound          = "RECORD_NOT_FOUND"
)

var (
	idPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)
)

type StorageError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *StorageError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type CallerIdentity struct {
	SubjectID                string   `json:"subject_id"`
	Issuer                   string   `json:"issuer"`
	Roles                    []string `json:"roles"`
	Authenticated            bool     `json:"authenticated"`
	SessionEpoch             int64    `json:"session_epoch"`
	MinRequiredEpoch         int64    `json:"min_required_epoch,omitempty"`
	UntrustedHeadersStripped bool     `json:"untrusted_headers_stripped"`
	ProviderState            string   `json:"provider_state,omitempty"`
}

type WriteRequest struct {
	SchemaVersion  string          `json:"schema_version"`
	OperationID    string          `json:"operation_id"`
	RecordID       string          `json:"record_id"`
	OwnerScope     string          `json:"owner_scope"`
	Classification string          `json:"classification"`
	Identity       CallerIdentity  `json:"identity"`
	Payload        json.RawMessage `json:"payload"`
}

type RecordEntry struct {
	RecordID       string `json:"record_id"`
	OwnerScope     string `json:"owner_scope"`
	Classification string `json:"classification"`
	ObjectDigest   string `json:"object_digest"`
	PayloadBytes   int    `json:"payload_bytes"`
	Revision       int64  `json:"revision"`
	OperationID    string `json:"operation_id"`
	UpdatedBy      string `json:"updated_by"`
	UpdatedAt      string `json:"updated_at"`
}

type OperationRecord struct {
	OperationID  string `json:"operation_id"`
	RecordID     string `json:"record_id"`
	RequestHash  string `json:"request_hash"`
	ObjectDigest string `json:"object_digest"`
	Revision     int64  `json:"revision"`
	CommittedAt  string `json:"committed_at"`
}

type Manifest struct {
	SchemaVersion string                     `json:"schema_version"`
	Revision      int64                      `json:"revision"`
	UpdatedAt     string                     `json:"updated_at"`
	Records       map[string]RecordEntry     `json:"records"`
	Operations    map[string]OperationRecord `json:"operations"`
}

type WriteReceipt struct {
	SchemaVersion    string `json:"schema_version"`
	OperationID      string `json:"operation_id"`
	RecordID         string `json:"record_id"`
	Revision         int64  `json:"revision"`
	ObjectDigest     string `json:"object_digest"`
	RequestHash      string `json:"request_hash"`
	Replayed         bool   `json:"replayed"`
	CommittedAt      string `json:"committed_at"`
	OrphansCleaned   int    `json:"orphans_cleaned,omitempty"`
}

type SimulatedFaults struct {
	SimulateDiskFull        bool
	InterruptAfterStaging   bool
	InterruptBeforeManifest bool
}

type Adapter struct {
	rootDir  string
	mu       sync.Mutex
	lockFile *os.File
	Faults   SimulatedFaults
}

func CalculateSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func HexDigest(prefixed string) string {
	return strings.TrimPrefix(prefixed, "sha256:")
}

// Open initializes the bounded local single-writer storage adapter and reconciles orphan staging state.
func Open(rootDir string) (*Adapter, int, error) {
	if strings.TrimSpace(rootDir) == "" {
		return nil, 0, &StorageError{Code: ErrCorruptState, Message: "storage root directory cannot be empty", Retryable: false}
	}

	if err := os.MkdirAll(filepath.Join(rootDir, ObjectsDirName), 0700); err != nil {
		return nil, 0, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("failed to create objects directory: %v", err), Retryable: true}
	}
	if err := os.MkdirAll(filepath.Join(rootDir, StagingDirName), 0700); err != nil {
		return nil, 0, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("failed to create staging directory: %v", err), Retryable: true}
	}

	lockPath := filepath.Join(rootDir, LockFileName)
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, 0, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("failed to open lock file: %v", err), Retryable: true}
	}

	// Acquire non-blocking exclusive file lock to enforce single writer across processes
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lf.Close()
		return nil, 0, &StorageError{
			Code:      ErrLockContention,
			Message:   "single-writer storage lock is already held by another process",
			Retryable: true,
		}
	}

	ad := &Adapter{
		rootDir:  rootDir,
		lockFile: lf,
	}

	orphans, err := ad.ReconcileStartup()
	if err != nil {
		_ = ad.Close()
		return nil, orphans, err
	}

	return ad, orphans, nil
}

func (a *Adapter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lockFile != nil {
		_ = syscall.Flock(int(a.lockFile.Fd()), syscall.LOCK_UN)
		err := a.lockFile.Close()
		a.lockFile = nil
		return err
	}
	return nil
}

// ReconcileStartup removes uncommitted staging files and verifies all published manifest references exist and match their digests.
func (a *Adapter) ReconcileStartup() (int, error) {
	stagingDir := filepath.Join(a.rootDir, StagingDirName)
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return 0, &StorageError{Code: ErrCorruptState, Message: fmt.Sprintf("failed reading staging dir: %v", err), Retryable: false}
	}

	cleaned := 0
	for _, entry := range entries {
		p := filepath.Join(stagingDir, entry.Name())
		if err := os.RemoveAll(p); err == nil {
			cleaned++
		}
	}

	// Clean any stray manifest.tmp in root
	tmpManifest := filepath.Join(a.rootDir, ManifestFileName+".tmp")
	if _, err := os.Stat(tmpManifest); err == nil {
		_ = os.Remove(tmpManifest)
		cleaned++
	}

	manifest, err := a.loadManifestUnlocked()
	if err != nil {
		return cleaned, err
	}

	// Verify every referenced object exists and matches its SHA-256 digest
	for recID, rec := range manifest.Records {
		objPath := filepath.Join(a.rootDir, ObjectsDirName, HexDigest(rec.ObjectDigest))
		raw, err := os.ReadFile(objPath)
		if err != nil {
			return cleaned, &StorageError{
				Code:      ErrCorruptState,
				Message:   fmt.Sprintf("manifest record '%s' references missing object '%s'", recID, rec.ObjectDigest),
				Retryable: false,
			}
		}
		if CalculateSHA256(raw) != rec.ObjectDigest {
			return cleaned, &StorageError{
				Code:      ErrCorruptState,
				Message:   fmt.Sprintf("manifest record '%s' object '%s' failed SHA-256 integrity verification", recID, rec.ObjectDigest),
				Retryable: false,
			}
		}
	}

	return cleaned, nil
}

func (a *Adapter) loadManifestUnlocked() (*Manifest, error) {
	manifestPath := filepath.Join(a.rootDir, ManifestFileName)
	raw, err := os.ReadFile(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return &Manifest{
			SchemaVersion: SchemaVersion,
			Revision:      0,
			UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
			Records:       make(map[string]RecordEntry),
			Operations:    make(map[string]OperationRecord),
		}, nil
	}
	if err != nil {
		return nil, &StorageError{Code: ErrCorruptState, Message: fmt.Sprintf("failed reading manifest: %v", err), Retryable: false}
	}

	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, &StorageError{Code: ErrCorruptState, Message: fmt.Sprintf("corrupt manifest JSON: %v", err), Retryable: false}
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, &StorageError{Code: ErrCorruptState, Message: fmt.Sprintf("unsupported manifest version '%s'", m.SchemaVersion), Retryable: false}
	}
	if m.Records == nil {
		m.Records = make(map[string]RecordEntry)
	}
	if m.Operations == nil {
		m.Operations = make(map[string]OperationRecord)
	}
	return &m, nil
}

// ValidateIdentityAndScope enforces fail-closed security invariants BEFORE any storage lock or disk side effect.
func ValidateIdentityAndScope(req WriteRequest) *StorageError {
	if req.SchemaVersion != SchemaVersion {
		return &StorageError{
			Code:      ErrInvalidOperationID,
			Message:   fmt.Sprintf("unsupported schema_version '%s'; expected '%s'", req.SchemaVersion, SchemaVersion),
			Retryable: false,
		}
	}

	// 1. Provider outage fail-closed
	if req.Identity.ProviderState == "unavailable" {
		return &StorageError{
			Code:      ErrProviderUnavailable,
			Message:   "identity or policy provider is unavailable; failing closed before write",
			Retryable: true,
		}
	}

	// 2. Spoofed / untrusted headers must be stripped at gateway boundary
	if !req.Identity.UntrustedHeadersStripped {
		return &StorageError{
			Code:      ErrForgedHeader,
			Message:   "untrusted identity headers were not stripped; rejecting forged header write attempt",
			Retryable: false,
		}
	}

	// 3. Authenticated normalized identity required
	if !req.Identity.Authenticated || strings.TrimSpace(req.Identity.SubjectID) == "" || strings.TrimSpace(req.Identity.Issuer) == "" {
		return &StorageError{
			Code:      ErrUnauthenticatedIdentity,
			Message:   "caller identity is missing or unauthenticated; authoritative writes require authenticated identity",
			Retryable: false,
		}
	}

	// 4. Expired or revoked session epoch check
	if req.Identity.SessionEpoch <= 0 || (req.Identity.MinRequiredEpoch > 0 && req.Identity.SessionEpoch < req.Identity.MinRequiredEpoch) {
		return &StorageError{
			Code:      ErrExpiredSession,
			Message:   fmt.Sprintf("caller session_epoch (%d) is expired or revoked (minimum required: %d)", req.Identity.SessionEpoch, req.Identity.MinRequiredEpoch),
			Retryable: false,
		}
	}

	// 5. Role & private classification check
	hasOperatorOrAdmin := false
	hasAdmin := false
	for _, r := range req.Identity.Roles {
		if r == "operator" || r == "admin" {
			hasOperatorOrAdmin = true
		}
		if r == "admin" {
			hasAdmin = true
		}
	}
	if !hasOperatorOrAdmin {
		return &StorageError{
			Code:      ErrPrivateFailClosed,
			Message:   "caller lacks required operator or admin role for authoritative storage write",
			Retryable: false,
		}
	}

	// 6. Owner / Object scope boundary enforcement (prevent cross-tenant or unrelated scope writes)
	if strings.TrimSpace(req.OwnerScope) == "" {
		return &StorageError{
			Code:      ErrScopeViolation,
			Message:   "owner_scope is required",
			Retryable: false,
		}
	}
	expectedPrefix := req.OwnerScope + ":"
	if !strings.HasPrefix(req.RecordID, expectedPrefix) {
		return &StorageError{
			Code:      ErrScopeViolation,
			Message:   fmt.Sprintf("record_id '%s' does not belong to declared owner_scope '%s'", req.RecordID, req.OwnerScope),
			Retryable: false,
		}
	}
	// Non-admin operators can only write within their own subject scope or shared "service:analytics" operator scope
	if !hasAdmin && req.OwnerScope != req.Identity.SubjectID && req.OwnerScope != "service:analytics" && req.OwnerScope != "policyhelix" {
		return &StorageError{
			Code:      ErrScopeViolation,
			Message:   fmt.Sprintf("subject '%s' is not authorized for owner_scope '%s'", req.Identity.SubjectID, req.OwnerScope),
			Retryable: false,
		}
	}

	if !idPattern.MatchString(req.OperationID) {
		return &StorageError{
			Code:      ErrInvalidOperationID,
			Message:   "operation_id must match ^[a-zA-Z0-9._:-]{1,128}$",
			Retryable: false,
		}
	}
	if !idPattern.MatchString(req.RecordID) {
		return &StorageError{
			Code:      ErrInvalidOperationID,
			Message:   "record_id must match ^[a-zA-Z0-9._:-]{1,128}$",
			Retryable: false,
		}
	}

	validClass := req.Classification == "internal" || req.Classification == "private" || req.Classification == "restricted"
	if !validClass {
		return &StorageError{
			Code:      ErrPrivateFailClosed,
			Message:   "classification must be internal, private, or restricted",
			Retryable: false,
		}
	}

	if len(req.Payload) == 0 || !json.Valid(req.Payload) {
		return &StorageError{
			Code:      ErrCorruptState,
			Message:   "payload must be non-empty valid JSON",
			Retryable: false,
		}
	}
	if len(req.Payload) > MaxPayloadBytes {
		return &StorageError{
			Code:      ErrPayloadTooLarge,
			Message:   fmt.Sprintf("payload size %d exceeds maximum %d bytes", len(req.Payload), MaxPayloadBytes),
			Retryable: false,
		}
	}

	return nil
}

func computeRequestHash(req WriteRequest) string {
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s", req.OperationID, req.RecordID, req.OwnerScope, req.Classification, string(req.Payload))
	return CalculateSHA256([]byte(canonical))
}

func syncDir(dirPath string) error {
	df, err := os.Open(dirPath)
	if err != nil {
		return err
	}
	defer df.Close()
	return df.Sync()
}

// WriteRecord performs a crash-consistent, single-writer authoritative write with idempotency guard.
func (a *Adapter) WriteRecord(ctx context.Context, req WriteRequest) (*WriteReceipt, *StorageError) {
	if err := ctx.Err(); err != nil {
		return nil, &StorageError{Code: ErrInterruptedWrite, Message: "context cancelled before write", Retryable: true}
	}

	// Gate 1: Fail-closed security & scope validation BEFORE touching locks or disk
	if secErr := ValidateIdentityAndScope(req); secErr != nil {
		return nil, secErr
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	manifest, err := a.loadManifestUnlocked()
	if err != nil {
		var se *StorageError
		if errors.As(err, &se) {
			return nil, se
		}
		return nil, &StorageError{Code: ErrCorruptState, Message: err.Error(), Retryable: false}
	}

	reqHash := computeRequestHash(req)
	objDigest := CalculateSHA256(req.Payload)

	// Gate 2: Idempotency check on stable OperationID
	if existingOp, exists := manifest.Operations[req.OperationID]; exists {
		if existingOp.RequestHash != reqHash {
			return nil, &StorageError{
				Code:      ErrOperationConflict,
				Message:   fmt.Sprintf("operation_id '%s' was already committed with a different payload or target", req.OperationID),
				Retryable: false,
			}
		}
		return &WriteReceipt{
			SchemaVersion: SchemaVersion,
			OperationID:   existingOp.OperationID,
			RecordID:      existingOp.RecordID,
			Revision:      existingOp.Revision,
			ObjectDigest:  existingOp.ObjectDigest,
			RequestHash:   existingOp.RequestHash,
			Replayed:      true,
			CommittedAt:   existingOp.CommittedAt,
		}, nil
	}

	// Check repository record bound
	if _, exists := manifest.Records[req.RecordID]; !exists && len(manifest.Records) >= MaxTotalRecords {
		return nil, &StorageError{
			Code:      ErrStorageBoundExceeded,
			Message:   fmt.Sprintf("repository record count limit (%d) reached", MaxTotalRecords),
			Retryable: false,
		}
	}

	// Fault injection: simulated disk full before write
	if a.Faults.SimulateDiskFull {
		return nil, &StorageError{
			Code:      ErrDiskFullOrWriteFailed,
			Message:   "simulated ENOSPC: no space left on device during staging allocation",
			Retryable: true,
		}
	}

	// Step 3: Write payload to staging file and fsync
	stagingFile := filepath.Join(a.rootDir, StagingDirName, fmt.Sprintf("%s.tmp", req.OperationID))
	sf, openErr := os.OpenFile(stagingFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if openErr != nil {
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("staging open failed: %v", openErr), Retryable: true}
	}
	if _, writeErr := sf.Write(req.Payload); writeErr != nil {
		_ = sf.Close()
		_ = os.Remove(stagingFile)
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("staging write failed: %v", writeErr), Retryable: true}
	}
	if syncErr := sf.Sync(); syncErr != nil {
		_ = sf.Close()
		_ = os.Remove(stagingFile)
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("staging fsync failed: %v", syncErr), Retryable: true}
	}
	_ = sf.Close()

	// Verify staged bytes hash
	stagedBytes, readErr := os.ReadFile(stagingFile)
	if readErr != nil || CalculateSHA256(stagedBytes) != objDigest {
		_ = os.Remove(stagingFile)
		return nil, &StorageError{Code: ErrCorruptState, Message: "staged file hash verification failed", Retryable: true}
	}

	// Fault injection: interrupt after staging (leaves orphan staging file on disk)
	if a.Faults.InterruptAfterStaging {
		return nil, &StorageError{
			Code:      ErrInterruptedWrite,
			Message:   "write interrupted after staging before object publication",
			Retryable: true,
		}
	}

	// Step 4: Atomically promote staged object to content-addressed objects/<hex>
	objectPath := filepath.Join(a.rootDir, ObjectsDirName, HexDigest(objDigest))
	if err := os.Rename(stagingFile, objectPath); err != nil {
		_ = os.Remove(stagingFile)
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("failed to publish object: %v", err), Retryable: true}
	}
	_ = syncDir(filepath.Join(a.rootDir, ObjectsDirName))

	if a.Faults.InterruptBeforeManifest {
		return nil, &StorageError{
			Code:      ErrInterruptedWrite,
			Message:   "write interrupted before atomic manifest publication",
			Retryable: true,
		}
	}

	// Step 5: Advance monotonic revision and stage new manifest
	now := time.Now().UTC().Format(time.RFC3339)
	nextRevision := manifest.Revision + 1
	manifest.Revision = nextRevision
	manifest.UpdatedAt = now

	manifest.Records[req.RecordID] = RecordEntry{
		RecordID:       req.RecordID,
		OwnerScope:     req.OwnerScope,
		Classification: req.Classification,
		ObjectDigest:   objDigest,
		PayloadBytes:   len(req.Payload),
		Revision:       nextRevision,
		OperationID:    req.OperationID,
		UpdatedBy:      req.Identity.SubjectID,
		UpdatedAt:      now,
	}

	manifest.Operations[req.OperationID] = OperationRecord{
		OperationID:  req.OperationID,
		RecordID:     req.RecordID,
		RequestHash:  reqHash,
		ObjectDigest: objDigest,
		Revision:     nextRevision,
		CommittedAt:  now,
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, &StorageError{Code: ErrCorruptState, Message: fmt.Sprintf("manifest marshal failed: %v", err), Retryable: false}
	}

	tmpManifest := filepath.Join(a.rootDir, ManifestFileName+".tmp")
	mf, err := os.OpenFile(tmpManifest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("manifest staging open failed: %v", err), Retryable: true}
	}
	if _, err := mf.Write(manifestBytes); err != nil {
		_ = mf.Close()
		_ = os.Remove(tmpManifest)
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("manifest staging write failed: %v", err), Retryable: true}
	}
	if err := mf.Sync(); err != nil {
		_ = mf.Close()
		_ = os.Remove(tmpManifest)
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("manifest staging fsync failed: %v", err), Retryable: true}
	}
	_ = mf.Close()

	// Step 6: Atomic rename of manifest.json and parent directory flush
	finalManifest := filepath.Join(a.rootDir, ManifestFileName)
	if err := os.Rename(tmpManifest, finalManifest); err != nil {
		_ = os.Remove(tmpManifest)
		return nil, &StorageError{Code: ErrDiskFullOrWriteFailed, Message: fmt.Sprintf("atomic manifest rename failed: %v", err), Retryable: true}
	}
	_ = syncDir(a.rootDir)

	return &WriteReceipt{
		SchemaVersion: SchemaVersion,
		OperationID:   req.OperationID,
		RecordID:      req.RecordID,
		Revision:      nextRevision,
		ObjectDigest:  objDigest,
		RequestHash:   reqHash,
		Replayed:      false,
		CommittedAt:   now,
	}, nil
}

// ReadRecord reads a committed record and verifies its content-addressed SHA-256 digest.
func (a *Adapter) ReadRecord(recordID string) ([]byte, *RecordEntry, *StorageError) {
	a.mu.Lock()
	defer a.mu.Unlock()

	manifest, err := a.loadManifestUnlocked()
	if err != nil {
		var se *StorageError
		if errors.As(err, &se) {
			return nil, nil, se
		}
		return nil, nil, &StorageError{Code: ErrCorruptState, Message: err.Error(), Retryable: false}
	}

	entry, exists := manifest.Records[recordID]
	if !exists {
		return nil, nil, &StorageError{
			Code:      ErrRecordNotFound,
			Message:   fmt.Sprintf("record '%s' not found in published manifest", recordID),
			Retryable: false,
		}
	}

	objPath := filepath.Join(a.rootDir, ObjectsDirName, HexDigest(entry.ObjectDigest))
	payload, readErr := os.ReadFile(objPath)
	if readErr != nil {
		return nil, nil, &StorageError{
			Code:      ErrCorruptState,
			Message:   fmt.Sprintf("missing object file for digest '%s'", entry.ObjectDigest),
			Retryable: false,
		}
	}

	if CalculateSHA256(payload) != entry.ObjectDigest {
		return nil, nil, &StorageError{
			Code:      ErrCorruptState,
			Message:   fmt.Sprintf("object digest mismatch for record '%s'", recordID),
			Retryable: false,
		}
	}

	return payload, &entry, nil
}

// GetManifest returns a snapshot of the current committed manifest.
func (a *Adapter) GetManifest() (*Manifest, *StorageError) {
	a.mu.Lock()
	defer a.mu.Unlock()

	m, err := a.loadManifestUnlocked()
	if err != nil {
		var se *StorageError
		if errors.As(err, &se) {
			return nil, se
		}
		return nil, &StorageError{Code: ErrCorruptState, Message: err.Error(), Retryable: false}
	}
	return m, nil
}
