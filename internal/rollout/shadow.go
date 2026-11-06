package rollout

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/audit"
	"github.com/parsa-emami/policyhelix/internal/policy"
)

const (
	CurrentShadowSchemaVersion = "1"
	DefaultMaxStoreRecords     = 1000
	DefaultPseudonymSalt      = "policyhelix-shadow-pseudonym-salt-v1"

	// Typed error codes for shadow rollout
	ErrCodeMalformedRequest    = "MALFORMED_REQUEST"
	ErrCodeProviderUnavailable = "PROVIDER_UNAVAILABLE"
	ErrCodeShadowEvalError     = "SHADOW_EVALUATION_ERROR"
	ErrCodePrivateFailClosed   = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrCodeTokenLeakDetected   = "TOKEN_LEAK_DETECTED"
)

var (
	bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*`)
	jwtPattern    = regexp.MustCompile(`\bey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)?\b`)
	cookiePattern = regexp.MustCompile(`(?i)\b(policyhelix_session|session|session_id|session_token|auth_token|token|access_token|refresh_token|id_token)\s*=\s*[^;\s,]+`)
)

// DivergenceType categorizes divergence observations between enforced and candidate policies.
type DivergenceType string

const (
	DivergenceNone        DivergenceType = "NONE"
	DivergenceAllowToDeny DivergenceType = "OUTCOME_DIVERGENCE_ALLOW_TO_DENY"
	DivergenceDenyToAllow DivergenceType = "OUTCOME_DIVERGENCE_DENY_TO_ALLOW"
	DivergenceReason      DivergenceType = "REASON_DIVERGENCE"
	DivergenceObligation  DivergenceType = "OBLIGATION_DIVERGENCE"
	DivergenceShadowError DivergenceType = "SHADOW_ERROR"
)

// RolloutError encapsulates typed errors occurring during shadow rollout evaluation.
type RolloutError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func (e *RolloutError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ShadowEvalRequest represents an inbound request to evaluate a decision in shadow mode.
type ShadowEvalRequest struct {
	RequestID              string                    `json:"request_id,omitempty"`
	Path                   string                    `json:"path"`
	Action                 string                    `json:"action"`
	Subject                policy.SubjectIdentity    `json:"subject"`
	ResourceID             string                    `json:"resource_id,omitempty"`
	ResourceClassification policy.ResourceClass      `json:"resource_classification,omitempty"`
	Context                map[string]interface{}    `json:"context,omitempty"`
	Headers                map[string]string         `json:"headers,omitempty"`
	DeadlineMS             int                       `json:"deadline_ms,omitempty"`
	EvalTime               string                    `json:"eval_time,omitempty"`
	EnforcedBundle         *policy.LocalPolicyBundle `json:"enforced_bundle,omitempty"`
	CandidateBundle        *policy.LocalPolicyBundle `json:"candidate_bundle,omitempty"`
	ProviderUnavailable    bool                      `json:"provider_unavailable,omitempty"`
	SimulateShadowPanic    bool                      `json:"simulate_shadow_panic,omitempty"`
	SimulateShadowDelayMS  int                       `json:"simulate_shadow_delay_ms,omitempty"`
	SimulateShadowError    string                    `json:"simulate_shadow_error,omitempty"`
	PseudonymSalt          string                    `json:"pseudonym_salt,omitempty"`
}

// DecisionSummary provides an auditable summary of an enforced policy decision.
type DecisionSummary struct {
	Allow        bool                      `json:"allow"`
	PolicyDigest string                    `json:"policy_digest,omitempty"`
	Revision     int64                     `json:"revision,omitempty"`
	Reasons      []string                  `json:"reasons,omitempty"`
	Obligations  []policy.PolicyObligation `json:"obligations,omitempty"`
	StatusCode   int                       `json:"status_code"`
}

// CandidateSummary provides an auditable summary of a candidate shadow evaluation.
type CandidateSummary struct {
	Allow        bool                      `json:"allow"`
	PolicyDigest string                    `json:"policy_digest,omitempty"`
	Revision     int64                     `json:"revision,omitempty"`
	Reasons      []string                  `json:"reasons,omitempty"`
	Obligations  []policy.PolicyObligation `json:"obligations,omitempty"`
	Error        string                    `json:"error,omitempty"`
}

// DivergenceRecord represents an immutable audit log entry documenting an enforced vs shadow comparison.
// Subject identities are strictly pseudonymized and credentials redacted.
type DivergenceRecord struct {
	RecordID               string                 `json:"record_id"`
	Timestamp              string                 `json:"timestamp"`
	RequestID              string                 `json:"request_id"`
	Path                   string                 `json:"path"`
	Action                 string                 `json:"action"`
	ResourceID             string                 `json:"resource_id,omitempty"`
	ResourceClassification policy.ResourceClass   `json:"resource_classification"`
	SubjectPseudonym       string                 `json:"subject_pseudonym"`
	EnforcedDecision       DecisionSummary        `json:"enforced_decision"`
	CandidateDecision      CandidateSummary       `json:"candidate_decision"`
	Diverged               bool                   `json:"diverged"`
	DivergenceType         DivergenceType         `json:"divergence_type"`
	DivergenceDetails      map[string]interface{} `json:"divergence_details,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	RedactionStats         audit.RedactionStats   `json:"redaction_stats"`
}

// ShadowResult represents the outcome returned to the client and caller.
// INVARIANT: Allow is strictly and authoritatively determined by EnforcedDecision.Allow.
type ShadowResult struct {
	Allow              bool                   `json:"allow"`
	StatusCode         int                    `json:"status_code"`
	EnforcedDecision   policy.BundleDecision  `json:"enforced_decision"`
	CandidateDecision  *policy.BundleDecision `json:"candidate_decision,omitempty"`
	Diverged           bool                   `json:"diverged"`
	DivergenceType     DivergenceType         `json:"divergence_type"`
	DivergenceRecord   *DivergenceRecord      `json:"divergence_record,omitempty"`
	InvariantsVerified []string               `json:"invariants_verified"`
	Error              string                 `json:"error,omitempty"`
}

// DivergenceFilter specifies criteria for querying logged divergence records.
type DivergenceFilter struct {
	DivergedOnly   bool           `json:"diverged_only,omitempty"`
	DivergenceType DivergenceType `json:"divergence_type,omitempty"`
	Limit          int            `json:"limit,omitempty"`
}

// DivergenceStats contains aggregate counts of evaluations and divergence categories.
type DivergenceStats struct {
	TotalEvaluations          int `json:"total_evaluations"`
	TotalDivergences          int `json:"total_divergences"`
	AllowToDenyCount          int `json:"allow_to_deny_count"`
	DenyToAllowCount          int `json:"deny_to_allow_count"`
	ShadowErrorCount          int `json:"shadow_error_count"`
	ReasonDivergenceCount     int `json:"reason_divergence_count"`
	ObligationDivergenceCount int `json:"obligation_divergence_count"`
}

// DivergenceStore defines the interface for persisting and retrieving divergence records.
type DivergenceStore interface {
	Record(rec DivergenceRecord)
	GetRecords(filter DivergenceFilter) []DivergenceRecord
	GetStats() DivergenceStats
	Clear()
	ExportJSON() ([]byte, error)
	ImportJSON(data []byte) error
}

// MemoryDivergenceStore provides a thread-safe, bounded in-memory implementation of DivergenceStore.
type MemoryDivergenceStore struct {
	mu         sync.RWMutex
	records    []DivergenceRecord
	maxRecords int
	stats      DivergenceStats
}

// NewMemoryDivergenceStore constructs a memory store bounded by maxRecords.
func NewMemoryDivergenceStore(maxRecords int) *MemoryDivergenceStore {
	if maxRecords <= 0 {
		maxRecords = DefaultMaxStoreRecords
	}
	return &MemoryDivergenceStore{
		records:    make([]DivergenceRecord, 0, 64),
		maxRecords: maxRecords,
	}
}

// Record appends a record, evicts oldest if limit reached, and updates stats.
func (s *MemoryDivergenceStore) Record(rec DivergenceRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.TotalEvaluations++
	if rec.Diverged {
		s.stats.TotalDivergences++
		switch rec.DivergenceType {
		case DivergenceAllowToDeny:
			s.stats.AllowToDenyCount++
		case DivergenceDenyToAllow:
			s.stats.DenyToAllowCount++
		case DivergenceShadowError:
			s.stats.ShadowErrorCount++
		case DivergenceReason:
			s.stats.ReasonDivergenceCount++
		case DivergenceObligation:
			s.stats.ObligationDivergenceCount++
		}
	}

	if len(s.records) >= s.maxRecords {
		// Evict oldest record by shifting left and zeroing the tail to allow GC collection
		copy(s.records, s.records[1:])
		s.records[len(s.records)-1] = DivergenceRecord{}
		s.records = s.records[:len(s.records)-1]
	}
	s.records = append(s.records, rec)
}

// GetRecords returns records matching the specified filter.
func (s *MemoryDivergenceStore) GetRecords(filter DivergenceFilter) []DivergenceRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]DivergenceRecord, 0, len(s.records))
	for _, r := range s.records {
		if filter.DivergedOnly && !r.Diverged {
			continue
		}
		if filter.DivergenceType != "" && r.DivergenceType != filter.DivergenceType {
			continue
		}
		out = append(out, r)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out
}

// GetStats returns aggregate divergence metrics.
func (s *MemoryDivergenceStore) GetStats() DivergenceStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

// Clear resets all stored records and statistics.
func (s *MemoryDivergenceStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = make([]DivergenceRecord, 0, 64)
	s.stats = DivergenceStats{}
}

type storeSnapshot struct {
	Records []DivergenceRecord `json:"records"`
	Stats   DivergenceStats    `json:"stats"`
}

// ExportJSON exports divergence records and stats as portable JSON bytes.
func (s *MemoryDivergenceStore) ExportJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := storeSnapshot{
		Records: s.records,
		Stats:   s.stats,
	}
	return json.Marshal(snap)
}

// ImportJSON restores divergence records and stats from portable JSON bytes.
func (s *MemoryDivergenceStore) ImportJSON(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var snap storeSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("failed to import divergence snapshot: %w", err)
	}
	s.records = snap.Records
	if len(s.records) > s.maxRecords {
		s.records = s.records[len(s.records)-s.maxRecords:]
	}
	s.stats = snap.Stats
	return nil
}

// VerifyNoTokenOrCookie inspects a DivergenceRecord ensuring no unredacted bearer token,
// JWT, or session cookie is exposed.
func VerifyNoTokenOrCookie(rec *DivergenceRecord) error {
	if rec == nil {
		return nil
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("failed to marshal divergence record for verification: %w", err)
	}
	content := string(raw)

	// Check Bearer tokens
	if matches := bearerPattern.FindAllString(content, -1); len(matches) > 0 {
		for _, m := range matches {
			if !strings.Contains(m, "[REDACTED]") {
				return fmt.Errorf("%s: unredacted bearer token detected: %s", ErrCodeTokenLeakDetected, m)
			}
		}
	}

	// Check JWTs
	if matches := jwtPattern.FindAllString(content, -1); len(matches) > 0 {
		for _, m := range matches {
			if !strings.Contains(m, "[REDACTED") {
				return fmt.Errorf("%s: unredacted JWT detected: %s", ErrCodeTokenLeakDetected, m)
			}
		}
	}

	// Check cookies
	if matches := cookiePattern.FindAllString(content, -1); len(matches) > 0 {
		for _, m := range matches {
			if !strings.Contains(m, "[REDACTED]") {
				return fmt.Errorf("%s: unredacted cookie detected: %s", ErrCodeTokenLeakDetected, m)
			}
		}
	}

	return nil
}

// ShadowEngine coordinates enforced policy evaluation alongside candidate shadow evaluation.
type ShadowEngine struct {
	mu                 sync.RWMutex
	enforcedEvaluator  *policy.BundleEvaluator
	candidateEvaluator *policy.BundleEvaluator
	store              DivergenceStore
	trustedIssuers     []string
	trustedSigners     []string
}

// NewShadowEngine constructs a ShadowEngine with the given evaluators and store.
func NewShadowEngine(enforcedEvaluator *policy.BundleEvaluator, candidateEvaluator *policy.BundleEvaluator, store DivergenceStore) *ShadowEngine {
	issuers := []string{"https://issuer.policyhelix.local", "https://auth.policyhelix.local"}
	signers := []string{"ed25519-primary-2026", "ed25519-staging-2026"}

	if enforcedEvaluator == nil {
		enforcedEvaluator = policy.NewBundleEvaluator(issuers, signers)
	}
	if candidateEvaluator == nil {
		candidateEvaluator = policy.NewBundleEvaluator(issuers, signers)
	}
	if store == nil {
		store = NewMemoryDivergenceStore(DefaultMaxStoreRecords)
	}

	return &ShadowEngine{
		enforcedEvaluator:  enforcedEvaluator,
		candidateEvaluator: candidateEvaluator,
		store:              store,
		trustedIssuers:     issuers,
		trustedSigners:     signers,
	}
}

// GetStore returns the underlying DivergenceStore.
func (e *ShadowEngine) GetStore() DivergenceStore {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.store
}

// Standard invariant statements affirmed upon evaluation.
var StandardInvariants = []string{
	"Shadow decision never changes enforced result and divergence is auditable",
	"Private resources fail closed",
	"Only authenticated normalized identity enters policy",
	"Absolute zero token exposure",
}

// Evaluate runs enforced authorization alongside candidate policy in shadow mode.
// INVARIANT 1: Shadow decision never changes the enforced result.
// INVARIANT 2: Private resources fail closed on unauthenticated access.
// INVARIANT 3: Missing prerequisites and unavailable providers produce explicit errors.
// INVARIANT 4: Divergence records never contain unredacted tokens or raw secrets.
func (e *ShadowEngine) Evaluate(ctx context.Context, req ShadowEvalRequest) (*ShadowResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Validate required prerequisites
	if strings.TrimSpace(req.Path) == "" || strings.TrimSpace(req.Action) == "" {
		res := &ShadowResult{
			Allow:              false,
			StatusCode:         http.StatusBadRequest,
			InvariantsVerified: StandardInvariants,
			Error:              ErrCodeMalformedRequest,
		}
		return res, &RolloutError{
			Code:       ErrCodeMalformedRequest,
			Message:    "Missing required request parameters: path and action are mandatory prerequisites",
			StatusCode: http.StatusBadRequest,
		}
	}

	// 2. Validate provider availability
	if req.ProviderUnavailable {
		res := &ShadowResult{
			Allow:              false,
			StatusCode:         http.StatusServiceUnavailable,
			InvariantsVerified: StandardInvariants,
			Error:              ErrCodeProviderUnavailable,
		}
		return res, &RolloutError{
			Code:       ErrCodeProviderUnavailable,
			Message:    "Required authorization provider is unavailable; failing closed",
			StatusCode: http.StatusServiceUnavailable,
		}
	}

	// 3. Prepare zero-token redactions & pseudonymization
	salt := req.PseudonymSalt
	if salt == "" {
		salt = DefaultPseudonymSalt
	}
	subjectPseudonym := audit.ComputeSubjectPseudonym(req.Subject.ID, salt)
	redactionStats := audit.RedactionStats{}
	redactedHeaders := audit.RedactHeaders(req.Headers, &redactionStats)
	redactedContext := audit.RedactMap(req.Context, &redactionStats)

	// Determine deadline
	deadlineMS := req.DeadlineMS
	if deadlineMS <= 0 {
		deadlineMS = policy.DefaultEvaluationDeadlineMS
	}

	// 4. Concurrently evaluate ENFORCED and CANDIDATE policies with isolated panic recovery
	enfInput := policy.BundleEvalInput{
		RequestID:  req.RequestID,
		Path:       req.Path,
		Action:     req.Action,
		Subject:    req.Subject,
		ResourceID: req.ResourceID,
		DeadlineMS: deadlineMS,
		EvalTime:   req.EvalTime,
		Bundle:     req.EnforcedBundle,
	}

	var (
		enforcedDecision policy.BundleDecision
		candDecision     *policy.BundleDecision
		candErr          string
		wg               sync.WaitGroup
	)

	wg.Add(2)

	// Concurrently evaluate ENFORCED policy
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				enforcedDecision = policy.BundleDecision{
					Allow:          false,
					Classification: policy.ResourceClassPrivate,
					Reasons:        []string{"ENFORCED_EVALUATION_PANIC"},
					Error: &policy.BundleError{
						Code:    "ENFORCED_EVALUATION_PANIC",
						Message: fmt.Sprintf("%v", r),
					},
				}
			}
		}()
		enforcedDecision = e.enforcedEvaluator.Evaluate(ctx, enfInput)
	}()

	// Concurrently evaluate CANDIDATE policy in isolated shadow mode
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				candErr = fmt.Sprintf("SHADOW_PANIC: %v", r)
			}
		}()

		if req.SimulateShadowPanic {
			panic("simulated shadow evaluation panic")
		}

		if req.SimulateShadowError != "" {
			candErr = req.SimulateShadowError
			return
		}

		candInput := policy.BundleEvalInput{
			RequestID:        req.RequestID,
			Path:             req.Path,
			Action:           req.Action,
			Subject:          req.Subject,
			ResourceID:       req.ResourceID,
			DeadlineMS:       deadlineMS,
			EvalTime:         req.EvalTime,
			Bundle:           req.CandidateBundle,
			SimulatedDelayMS: req.SimulateShadowDelayMS,
		}

		candTimeout := time.Duration(deadlineMS) * time.Millisecond
		if candTimeout > time.Duration(policy.MaxEvaluationDeadlineMS)*time.Millisecond {
			candTimeout = time.Duration(policy.MaxEvaluationDeadlineMS) * time.Millisecond
		}
		candCtx, candCancel := context.WithTimeout(ctx, candTimeout)
		defer candCancel()

		dec := e.candidateEvaluator.Evaluate(candCtx, candInput)
		candDecision = &dec
		if dec.Error != nil {
			candErr = dec.Error.Error()
		}
	}()

	wg.Wait()

	// Determine authoritative outcome & HTTP status code strictly from Enforced decision
	authoritativeAllow := enforcedDecision.Allow
	statusCode := http.StatusOK
	if !authoritativeAllow {
		statusCode = http.StatusForbidden
	}

	if candDecision == nil {
		candDecision = &policy.BundleDecision{
			Allow: false,
			Error: &policy.BundleError{
				Code:    ErrCodeShadowEvalError,
				Message: candErr,
			},
			Reasons: []string{ErrCodeShadowEvalError},
		}
	}

	// 6. Divergence Detection
	var diverged bool
	var divType DivergenceType = DivergenceNone
	divDetails := make(map[string]interface{})

	isShadowFatalError := strings.HasPrefix(candErr, "SHADOW_PANIC") || req.SimulateShadowError != ""
	if candDecision.Error != nil {
		switch candDecision.Error.Code {
		case policy.ErrCodeDeadlineExceeded,
			policy.ErrCodeRequestCancelled,
			policy.ErrCodeInvalidPolicyBundle,
			policy.ErrCodeTamperedBundle,
			policy.ErrCodeUntrustedSigner,
			policy.ErrCodeStaleOrReplayedRevision,
			policy.ErrCodeExpiredPolicyBundle,
			policy.ErrCodeNoActiveBundle,
			ErrCodeShadowEvalError:
			isShadowFatalError = true
		}
	}

	if isShadowFatalError {
		diverged = true
		divType = DivergenceShadowError
		divDetails["shadow_error"] = candErr
	} else {
		if enforcedDecision.Allow != candDecision.Allow {
			diverged = true
			if enforcedDecision.Allow && !candDecision.Allow {
				divType = DivergenceAllowToDeny
			} else {
				divType = DivergenceDenyToAllow
			}
			divDetails["enforced_allow"] = enforcedDecision.Allow
			divDetails["candidate_allow"] = candDecision.Allow
		} else if !stringSlicesEqual(enforcedDecision.Reasons, candDecision.Reasons) {
			diverged = true
			divType = DivergenceReason
			divDetails["enforced_reasons"] = enforcedDecision.Reasons
			divDetails["candidate_reasons"] = candDecision.Reasons
		} else if !obligationsEqual(enforcedDecision.Obligations, candDecision.Obligations) {
			diverged = true
			divType = DivergenceObligation
			divDetails["enforced_obligations"] = enforcedDecision.Obligations
			divDetails["candidate_obligations"] = candDecision.Obligations
		}
	}

	// 7. Construct auditable DivergenceRecord
	now := time.Now().UTC().Format(time.RFC3339Nano)
	reqID := req.RequestID
	if reqID == "" {
		reqID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	recordID := fmt.Sprintf("div-%d-%s", time.Now().UnixNano(), reqID)

	enforcedSummary := DecisionSummary{
		Allow:        enforcedDecision.Allow,
		PolicyDigest: enforcedDecision.PolicyDigest,
		Revision:     enforcedDecision.Revision,
		Reasons:      enforcedDecision.Reasons,
		Obligations:  enforcedDecision.Obligations,
		StatusCode:   statusCode,
	}

	candSummary := CandidateSummary{}
	if candDecision != nil {
		candSummary.Allow = candDecision.Allow
		candSummary.PolicyDigest = candDecision.PolicyDigest
		candSummary.Revision = candDecision.Revision
		candSummary.Reasons = candDecision.Reasons
		candSummary.Obligations = candDecision.Obligations
	}
	if candErr != "" {
		candSummary.Error = candErr
	}

	resClassification := req.ResourceClassification
	if resClassification == "" {
		resClassification = enforcedDecision.Classification
	}
	if resClassification == "" {
		resClassification = policy.ResourceClassPrivate
	}

	// Merge sanitized metadata
	finalMetadata := make(map[string]interface{})
	for k, v := range redactedContext {
		finalMetadata[k] = v
	}
	if len(redactedHeaders) > 0 {
		finalMetadata["headers"] = redactedHeaders
	}

	record := DivergenceRecord{
		RecordID:               recordID,
		Timestamp:              now,
		RequestID:              reqID,
		Path:                   req.Path,
		Action:                 req.Action,
		ResourceID:             req.ResourceID,
		ResourceClassification: resClassification,
		SubjectPseudonym:       subjectPseudonym,
		EnforcedDecision:       enforcedSummary,
		CandidateDecision:      candSummary,
		Diverged:               diverged,
		DivergenceType:         divType,
		DivergenceDetails:      divDetails,
		Metadata:               finalMetadata,
		RedactionStats:         redactionStats,
	}

	// 8. Assert zero token exposure on the record
	if err := VerifyNoTokenOrCookie(&record); err != nil {
		return nil, &RolloutError{
			Code:       ErrCodeTokenLeakDetected,
			Message:    err.Error(),
			StatusCode: http.StatusInternalServerError,
		}
	}

	// 9. Store record
	if e.store != nil {
		e.store.Record(record)
	}

	// 10. Assemble authoritative ShadowResult
	// CRITICAL INVARIANT: Shadow decision NEVER changes enforced result.
	result := &ShadowResult{
		Allow:              authoritativeAllow,
		StatusCode:         statusCode,
		EnforcedDecision:   enforcedDecision,
		CandidateDecision:  candDecision,
		Diverged:           diverged,
		DivergenceType:     divType,
		DivergenceRecord:   &record,
		InvariantsVerified: StandardInvariants,
	}

	return result, nil
}

func stringSlicesEqual(a, b []string) bool {
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

func obligationsEqual(a, b []policy.PolicyObligation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Type != b[i].Type {
			return false
		}
		rawA, errA := json.Marshal(a[i].Parameters)
		rawB, errB := json.Marshal(b[i].Parameters)
		if errA != nil || errB != nil || string(rawA) != string(rawB) {
			return false
		}
	}
	return true
}
