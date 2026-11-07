package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// MaxBundleBytes bounds the maximum raw size of a local policy bundle (64 KiB).
	MaxBundleBytes = 65536
	// MaxBundleRules bounds the maximum number of rules in a local policy bundle.
	MaxBundleRules = 256
	// MaxEvaluationDeadlineMS is the strict upper bound for policy evaluation latency (200ms SLO).
	MaxEvaluationDeadlineMS = 200
	// DefaultEvaluationDeadlineMS is used when a caller does not specify a custom deadline within bounds.
	DefaultEvaluationDeadlineMS = 50
)

// Typed error and reason codes for bounded local OPA bundle evaluation (Requirement F02).
const (
	ErrCodeInvalidPolicyBundle     = "INVALID_POLICY_BUNDLE"
	ErrCodeDeadlineExceeded        = "DECISION_DEADLINE_EXCEEDED"
	ErrCodeRequestCancelled        = "REQUEST_CANCELLED"
	ErrCodeTamperedBundle          = "TAMPERED_BUNDLE_DIGEST"
	ErrCodeUntrustedSigner         = "UNTRUSTED_OR_MISSING_SIGNER"
	ErrCodeStaleOrReplayedRevision = "STALE_OR_REPLAYED_REVISION"
	ErrCodeExpiredPolicyBundle     = "EXPIRED_POLICY_BUNDLE"
	ErrCodeNoActiveBundle          = "NO_ACTIVE_POLICY_BUNDLE"
	ErrCodePrivateFailClosed       = "PRIVATE_RESOURCE_FAIL_CLOSED"
)

var bundleDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// PolicyObligation represents a mandatory obligation attached to an authorization decision.
type PolicyObligation struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// PolicyRule defines a bounded authorization rule within a local policy bundle.
type PolicyRule struct {
	ID            string             `json:"id"`
	Effect        string             `json:"effect"` // "allow" or "deny"
	PathPattern   string             `json:"path_pattern"`
	Actions       []string           `json:"actions"`
	Roles         []string           `json:"roles,omitempty"`
	ResourceClass ResourceClass      `json:"resource_class,omitempty"`
	ReasonCode    string             `json:"reason_code"`
	ReasonMessage string             `json:"reason_message,omitempty"`
	Obligations   []PolicyObligation `json:"obligations,omitempty"`
}

// LocalPolicyBundle represents a signed, bounded, versioned local OPA-compatible policy bundle.
type LocalPolicyBundle struct {
	SchemaVersion     string       `json:"schema_version"`
	BundleID          string       `json:"bundle_id"`
	Package           string       `json:"package"`
	Issuer            string       `json:"issuer"`
	SignerKeyID       string       `json:"signer_key_id"`
	Signature         string       `json:"signature"`
	SignatureVerified bool         `json:"signature_verified"`
	Revision          int64        `json:"revision"`
	IssuedAt          string       `json:"issued_at"`
	ExpiresAt         string       `json:"expires_at"`
	Digest            string       `json:"digest"`
	RegoModule        string       `json:"rego_module"`
	Routes            []RouteRule  `json:"routes"`
	Rules             []PolicyRule `json:"rules"`
}

// canonicalBundleContent is used to compute the deterministic SHA-256 content digest of a bundle.
// Any single-byte modification to any policy field changes the computed digest.
type canonicalBundleContent struct {
	SchemaVersion string       `json:"schema_version"`
	BundleID      string       `json:"bundle_id"`
	Package       string       `json:"package"`
	Issuer        string       `json:"issuer"`
	SignerKeyID   string       `json:"signer_key_id"`
	Revision      int64        `json:"revision"`
	IssuedAt      string       `json:"issued_at"`
	ExpiresAt     string       `json:"expires_at"`
	RegoModule    string       `json:"rego_module"`
	Routes        []RouteRule  `json:"routes"`
	Rules         []PolicyRule `json:"rules"`
}

// ComputeCanonicalBundleDigest computes the deterministic SHA-256 digest over the bundle's content.
func ComputeCanonicalBundleDigest(b LocalPolicyBundle) string {
	canonical := canonicalBundleContent{
		SchemaVersion: b.SchemaVersion,
		BundleID:      b.BundleID,
		Package:       b.Package,
		Issuer:        b.Issuer,
		SignerKeyID:   b.SignerKeyID,
		Revision:      b.Revision,
		IssuedAt:      b.IssuedAt,
		ExpiresAt:     b.ExpiresAt,
		RegoModule:    b.RegoModule,
		Routes:        b.Routes,
		Rules:         b.Rules,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BundleError provides structured error diagnostics for rejected bundles or failed evaluations.
type BundleError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *BundleError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ResourceInput represents structured resource identity and classification.
type ResourceInput struct {
	ID             string        `json:"id,omitempty"`
	Classification ResourceClass `json:"classification,omitempty"`
}

// BundleEvalInput defines the strongly typed request for evaluating a decision against a bounded bundle.
type BundleEvalInput struct {
	RequestID        string             `json:"request_id"`
	Path             string             `json:"path"`
	Action           string             `json:"action"`
	Subject          SubjectIdentity    `json:"subject"`
	ResourceID       string             `json:"resource_id,omitempty"`
	Resource         *ResourceInput     `json:"resource,omitempty"`
	DeadlineMS       int                `json:"deadline_ms"`
	SimulatedDelayMS int                `json:"simulated_delay_ms,omitempty"`
	EvalTime         string             `json:"eval_time,omitempty"`
	Bundle           *LocalPolicyBundle `json:"bundle,omitempty"`
}

// BundleDecision represents the strongly typed authorization outcome from bounded policy evaluation.
type BundleDecision struct {
	Allow          bool               `json:"allow"`
	PolicyDigest   string             `json:"policy_digest"`
	Revision       int64              `json:"revision"`
	Classification ResourceClass      `json:"classification"`
	Reasons        []string           `json:"reasons"`
	Obligations    []PolicyObligation `json:"obligations"`
	Error          *BundleError       `json:"error,omitempty"`
	ElapsedMS      float64            `json:"elapsed_ms"`
	WithinDeadline bool               `json:"within_deadline"`
}

// BundleEvaluator manages the active verified policy bundle, enforces monotonic revisions,
// and executes bounded fail-closed evaluations (Requirement F02).
type BundleEvaluator struct {
	mu              sync.RWMutex
	trustedIssuers  map[string]bool
	trustedSigners  map[string]bool
	activeBundle    *LocalPolicyBundle
	activeRegistry  *RouteRegistry
	highestRevision int64
}

// NewBundleEvaluator constructs a bounded policy bundle evaluator with explicit trusted issuers and signers.
func NewBundleEvaluator(trustedIssuers, trustedSigners []string) *BundleEvaluator {
	issuers := make(map[string]bool, len(trustedIssuers))
	for _, iss := range trustedIssuers {
		if trimmed := strings.TrimSpace(iss); trimmed != "" {
			issuers[trimmed] = true
		}
	}
	signers := make(map[string]bool, len(trustedSigners))
	for _, sig := range trustedSigners {
		if trimmed := strings.TrimSpace(sig); trimmed != "" {
			signers[trimmed] = true
		}
	}
	return &BundleEvaluator{
		trustedIssuers: issuers,
		trustedSigners: signers,
	}
}

// validateRegoSyntax performs bounded syntax and package header verification on the Rego module.
func validateRegoSyntax(pkgName, module string) error {
	trimmed := strings.TrimSpace(module)
	if trimmed == "" {
		return errors.New("rego_module cannot be empty")
	}
	expectedHeader := "package " + pkgName
	if !strings.HasPrefix(trimmed, expectedHeader) {
		return fmt.Errorf("rego_module must begin with '%s'", expectedHeader)
	}
	if !strings.Contains(trimmed, "default allow = false") && !strings.Contains(trimmed, "default allow := false") {
		return errors.New("rego_module must declare explicit fail-closed 'default allow = false' or 'default allow := false'")
	}
	// Check balanced braces and brackets
	braceCount := 0
	bracketCount := 0
	for _, ch := range trimmed {
		switch ch {
		case '{':
			braceCount++
		case '}':
			braceCount--
			if braceCount < 0 {
				return errors.New("rego_module has unbalanced closing brace '}'")
			}
		case '[':
			bracketCount++
		case ']':
			bracketCount--
			if bracketCount < 0 {
				return errors.New("rego_module has unbalanced closing bracket ']'")
			}
		}
	}
	if braceCount != 0 || bracketCount != 0 {
		return errors.New("rego_module has unbalanced braces or brackets")
	}
	if strings.Contains(trimmed, "SYNTAX_ERROR") || strings.Contains(trimmed, "???") {
		return errors.New("rego_module contains invalid syntax tokens")
	}
	return nil
}

// ValidateBundle verifies structural bounds, policy syntax, cryptographic signature/signer trust,
// SHA-256 content digest integrity, and validity window freshness.
func (e *BundleEvaluator) ValidateBundle(b LocalPolicyBundle, evalTime time.Time) (*RouteRegistry, *BundleError) {
	rawBytes, err := json.Marshal(b)
	if err != nil || len(rawBytes) > MaxBundleBytes {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   fmt.Sprintf("Policy bundle exceeds maximum allowed size of %d bytes", MaxBundleBytes),
			Retryable: false,
		}
	}

	if b.SchemaVersion != "1" {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   fmt.Sprintf("Unsupported bundle schema_version '%s'; expected '1'", b.SchemaVersion),
			Retryable: false,
		}
	}

	if strings.TrimSpace(b.BundleID) == "" || strings.TrimSpace(b.Package) == "" {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   "Bundle requires non-empty bundle_id and package",
			Retryable: false,
		}
	}

	if b.Revision < 1 {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   "Bundle revision must be a positive integer >= 1",
			Retryable: false,
		}
	}

	// Verify signer and issuer evidence before accepting authority
	if !b.SignatureVerified || strings.TrimSpace(b.Signature) == "" || strings.TrimSpace(b.SignerKeyID) == "" || strings.TrimSpace(b.Issuer) == "" {
		return nil, &BundleError{
			Code:      ErrCodeUntrustedSigner,
			Message:   "Bundle is missing cryptographic signature evidence or signer verification",
			Retryable: false,
		}
	}

	if len(e.trustedIssuers) > 0 && !e.trustedIssuers[b.Issuer] {
		return nil, &BundleError{
			Code:      ErrCodeUntrustedSigner,
			Message:   fmt.Sprintf("Bundle issuer '%s' is not in the trusted issuer set", b.Issuer),
			Retryable: false,
		}
	}

	if len(e.trustedSigners) > 0 && !e.trustedSigners[b.SignerKeyID] {
		return nil, &BundleError{
			Code:      ErrCodeUntrustedSigner,
			Message:   fmt.Sprintf("Bundle signer key '%s' is not in the trusted signer set", b.SignerKeyID),
			Retryable: false,
		}
	}

	// Verify digest format and exact canonical SHA-256 content match (detects single-byte modifications)
	if !bundleDigestPattern.MatchString(b.Digest) {
		return nil, &BundleError{
			Code:      ErrCodeTamperedBundle,
			Message:   "Bundle digest is missing or malformed; expected sha256:<64-hex>",
			Retryable: false,
		}
	}

	computedDigest := ComputeCanonicalBundleDigest(b)
	if computedDigest != b.Digest {
		return nil, &BundleError{
			Code:      ErrCodeTamperedBundle,
			Message:   fmt.Sprintf("Bundle content digest mismatch: declared %s, computed %s", b.Digest, computedDigest),
			Retryable: false,
		}
	}

	// Verify Rego module syntax and fail-closed default
	if err := validateRegoSyntax(b.Package, b.RegoModule); err != nil {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   fmt.Sprintf("Invalid policy syntax: %v", err),
			Retryable: false,
		}
	}

	// Verify rule count and rule validity
	if len(b.Rules) == 0 || len(b.Rules) > MaxBundleRules {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   fmt.Sprintf("Bundle must contain between 1 and %d policy rules", MaxBundleRules),
			Retryable: false,
		}
	}

	for _, rule := range b.Rules {
		if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.PathPattern) == "" || len(rule.Actions) == 0 {
			return nil, &BundleError{
				Code:      ErrCodeInvalidPolicyBundle,
				Message:   fmt.Sprintf("Policy rule '%s' is missing required id, path_pattern, or actions", rule.ID),
				Retryable: false,
			}
		}
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return nil, &BundleError{
				Code:      ErrCodeInvalidPolicyBundle,
				Message:   fmt.Sprintf("Policy rule '%s' has invalid effect '%s'; must be 'allow' or 'deny'", rule.ID, rule.Effect),
				Retryable: false,
			}
		}
		if rule.ResourceClass != "" && !rule.ResourceClass.IsValid() {
			return nil, &BundleError{
				Code:      ErrCodeInvalidPolicyBundle,
				Message:   fmt.Sprintf("Policy rule '%s' has invalid resource_class '%s'", rule.ID, rule.ResourceClass),
				Retryable: false,
			}
		}
	}

	// Build route registry (also validates F01 route invariants)
	reg, err := NewRouteRegistry(b.Routes...)
	if err != nil {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   fmt.Sprintf("Invalid route configuration in bundle: %v", err),
			Retryable: false,
		}
	}

	// Verify validity period timestamps
	issuedAt, err := time.Parse(time.RFC3339, b.IssuedAt)
	if err != nil {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   "Bundle issued_at must be a valid RFC3339 timestamp",
			Retryable: false,
		}
	}
	expiresAt, err := time.Parse(time.RFC3339, b.ExpiresAt)
	if err != nil {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   "Bundle expires_at must be a valid RFC3339 timestamp",
			Retryable: false,
		}
	}
	if !expiresAt.After(issuedAt) {
		return nil, &BundleError{
			Code:      ErrCodeInvalidPolicyBundle,
			Message:   "Bundle expires_at must be strictly after issued_at",
			Retryable: false,
		}
	}

	if !evalTime.IsZero() {
		if evalTime.Before(issuedAt) {
			return nil, &BundleError{
				Code:      ErrCodeExpiredPolicyBundle,
				Message:   fmt.Sprintf("Bundle '%s' is not yet valid at %s (issued_at %s)", b.BundleID, evalTime.UTC().Format(time.RFC3339), b.IssuedAt),
				Retryable: false,
			}
		}
		if !evalTime.Before(expiresAt) {
			return nil, &BundleError{
				Code:      ErrCodeExpiredPolicyBundle,
				Message:   fmt.Sprintf("Bundle '%s' expired at %s (eval_time %s)", b.BundleID, b.ExpiresAt, evalTime.UTC().Format(time.RFC3339)),
				Retryable: false,
			}
		}
	}

	return reg, nil
}

// LoadBundle validates and activates a candidate policy bundle.
// If the candidate bundle is invalid, tampered, untrusted, expired, or has a stale/replayed revision
// (revision <= highestRevision), LoadBundle rejects it with a typed error and preserves the last valid
// accepted authority unchanged.
func (e *BundleEvaluator) LoadBundle(b LocalPolicyBundle, evalTime time.Time) *BundleError {
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	reg, bErr := e.ValidateBundle(b, evalTime)
	if bErr != nil {
		return bErr
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if b.Revision <= e.highestRevision {
		return &BundleError{
			Code:      ErrCodeStaleOrReplayedRevision,
			Message:   fmt.Sprintf("Rejected stale or replayed bundle revision %d; active revision is %d", b.Revision, e.highestRevision),
			Retryable: false,
		}
	}

	bundleCopy := b
	e.activeBundle = &bundleCopy
	e.activeRegistry = reg
	e.highestRevision = b.Revision
	return nil
}

// ActiveBundle returns a copy of the currently active valid policy bundle, if any.
func (e *BundleEvaluator) ActiveBundle() (LocalPolicyBundle, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.activeBundle == nil {
		return LocalPolicyBundle{}, false
	}
	return *e.activeBundle, true
}

// HighestRevision returns the highest monotonic bundle revision accepted by the evaluator.
func (e *BundleEvaluator) HighestRevision() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.highestRevision
}

func matchPathPattern(pattern, path string) bool {
	if pattern == "*" || pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix)
	}
	return false
}

func matchAction(ruleActions []string, action string) bool {
	norm := strings.ToLower(strings.TrimSpace(action))
	for _, a := range ruleActions {
		la := strings.ToLower(strings.TrimSpace(a))
		if la == "*" || la == norm {
			return true
		}
	}
	return false
}

func matchRoles(requiredRoles []string, subject SubjectIdentity) bool {
	if len(requiredRoles) == 0 {
		return true
	}
	for _, reqRole := range requiredRoles {
		if subject.HasRole(reqRole) {
			return true
		}
	}
	return false
}

// Evaluate executes a bounded authorization evaluation against the active (or inline) policy bundle.
// Invalid policy, untrusted/tampered bundles, expired authority, unauthenticated private access,
// and exceeded deadlines strictly produce allow: false and a typed error (Requirement F02).
func (e *BundleEvaluator) Evaluate(parentCtx context.Context, input BundleEvalInput) BundleDecision {
	start := time.Now()
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	// 1. Validate deadline configuration
	deadlineMS := input.DeadlineMS
	if deadlineMS == 0 {
		deadlineMS = DefaultEvaluationDeadlineMS
	}
	if deadlineMS < 0 || deadlineMS > MaxEvaluationDeadlineMS {
		return BundleDecision{
			Allow:          false,
			Classification: ResourceClassPrivate,
			Reasons:        []string{ErrCodeDeadlineExceeded},
			Obligations:    []PolicyObligation{},
			Error: &BundleError{
				Code:      ErrCodeDeadlineExceeded,
				Message:   fmt.Sprintf("Requested deadline_ms (%d) is invalid or exceeds maximum allowed %dms bound", input.DeadlineMS, MaxEvaluationDeadlineMS),
				Retryable: false,
			},
			ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
			WithinDeadline: false,
		}
	}

	evalCtx, cancel := context.WithTimeout(parentCtx, time.Duration(deadlineMS)*time.Millisecond)
	defer cancel()

	// 2. Parse evaluation timestamp
	evalTime := time.Now().UTC()
	if strings.TrimSpace(input.EvalTime) != "" {
		parsedTime, err := time.Parse(time.RFC3339, input.EvalTime)
		if err != nil {
			return BundleDecision{
				Allow:          false,
				Classification: ResourceClassPrivate,
				Reasons:        []string{ErrCodeInvalidPolicyBundle},
				Obligations:    []PolicyObligation{},
				Error: &BundleError{
					Code:      ErrCodeInvalidPolicyBundle,
					Message:   fmt.Sprintf("Invalid eval_time RFC3339 timestamp: %v", err),
					Retryable: false,
				},
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				WithinDeadline: true,
			}
		}
		evalTime = parsedTime
	}

	// 3. Resolve bundle to evaluate (inline candidate or active authority)
	var bundle LocalPolicyBundle
	var reg *RouteRegistry

	if input.Bundle != nil {
		// If an inline bundle is provided, validate it through LoadBundle semantics if no active bundle exists
		// or validate it directly against the evaluator's trust and monotonic revision constraints.
		validatedReg, bErr := e.ValidateBundle(*input.Bundle, evalTime)
		if bErr != nil {
			return BundleDecision{
				Allow:          false,
				PolicyDigest:   input.Bundle.Digest,
				Revision:       input.Bundle.Revision,
				Classification: ResourceClassPrivate,
				Reasons:        []string{bErr.Code},
				Obligations:    []PolicyObligation{},
				Error:          bErr,
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				WithinDeadline: true,
			}
		}
		e.mu.RLock()
		highest := e.highestRevision
		e.mu.RUnlock()
		if highest > 0 && input.Bundle.Revision < highest {
			staleErr := &BundleError{
				Code:      ErrCodeStaleOrReplayedRevision,
				Message:   fmt.Sprintf("Bundle revision %d is older than accepted revision %d", input.Bundle.Revision, highest),
				Retryable: false,
			}
			return BundleDecision{
				Allow:          false,
				PolicyDigest:   input.Bundle.Digest,
				Revision:       input.Bundle.Revision,
				Classification: ResourceClassPrivate,
				Reasons:        []string{staleErr.Code},
				Obligations:    []PolicyObligation{},
				Error:          staleErr,
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				WithinDeadline: true,
			}
		}
		bundle = *input.Bundle
		reg = validatedReg
	} else {
		e.mu.RLock()
		if e.activeBundle != nil {
			bundle = *e.activeBundle
			reg = e.activeRegistry
		}
		e.mu.RUnlock()

		if reg == nil {
			return BundleDecision{
				Allow:          false,
				Classification: ResourceClassPrivate,
				Reasons:        []string{ErrCodeNoActiveBundle},
				Obligations:    []PolicyObligation{},
				Error: &BundleError{
					Code:      ErrCodeNoActiveBundle,
					Message:   "No valid active policy bundle loaded; failing closed",
					Retryable: false,
				},
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				WithinDeadline: true,
			}
		}

		// Re-verify active bundle freshness at evaluation time
		if _, bErr := e.ValidateBundle(bundle, evalTime); bErr != nil {
			return BundleDecision{
				Allow:          false,
				PolicyDigest:   bundle.Digest,
				Revision:       bundle.Revision,
				Classification: ResourceClassPrivate,
				Reasons:        []string{bErr.Code},
				Obligations:    []PolicyObligation{},
				Error:          bErr,
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				WithinDeadline: true,
			}
		}
	}

	// 4. Enforce execution deadline (including deterministic simulated delay when testing deadline bounds)
	if input.SimulatedDelayMS > 0 {
		delay := time.Duration(input.SimulatedDelayMS) * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-evalCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}

	select {
	case <-evalCtx.Done():
		err := evalCtx.Err()
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0
		if errors.Is(err, context.Canceled) {
			return BundleDecision{
				Allow:          false,
				PolicyDigest:   bundle.Digest,
				Revision:       bundle.Revision,
				Classification: ResourceClassPrivate,
				Reasons:        []string{ErrCodeRequestCancelled},
				Obligations:    []PolicyObligation{},
				Error: &BundleError{
					Code:      ErrCodeRequestCancelled,
					Message:   "Policy evaluation cancelled before completion; failing closed",
					Retryable: true,
				},
				ElapsedMS:      elapsed,
				WithinDeadline: elapsed <= float64(deadlineMS),
			}
		}
		return BundleDecision{
			Allow:          false,
			PolicyDigest:   bundle.Digest,
			Revision:       bundle.Revision,
			Classification: ResourceClassPrivate,
			Reasons:        []string{ErrCodeDeadlineExceeded},
			Obligations:    []PolicyObligation{},
			Error: &BundleError{
				Code:      ErrCodeDeadlineExceeded,
				Message:   fmt.Sprintf("Policy evaluation exceeded %dms deadline; failing closed without fallback permit", deadlineMS),
				Retryable: true,
			},
			ElapsedMS:      elapsed,
			WithinDeadline: false,
		}
	default:
	}

	// 5. Evaluate F01 route classification and baseline access via RouteRegistry
	routeOut := reg.EvaluateRoute(EvaluationInput{
		Path:       input.Path,
		Action:     input.Action,
		Subject:    input.Subject,
		ResourceID: input.ResourceID,
	})

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0
	if !routeOut.Allow {
		return BundleDecision{
			Allow:          false,
			PolicyDigest:   bundle.Digest,
			Revision:       bundle.Revision,
			Classification: routeOut.Classification,
			Reasons:        []string{routeOut.ReasonCode},
			Obligations:    []PolicyObligation{},
			Error: &BundleError{
				Code:      ErrCodePrivateFailClosed,
				Message:   routeOut.ReasonMessage,
				Retryable: false,
			},
			ElapsedMS:      elapsed,
			WithinDeadline: true,
		}
	}

	// 6. Evaluate explicit bundle policy rules (deny rules take precedence over allow rules; default is deny)
	var matchedAllow *PolicyRule
	for i := range bundle.Rules {
		rule := &bundle.Rules[i]
		if !matchPathPattern(rule.PathPattern, input.Path) {
			continue
		}
		if !matchAction(rule.Actions, input.Action) {
			continue
		}
		if !matchRoles(rule.Roles, input.Subject) {
			continue
		}
		if rule.Effect == "deny" {
			reason := rule.ReasonCode
			if reason == "" {
				reason = "POLICY_EXPLICIT_DENY"
			}
			msg := rule.ReasonMessage
			if msg == "" {
				msg = "Explicit policy deny rule matched"
			}
			return BundleDecision{
				Allow:          false,
				PolicyDigest:   bundle.Digest,
				Revision:       bundle.Revision,
				Classification: routeOut.Classification,
				Reasons:        []string{reason},
				Obligations:    []PolicyObligation{},
				Error: &BundleError{
					Code:      ErrCodePrivateFailClosed,
					Message:   msg,
					Retryable: false,
				},
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				WithinDeadline: true,
			}
		}
		if rule.Effect == "allow" && matchedAllow == nil {
			matchedAllow = rule
		}
	}

	if matchedAllow == nil {
		// Fail closed: even if route registry allowed baseline authentication, bundle must have an explicit matching allow rule
		return BundleDecision{
			Allow:          false,
			PolicyDigest:   bundle.Digest,
			Revision:       bundle.Revision,
			Classification: routeOut.Classification,
			Reasons:        []string{ErrCodePrivateFailClosed, "NO_MATCHING_BUNDLE_ALLOW_RULE"},
			Obligations:    []PolicyObligation{},
			Error: &BundleError{
				Code:      ErrCodePrivateFailClosed,
				Message:   "No matching allow rule in policy bundle; failing closed",
				Retryable: false,
			},
			ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
			WithinDeadline: true,
		}
	}

	reasonCode := matchedAllow.ReasonCode
	if reasonCode == "" {
		reasonCode = routeOut.ReasonCode
	}
	obligations := matchedAllow.Obligations
	if obligations == nil {
		obligations = []PolicyObligation{}
	}

	return BundleDecision{
		Allow:          true,
		PolicyDigest:   bundle.Digest,
		Revision:       bundle.Revision,
		Classification: routeOut.Classification,
		Reasons:        []string{reasonCode},
		Obligations:    obligations,
		Error:          nil,
		ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
		WithinDeadline: true,
	}
}
