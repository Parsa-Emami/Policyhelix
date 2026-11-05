package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/contracts"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

// Specific error codes for C19 per-resource outage behavior (Requirement F13).
const (
	ErrCodeDecisionLossDeny          = "DECISION_LOSS_SENSITIVE_DENY"
	ErrCodeUnspecifiedRouteOutage    = "UNSPECIFIED_ROUTE_OUTAGE_DENY"
	ErrCodeMalformedFailureConfig    = "MALFORMED_FAILURE_CONFIG"
	ErrCodeIllegalPublicBypassConfig = "ILLEGAL_PUBLIC_BYPASS_CONFIG"
)

// Disposition constants for outage evaluation outcomes.
const (
	OutageDispositionFailClosedDeny          = "FAIL_CLOSED_DENY"
	OutageDispositionIntentionalPublicBypass = "INTENTIONAL_PUBLIC_BYPASS"
	OutageDispositionHealthyDecision         = "HEALTHY_DECISION_ENFORCED"
)

// ResourceOutageRequest models an inbound authorization request during possible
// policy decision service outage, timeout, or provider failure.
type ResourceOutageRequest struct {
	RequestID              string                 `json:"request_id,omitempty"`
	Path                   string                 `json:"path"`
	Method                 string                 `json:"method,omitempty"`
	Headers                map[string]string      `json:"headers,omitempty"`
	Subject                *contracts.Subject     `json:"subject,omitempty"`
	ResourceClassification string                 `json:"resource_classification,omitempty"`
	DecisionLoss           bool                   `json:"decision_loss"`
	DecisionEngineState    string                 `json:"decision_engine_state,omitempty"` // "healthy", "outage", "timeout", "corrupted"
	ProviderUnavailable    bool                   `json:"provider_unavailable,omitempty"`
	ProviderState          string                 `json:"provider_state,omitempty"`
	ExplicitPublicRoute    bool                   `json:"explicit_public_route,omitempty"`
	AllowPublicBypass      bool                   `json:"allow_public_bypass,omitempty"`
	EvaluationTime         time.Time              `json:"evaluation_time,omitempty"`
	ContextData            map[string]interface{} `json:"context_data,omitempty"`
}

// ResourceOutageResult represents the authoritative outcome of per-resource outage evaluation.
type ResourceOutageResult struct {
	Valid                     bool                   `json:"valid"`
	Allow                     bool                   `json:"allow"`
	StatusCode                int                    `json:"status_code"`
	ErrorCode                 string                 `json:"error_code,omitempty"`
	ErrorMessage              string                 `json:"error_message,omitempty"`
	Disposition               string                 `json:"disposition"`
	Classification            policy.ResourceClass   `json:"classification"`
	PublicBypassUsed          bool                   `json:"public_bypass_used"`
	ForwardedToUpstream       bool                   `json:"forwarded_to_upstream"`
	SideEffectsExecuted       bool                   `json:"side_effects_executed"`
	Subject                   *contracts.Subject     `json:"subject,omitempty"`
	StrippedHeaders           []string               `json:"stripped_headers,omitempty"`
	DownstreamInjectedHeaders map[string]string      `json:"downstream_injected_headers,omitempty"`
	OutageMetadata            map[string]interface{} `json:"outage_metadata,omitempty"`
}

// OutageRecord represents a durable record of an outage event and its recovery status.
type OutageRecord struct {
	EventID        string    `json:"event_id"`
	Component      string    `json:"component"`
	State          string    `json:"state"` // "outage", "recovered"
	RecordedAt     time.Time `json:"recorded_at"`
	RecoveredAt    time.Time `json:"recovered_at,omitempty"`
	SensitiveDeny  int       `json:"sensitive_deny_count"`
	PublicBypasses int       `json:"public_bypass_count"`
}

// EvaluateResourceOutage evaluates the request against per-resource outage rules.
// Requirement F13: Decision loss denies sensitive routes; public route bypass remains intentional and testable.
func EvaluateResourceOutage(ctx context.Context, req ResourceOutageRequest) (*ResourceOutageResult, error) {
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}

	cleanPath := strings.TrimSpace(req.Path)
	if cleanPath == "" {
		return &ResourceOutageResult{
			Valid:               false,
			Allow:               false,
			StatusCode:          http.StatusBadRequest,
			ErrorCode:           ErrCodeMalformedFailureConfig,
			ErrorMessage:        "Path cannot be empty for resource outage evaluation",
			Disposition:         OutageDispositionFailClosedDeny,
			Classification:      policy.ResourceClassPrivate,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
		}, nil
	}

	// Gate 1: Check for path traversal attempts
	if strings.Contains(cleanPath, "..") || strings.Contains(cleanPath, "//") || strings.Contains(cleanPath, "@") {
		return &ResourceOutageResult{
			Valid:               false,
			Allow:               false,
			StatusCode:          http.StatusForbidden,
			ErrorCode:           ErrCodeWidenedPermission,
			ErrorMessage:        fmt.Sprintf("Path traversal or malformed path '%s' denied", cleanPath),
			Disposition:         OutageDispositionFailClosedDeny,
			Classification:      policy.ResourceClassPrivate,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
		}, nil
	}

	// Gate 2: Resolve resource classification with Requirement F01 default-private invariant
	var resClass policy.ResourceClass
	rawClass := strings.ToLower(strings.TrimSpace(req.ResourceClassification))
	switch rawClass {
	case "public":
		resClass = policy.ResourceClassPublic
	case "internal":
		resClass = policy.ResourceClassInternal
	case "restricted":
		resClass = policy.ResourceClassRestricted
	case "private":
		resClass = policy.ResourceClassPrivate
	case "":
		// If unspecified, check if explicit public route flag is set or standard public probe paths
		if req.ExplicitPublicRoute && (cleanPath == "/health" || cleanPath == "/healthz") {
			resClass = policy.ResourceClassPublic
		} else {
			// F01 Default: all unspecified routes default strictly to private
			resClass = policy.ResourceClassPrivate
		}
	default:
		return &ResourceOutageResult{
			Valid:               false,
			Allow:               false,
			StatusCode:          http.StatusBadRequest,
			ErrorCode:           ErrCodeMalformedFailureConfig,
			ErrorMessage:        fmt.Sprintf("Invalid resource classification '%s'", req.ResourceClassification),
			Disposition:         OutageDispositionFailClosedDeny,
			Classification:      policy.ResourceClassPrivate,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
		}, nil
	}

	// Gate 3: Invariant Guard - Illegal Public Bypass on Sensitive Routes
	// An operator or configuration MUST NOT be allowed to enable outage bypass on sensitive routes.
	if req.AllowPublicBypass && resClass != policy.ResourceClassPublic {
		return &ResourceOutageResult{
			Valid:               false,
			Allow:               false,
			StatusCode:          http.StatusForbidden,
			ErrorCode:           ErrCodeIllegalPublicBypassConfig,
			ErrorMessage:        fmt.Sprintf("Illegal configuration: route '%s' classified as '%s' cannot have outage bypass enabled; only explicit public routes may bypass outage", cleanPath, resClass),
			Disposition:         OutageDispositionFailClosedDeny,
			Classification:      resClass,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
		}, nil
	}

	// Gate 4: Header Stripping (C16)
	sanitizedHeaders, strippedHeaders := StripUntrustedHeaders(req.Headers)

	// Gate 5: Detect Decision Loss Condition
	isDecisionLoss := req.DecisionLoss ||
		req.ProviderUnavailable ||
		strings.EqualFold(strings.TrimSpace(req.ProviderState), "unavailable") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "outage") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "timeout") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "corrupted") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "deadline_exceeded")

	// Gate 6: Evaluate Decision Loss Behavior (Requirement F13)
	if isDecisionLoss {
		// Case A: Explicit Public Route with intentional bypass enabled
		if resClass == policy.ResourceClassPublic && (req.AllowPublicBypass || (req.ExplicitPublicRoute && (cleanPath == "/health" || cleanPath == "/healthz"))) {
			anonSubject := contracts.Subject{
				ID:            "anonymous",
				Issuer:        "https://policyhelix.local/auth",
				Roles:         []string{"public"},
				Authenticated: false,
				SessionEpoch:  0,
			}

			injected := make(map[string]string, len(sanitizedHeaders)+5)
			for k, v := range sanitizedHeaders {
				injected[k] = v
			}
			injected[HeaderPolicyHelixSubject] = anonSubject.ID
			injected[HeaderPolicyHelixIssuer] = anonSubject.Issuer
			injected[HeaderPolicyHelixRoles] = "public"
			injected[HeaderPolicyHelixAuthenticated] = "false"
			injected[HeaderPolicyHelixSessionEpoch] = "0"

			metadata := map[string]interface{}{
				"outage_detected":        true,
				"decision_loss_reason":   "provider_or_engine_outage",
				"bypass_reason":          "explicit_public_route_intentional_bypass",
				"path":                   cleanPath,
				"resource_class":         string(resClass),
				"evaluated_at":           evalTime.Format(time.RFC3339),
				"side_effects_prevented": true,
			}

			return &ResourceOutageResult{
				Valid:                     true,
				Allow:                     true,
				StatusCode:                http.StatusOK,
				Disposition:               OutageDispositionIntentionalPublicBypass,
				Classification:            resClass,
				PublicBypassUsed:          true,
				ForwardedToUpstream:       true,
				SideEffectsExecuted:       false,
				Subject:                   &anonSubject,
				StrippedHeaders:           strippedHeaders,
				DownstreamInjectedHeaders: injected,
				OutageMetadata:            metadata,
			}, nil
		}

		// Case B: Sensitive Route (or public route without intentional bypass) under decision loss
		// Requirement F13: Decision loss denies sensitive routes
		errCode := ErrCodeDecisionLossDeny
		if rawClass == "" && !req.ExplicitPublicRoute {
			errCode = ErrCodeUnspecifiedRouteOutage
		}

		metadata := map[string]interface{}{
			"outage_detected":        true,
			"decision_loss_reason":   "provider_or_engine_outage",
			"path":                   cleanPath,
			"resource_class":         string(resClass),
			"evaluated_at":           evalTime.Format(time.RFC3339),
			"forwarding_prevented":   true,
			"side_effects_prevented": true,
		}

		return &ResourceOutageResult{
			Valid:               false,
			Allow:               false,
			StatusCode:          http.StatusServiceUnavailable,
			ErrorCode:           errCode,
			ErrorMessage:        fmt.Sprintf("Fail closed: decision loss denies access to sensitive route '%s' (classification: %s)", cleanPath, resClass),
			Disposition:         OutageDispositionFailClosedDeny,
			Classification:      resClass,
			PublicBypassUsed:    false,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
			StrippedHeaders:     strippedHeaders,
			OutageMetadata:      metadata,
		}, nil
	}

	// Gate 7: Healthy Decision Evaluation (No outage)
	if resClass == policy.ResourceClassPublic {
		anonSubject := contracts.Subject{
			ID:            "anonymous",
			Issuer:        "https://policyhelix.local/auth",
			Roles:         []string{"public"},
			Authenticated: false,
			SessionEpoch:  0,
		}
		if req.Subject != nil && req.Subject.Authenticated {
			anonSubject = *req.Subject
		}

		injected := make(map[string]string, len(sanitizedHeaders)+5)
		for k, v := range sanitizedHeaders {
			injected[k] = v
		}
		injected[HeaderPolicyHelixSubject] = anonSubject.ID
		injected[HeaderPolicyHelixIssuer] = anonSubject.Issuer
		injected[HeaderPolicyHelixRoles] = strings.Join(anonSubject.Roles, ",")
		injected[HeaderPolicyHelixAuthenticated] = fmt.Sprintf("%t", anonSubject.Authenticated)
		injected[HeaderPolicyHelixSessionEpoch] = fmt.Sprintf("%d", anonSubject.SessionEpoch)

		return &ResourceOutageResult{
			Valid:                     true,
			Allow:                     true,
			StatusCode:                http.StatusOK,
			Disposition:               OutageDispositionHealthyDecision,
			Classification:            resClass,
			PublicBypassUsed:          false,
			ForwardedToUpstream:       true,
			SideEffectsExecuted:       true,
			Subject:                   &anonSubject,
			StrippedHeaders:           strippedHeaders,
			DownstreamInjectedHeaders: injected,
		}, nil
	}

	// Private, internal, or restricted resources require authenticated identity
	if req.Subject == nil || !req.Subject.Authenticated {
		return &ResourceOutageResult{
			Valid:               false,
			Allow:               false,
			StatusCode:          http.StatusForbidden,
			ErrorCode:           ErrCodePrivateResource,
			ErrorMessage:        fmt.Sprintf("Fail closed: unauthenticated access to %s resource '%s' denied", resClass, cleanPath),
			Disposition:         OutageDispositionFailClosedDeny,
			Classification:      resClass,
			PublicBypassUsed:    false,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
			StrippedHeaders:     strippedHeaders,
		}, nil
	}

	injected := make(map[string]string, len(sanitizedHeaders)+5)
	for k, v := range sanitizedHeaders {
		injected[k] = v
	}
	injected[HeaderPolicyHelixSubject] = req.Subject.ID
	injected[HeaderPolicyHelixIssuer] = req.Subject.Issuer
	injected[HeaderPolicyHelixRoles] = strings.Join(req.Subject.Roles, ",")
	injected[HeaderPolicyHelixAuthenticated] = "true"
	injected[HeaderPolicyHelixSessionEpoch] = fmt.Sprintf("%d", req.Subject.SessionEpoch)

	return &ResourceOutageResult{
		Valid:                     true,
		Allow:                     true,
		StatusCode:                http.StatusOK,
		Disposition:               OutageDispositionHealthyDecision,
		Classification:            resClass,
		PublicBypassUsed:          false,
		ForwardedToUpstream:       true,
		SideEffectsExecuted:       true,
		Subject:                   req.Subject,
		StrippedHeaders:           strippedHeaders,
		DownstreamInjectedHeaders: injected,
	}, nil
}

// DurableOutageTracker tracks and persists outage state and recovery across restarts.
type DurableOutageTracker struct {
	mu            sync.RWMutex
	store         storage.StorageAdapter
	currentState  string
	lastOutageAt  time.Time
	recoveredAt   time.Time
	denyCount     int
	bypassCount   int
}

// NewDurableOutageTracker creates a new tracker optionally bound to storage.
func NewDurableOutageTracker(store storage.StorageAdapter) *DurableOutageTracker {
	return &DurableOutageTracker{
		store:        store,
		currentState: "healthy",
	}
}

// RecordOutageEvent records an outage occurrence and persists to storage if available.
func (t *DurableOutageTracker) RecordOutageEvent(ctx context.Context, component, state string, at time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.currentState = state
	if state == "outage" {
		t.lastOutageAt = at
	} else if state == "recovered" {
		t.recoveredAt = at
	}

	if t.store != nil {
		rec := OutageRecord{
			EventID:        fmt.Sprintf("outage-%s-%d", component, at.UnixNano()),
			Component:      component,
			State:          state,
			RecordedAt:     at,
			SensitiveDeny:  t.denyCount,
			PublicBypasses: t.bypassCount,
		}
		raw, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		_, err = t.store.WriteRecord(ctx, storage.WriteRequest{
			OperationID: fmt.Sprintf("op-outage-%d", at.UnixNano()),
			RecordID:    fmt.Sprintf("rec-outage-%s", component),
			Data:        raw,
		})
		return err
	}
	return nil
}

// GetStatus returns the current outage tracking status.
func (t *DurableOutageTracker) GetStatus() (string, time.Time, time.Time, int, int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.currentState, t.lastOutageAt, t.recoveredAt, t.denyCount, t.bypassCount
}

// RecordDecision records an evaluated outage result count.
func (t *DurableOutageTracker) RecordDecision(res *ResourceOutageResult) {
	if res == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !res.Allow {
		t.denyCount++
	} else if res.PublicBypassUsed {
		t.bypassCount++
	}
}
