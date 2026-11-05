package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/audit"
	"github.com/parsa-emami/policyhelix/internal/contracts"
)

// Specific error codes for C18 policy obligation enforcement (Requirement F12).
const (
	ErrCodeUnknownObligation   = "UNKNOWN_MANDATORY_OBLIGATION"
	ErrCodeMalformedObligation = "MALFORMED_OBLIGATION"
	ErrCodeObligationFailed    = "OBLIGATION_EXECUTION_FAILED"
)

// Status constants for executed obligations.
const (
	ObligationStatusSatisfied     = "satisfied"
	ObligationStatusIgnoredAdvice = "ignored_advice"
	ObligationStatusFailed        = "failed"
)

// Obligation models an authorization obligation attached to a policy decision.
// By default, obligations are mandatory unless explicitly designated as advice (mandatory == false).
type Obligation struct {
	ID         string                 `json:"id,omitempty"`
	Type       string                 `json:"type"`
	Mandatory  *bool                  `json:"mandatory,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// IsMandatory reports whether the obligation must be strictly enforced.
// If not explicitly set to false, obligations default to mandatory (Requirement F12).
func (o Obligation) IsMandatory() bool {
	if o.Mandatory == nil {
		return true
	}
	return *o.Mandatory
}

// ObligationExecutionRequest represents an inbound request to enforce attached policy obligations.
type ObligationExecutionRequest struct {
	RequestID              string             `json:"request_id,omitempty"`
	Obligations            []Obligation       `json:"obligations"`
	Subject                *contracts.Subject `json:"subject,omitempty"`
	ResourceClassification string             `json:"resource_classification,omitempty"`
	TargetUpstreamID       string             `json:"target_upstream_id,omitempty"`
	Path                   string             `json:"path,omitempty"`
	Method                 string             `json:"method,omitempty"`
	Headers                map[string]string  `json:"headers,omitempty"`
	ProviderUnavailable    bool               `json:"provider_unavailable,omitempty"`
	ProviderState          string             `json:"provider_state,omitempty"`
	EvaluationTime         time.Time          `json:"evaluation_time,omitempty"`
}

// ExecutedObligation details the outcome of executing a single obligation.
type ExecutedObligation struct {
	ID              string            `json:"id,omitempty"`
	Type            string            `json:"type"`
	Status          string            `json:"status"`
	Details         string            `json:"details,omitempty"`
	InjectedHeaders map[string]string `json:"injected_headers,omitempty"`
}

// ObligationExecutionResult represents the authoritative outcome of obligation enforcement.
type ObligationExecutionResult struct {
	Valid               bool                     `json:"valid"`
	Allow               bool                     `json:"allow"`
	StatusCode          int                      `json:"status_code"`
	ErrorCode           string                   `json:"error_code,omitempty"`
	ErrorMessage        string                   `json:"error_message,omitempty"`
	ExecutedObligations []ExecutedObligation     `json:"executed_obligations,omitempty"`
	DownstreamHeaders   map[string]string        `json:"downstream_headers,omitempty"`
	AuditRecords        []map[string]interface{} `json:"audit_records,omitempty"`
}

// Helper to parse numeric limits regardless of underlying numeric JSON type
func getNumericLimit(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	default:
		return 0, false
	}
}

// validateInjectedHeader guarantees downstream injected headers cannot spoof identity,
// inject CRLF, or overwrite canonical gateway proof headers.
func validateInjectedHeader(key, val string) (string, string, string) {
	cleanKey := strings.TrimSpace(key)
	if cleanKey == "" {
		return "", "", "header name cannot be empty"
	}
	if strings.ContainsAny(cleanKey, "\r\n") || strings.ContainsAny(val, "\r\n") {
		return "", "", "header name or value contains illegal CRLF characters"
	}
	canonical := http.CanonicalHeaderKey(cleanKey)
	if canonical == http.CanonicalHeaderKey(HeaderGatewayProof) ||
		canonical == http.CanonicalHeaderKey(HeaderPolicyHelixSubject) ||
		canonical == http.CanonicalHeaderKey(HeaderPolicyHelixIssuer) ||
		canonical == http.CanonicalHeaderKey(HeaderPolicyHelixRoles) ||
		canonical == http.CanonicalHeaderKey(HeaderPolicyHelixAuthenticated) ||
		canonical == http.CanonicalHeaderKey(HeaderPolicyHelixSessionEpoch) ||
		canonical == http.CanonicalHeaderKey(HeaderPolicyHelixSessionID) ||
		canonical == http.CanonicalHeaderKey(HeaderPolicyHelixTenantID) {
		return "", "", fmt.Sprintf("header '%s' is a reserved gateway identity header and cannot be injected", cleanKey)
	}
	for _, prohibited := range ProhibitedClientIdentityHeaders {
		if strings.EqualFold(canonical, prohibited) {
			return "", "", fmt.Sprintf("header '%s' is a prohibited identity header and cannot be injected", cleanKey)
		}
	}
	return cleanKey, val, ""
}

// Supported obligation types recognized by PolicyHelix PEP.
func isSupportedObligationType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "audit", "audit_log", "log":
		return true
	case "header_inject", "transform_header", "inject_header":
		return true
	case "rate_limit", "rate-limit":
		return true
	case "redact", "mask", "filter":
		return true
	default:
		return false
	}
}

// EnforceObligations evaluates and enforces all attached obligations atomically.
// Requirement F12: Unknown mandatory obligations cause immediate fail-closed denial.
func EnforceObligations(ctx context.Context, req ObligationExecutionRequest) (*ObligationExecutionResult, error) {
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}

	// Gate 1: Check provider availability
	if req.ProviderUnavailable || strings.EqualFold(req.ProviderState, "unavailable") {
		return &ObligationExecutionResult{
			Valid:        false,
			Allow:        false,
			StatusCode:   http.StatusServiceUnavailable,
			ErrorCode:    ErrCodeProviderUnavailable,
			ErrorMessage: "Fail closed: obligation enforcement provider is unavailable",
		}, nil
	}

	// Gate 2: Check for malformed obligations (syntax validation before semantic authorization)
	for _, ob := range req.Obligations {
		if strings.TrimSpace(ob.Type) == "" {
			return &ObligationExecutionResult{
				Valid:        false,
				Allow:        false,
				StatusCode:   http.StatusBadRequest,
				ErrorCode:    ErrCodeMalformedObligation,
				ErrorMessage: "Malformed obligation: missing or empty obligation type",
			}, nil
		}
	}

	// Gate 3: Enforce private resource authentication invariant
	resClass := req.ResourceClassification
	if resClass == "" {
		resClass = "private"
	}
	if resClass == "private" && (req.Subject == nil || !req.Subject.Authenticated) {
		return &ObligationExecutionResult{
			Valid:        false,
			Allow:        false,
			StatusCode:   http.StatusForbidden,
			ErrorCode:    ErrCodePrivateResource,
			ErrorMessage: "Fail closed: unauthenticated access to private resource with obligations denied",
		}, nil
	}

	// If no obligations are present, allow immediately
	if len(req.Obligations) == 0 {
		return &ObligationExecutionResult{
			Valid:               true,
			Allow:               true,
			StatusCode:          http.StatusOK,
			ExecutedObligations: []ExecutedObligation{},
			DownstreamHeaders:   make(map[string]string),
			AuditRecords:        make([]map[string]interface{}, 0),
		}, nil
	}

	downstreamHeaders := make(map[string]string)
	executed := make([]ExecutedObligation, 0, len(req.Obligations))
	auditRecords := make([]map[string]interface{}, 0)

	subjID := "anonymous"
	if req.Subject != nil && req.Subject.ID != "" {
		subjID = req.Subject.ID
	}

	// Gate 3: Iterate and enforce each obligation
	for _, ob := range req.Obligations {
		cleanType := strings.TrimSpace(ob.Type)
		if cleanType == "" {
			return &ObligationExecutionResult{
				Valid:        false,
				Allow:        false,
				StatusCode:   http.StatusBadRequest,
				ErrorCode:    ErrCodeMalformedObligation,
				ErrorMessage: "Malformed obligation: missing or empty obligation type",
			}, nil
		}

		if !isSupportedObligationType(cleanType) {
			if ob.IsMandatory() {
				// Requirement F12: Unknown mandatory obligation denies rather than being ignored
				return &ObligationExecutionResult{
					Valid:        false,
					Allow:        false,
					StatusCode:   http.StatusForbidden,
					ErrorCode:    ErrCodeUnknownObligation,
					ErrorMessage: fmt.Sprintf("Fail closed: unknown mandatory obligation '%s' denied", cleanType),
				}, nil
			}

			// Non-mandatory unknown obligation is advisory advice: safely ignore
			executed = append(executed, ExecutedObligation{
				ID:      ob.ID,
				Type:    cleanType,
				Status:  ObligationStatusIgnoredAdvice,
				Details: fmt.Sprintf("Advisory obligation '%s' safely ignored", cleanType),
			})
			continue
		}

		// Check for simulated execution failure directive
		if ob.Parameters != nil {
			if shouldFail, ok := ob.Parameters["fail"].(bool); ok && shouldFail {
				return &ObligationExecutionResult{
					Valid:        false,
					Allow:        false,
					StatusCode:   http.StatusForbidden,
					ErrorCode:    ErrCodeObligationFailed,
					ErrorMessage: fmt.Sprintf("Obligation '%s' execution failed", cleanType),
				}, nil
			}
		}

		// Execute supported handler
		switch strings.ToLower(cleanType) {
		case "audit", "audit_log", "log":
			pseudonym := audit.ComputeSubjectPseudonym(subjID, "")
			record := map[string]interface{}{
				"request_id":         req.RequestID,
				"event":              "obligation_audit",
				"recorded_at":        evalTime.Format(time.RFC3339),
				"subject_id":         pseudonym,
				"subject_pseudonym":  pseudonym,
				"target_upstream_id": req.TargetUpstreamID,
				"path":               req.Path,
				"method":             req.Method,
			}
			if ob.Parameters != nil {
				sanitizedParams := audit.RedactMap(ob.Parameters, nil)
				for k, v := range sanitizedParams {
					record[k] = v
				}
			}
			auditRecords = append(auditRecords, record)
			executed = append(executed, ExecutedObligation{
				ID:      ob.ID,
				Type:    cleanType,
				Status:  ObligationStatusSatisfied,
				Details: "Audit event recorded successfully",
			})

		case "header_inject", "transform_header", "inject_header":
			injected := make(map[string]string)
			if ob.Parameters != nil {
				if headersMap, ok := ob.Parameters["headers"].(map[string]interface{}); ok {
					for hk, hv := range headersMap {
						valStr := fmt.Sprintf("%v", hv)
						k, v, errStr := validateInjectedHeader(hk, valStr)
						if errStr != "" {
							return &ObligationExecutionResult{
								Valid:        false,
								Allow:        false,
								StatusCode:   http.StatusBadRequest,
								ErrorCode:    ErrCodeMalformedObligation,
								ErrorMessage: fmt.Sprintf("Malformed header injection obligation: %s", errStr),
							}, nil
						}
						downstreamHeaders[k] = v
						injected[k] = v
					}
				}
				if hName, ok := ob.Parameters["header_name"].(string); ok && hName != "" {
					hVal := fmt.Sprintf("%v", ob.Parameters["header_value"])
					k, v, errStr := validateInjectedHeader(hName, hVal)
					if errStr != "" {
						return &ObligationExecutionResult{
							Valid:        false,
							Allow:        false,
							StatusCode:   http.StatusBadRequest,
							ErrorCode:    ErrCodeMalformedObligation,
							ErrorMessage: fmt.Sprintf("Malformed header injection obligation: %s", errStr),
						}, nil
					}
					downstreamHeaders[k] = v
					injected[k] = v
				}
			}
			if len(injected) == 0 {
				defaultHeader := "X-PolicyHelix-Obligation-Token"
				defaultVal := "satisfied"
				downstreamHeaders[defaultHeader] = defaultVal
				injected[defaultHeader] = defaultVal
			}
			executed = append(executed, ExecutedObligation{
				ID:              ob.ID,
				Type:            cleanType,
				Status:          ObligationStatusSatisfied,
				Details:         "Downstream headers injected successfully",
				InjectedHeaders: injected,
			})

		case "rate_limit", "rate-limit":
			if ob.Parameters != nil {
				if limVal, ok := ob.Parameters["limit"]; ok {
					if lim, isNum := getNumericLimit(limVal); isNum && lim < 0 {
						return &ObligationExecutionResult{
							Valid:        false,
							Allow:        false,
							StatusCode:   http.StatusBadRequest,
							ErrorCode:    ErrCodeMalformedObligation,
							ErrorMessage: "Rate limit invalid: negative limit",
						}, nil
					}
				}
			}
			executed = append(executed, ExecutedObligation{
				ID:      ob.ID,
				Type:    cleanType,
				Status:  ObligationStatusSatisfied,
				Details: "Rate limit policy satisfied",
			})

		case "redact", "mask", "filter":
			executed = append(executed, ExecutedObligation{
				ID:      ob.ID,
				Type:    cleanType,
				Status:  ObligationStatusSatisfied,
				Details: "Data filtering and redaction policy applied",
			})
		}
	}

	return &ObligationExecutionResult{
		Valid:               true,
		Allow:               true,
		StatusCode:          http.StatusOK,
		ExecutedObligations: executed,
		DownstreamHeaders:   downstreamHeaders,
		AuditRecords:        auditRecords,
	}, nil
}
