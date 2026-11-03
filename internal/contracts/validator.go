package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	CurrentSchemaVersion = "1"
	EngineVersion        = "0.0.1"
	MaxAllowedPayload    = 65536 // 64 KiB
	MaxAllowedDeadlineMS = 200   // 200ms SLO
)

var (
	digestRegex    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	requestIDRegex = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)
)

// Typed Error Codes
const (
	ErrInvalidJSON               = "INVALID_JSON"
	ErrPayloadTooLarge           = "PAYLOAD_TOO_LARGE"
	ErrUnsupportedVersion        = "UNSUPPORTED_VERSION"
	ErrSchemaValidationFailed    = "SCHEMA_VALIDATION_FAILED"
	ErrUnauthenticatedIdentity   = "UNAUTHENTICATED_IDENTITY"
	ErrPrivateResourceFailClosed = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrStaleOrUnsignedBundle     = "STALE_OR_UNSIGNED_BUNDLE"
	ErrProviderUnavailable       = "PROVIDER_UNAVAILABLE"
	ErrDecisionTimeout           = "DECISION_TIMEOUT"
	ErrRequestCancelled          = "REQUEST_CANCELLED"
)

type Subject struct {
	ID           string   `json:"id"`
	Issuer       string   `json:"issuer"`
	Email        string   `json:"email,omitempty"`
	Roles        []string `json:"roles"`
	Authenticated bool    `json:"authenticated"`
	SessionEpoch int64    `json:"session_epoch"`
}

type Resource struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Classification string `json:"classification"`
}

type RequestContext struct {
	Protocol                 string `json:"protocol"`
	SourceIP                 string `json:"source_ip"`
	ClientID                 string `json:"client_id"`
	Timestamp                string `json:"timestamp"`
	UntrustedHeadersStripped bool   `json:"untrusted_headers_stripped"`
}

type PolicyBundleRef struct {
	Digest            string `json:"digest"`
	Revision          int64  `json:"revision"`
	SignedAt          string `json:"signed_at"`
	ExpiresAt         string `json:"expires_at,omitempty"`
	SignatureVerified bool   `json:"signature_verified"`
	ProviderState     string `json:"provider_state,omitempty"`
}

type ExecutionLimits struct {
	MaxPayloadBytes int `json:"max_payload_bytes"`
	DeadlineMS      int `json:"deadline_ms"`
	CancelAfterMS   int `json:"cancel_after_ms,omitempty"`
}

type Input struct {
	SchemaVersion string          `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	Subject       Subject         `json:"subject"`
	Resource      Resource        `json:"resource"`
	Action        string          `json:"action"`
	Context       RequestContext  `json:"context"`
	PolicyBundle  PolicyBundleRef `json:"policy_bundle"`
	Limits        ExecutionLimits `json:"limits"`
}

type DecisionReason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Obligation struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

type Decision struct {
	Subject      string           `json:"subject"`
	Resource     string           `json:"resource"`
	Action       string           `json:"action"`
	PolicyDigest string           `json:"policy_digest"`
	Allow        bool             `json:"allow"`
	Reasons      []DecisionReason `json:"reasons"`
	Obligations  []Obligation     `json:"obligations"`
}

type TypedError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	Field     string `json:"field,omitempty"`
}

type Metrics struct {
	ElapsedMS      float64 `json:"elapsed_ms"`
	PayloadBytes   int     `json:"payload_bytes"`
	WithinDeadline bool    `json:"within_deadline"`
}

type Result struct {
	SchemaVersion string      `json:"schema_version"`
	RequestID     string      `json:"request_id"`
	Status        string      `json:"status"`
	InputDigest   string      `json:"input_digest"`
	EngineVersion string      `json:"engine_version"`
	Decision      Decision    `json:"decision"`
	Error         *TypedError `json:"error"`
	Metrics       Metrics     `json:"metrics"`
	Warnings      []string    `json:"warnings"`
}

func CalculateDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func ValidateAndEvaluate(parentCtx context.Context, raw []byte) (int, Result) {
	start := time.Now()
	payloadBytes := len(raw)

	digest := CalculateDigest(raw)

	if payloadBytes > MaxAllowedPayload {
		return http.StatusRequestEntityTooLarge, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     "unknown",
			Status:        "failed",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Allow:       false,
				Reasons:     []DecisionReason{{Code: "payload_too_large", Message: "Payload exceeds 64 KiB limit"}},
				Obligations: []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrPayloadTooLarge,
				Message:   fmt.Sprintf("Payload size %d exceeds maximum allowed %d bytes", payloadBytes, MaxAllowedPayload),
				Retryable: false,
			},
			Metrics: Metrics{
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{},
		}
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return http.StatusBadRequest, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     "unknown",
			Status:        "failed",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Allow:       false,
				Reasons:     []DecisionReason{{Code: "invalid_json", Message: err.Error()}},
				Obligations: []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrInvalidJSON,
				Message:   "Input must be valid JSON: " + err.Error(),
				Retryable: false,
			},
			Metrics: Metrics{
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{},
		}
	}

	ver, _ := rawMap["schema_version"].(string)
	if ver != CurrentSchemaVersion {
		return http.StatusBadRequest, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     fmt.Sprintf("%v", rawMap["request_id"]),
			Status:        "failed",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Allow:       false,
				Reasons:     []DecisionReason{{Code: "unsupported_version", Message: fmt.Sprintf("Unsupported schema_version '%s'", ver)}},
				Obligations: []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrUnsupportedVersion,
				Message:   fmt.Sprintf("Input schema_version '%s' is not supported; expected '%s'", ver, CurrentSchemaVersion),
				Retryable: false,
				Field:     "schema_version",
			},
			Metrics: Metrics{
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{},
		}
	}

	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return http.StatusUnprocessableEntity, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     "unknown",
			Status:        "failed",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Allow:       false,
				Reasons:     []DecisionReason{{Code: "unmarshal_failed", Message: err.Error()}},
				Obligations: []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrSchemaValidationFailed,
				Message:   "Schema parsing failed: " + err.Error(),
				Retryable: false,
			},
			Metrics: Metrics{
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{},
		}
	}

	// Validate required fields and constraints
	if !requestIDRegex.MatchString(in.RequestID) {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "request_id", "must match ^[a-zA-Z0-9._:-]{1,128}$")
	}
	if in.Subject.ID == "" {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "subject.id", "is required and cannot be empty")
	}
	if in.Subject.Issuer == "" {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "subject.issuer", "is required and cannot be empty")
	}
	if in.Resource.ID == "" {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "resource.id", "is required and cannot be empty")
	}
	validResTypes := []string{"service", "dataset", "endpoint", "policy_bundle"}
	if !contains(validResTypes, in.Resource.Type) {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "resource.type", "must be one of: service, dataset, endpoint, policy_bundle")
	}
	validClasses := []string{"public", "internal", "private", "restricted"}
	if !contains(validClasses, in.Resource.Classification) {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "resource.classification", "must be one of: public, internal, private, restricted")
	}
	validActions := []string{"read", "write", "execute", "admin", "simulate"}
	if !contains(validActions, in.Action) {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "action", "must be one of: read, write, execute, admin, simulate")
	}
	if !digestRegex.MatchString(in.PolicyBundle.Digest) {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "policy_bundle.digest", "must match ^sha256:[a-f0-9]{64}$")
	}
	if in.PolicyBundle.Revision < 1 {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "policy_bundle.revision", "must be >= 1")
	}
	if in.Limits.MaxPayloadBytes <= 0 || in.Limits.MaxPayloadBytes > MaxAllowedPayload {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "limits.max_payload_bytes", fmt.Sprintf("must be between 1 and %d", MaxAllowedPayload))
	}
	if in.Limits.DeadlineMS <= 0 || in.Limits.DeadlineMS > MaxAllowedDeadlineMS {
		return http.StatusUnprocessableEntity, schemaError(in, digest, start, payloadBytes, "limits.deadline_ms", fmt.Sprintf("must be between 1 and %d", MaxAllowedDeadlineMS))
	}

	// Payload exceeds client-specified limit
	if payloadBytes > in.Limits.MaxPayloadBytes {
		return http.StatusRequestEntityTooLarge, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     in.RequestID,
			Status:        "failed",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Subject:      in.Subject.ID,
				Resource:     in.Resource.ID,
				Action:       in.Action,
				PolicyDigest: in.PolicyBundle.Digest,
				Allow:        false,
				Reasons:      []DecisionReason{{Code: "payload_limit_exceeded", Message: fmt.Sprintf("Payload size %d exceeds configured limit %d", payloadBytes, in.Limits.MaxPayloadBytes)}},
				Obligations:  []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrPayloadTooLarge,
				Message:   fmt.Sprintf("Payload size %d exceeds limit of %d bytes", payloadBytes, in.Limits.MaxPayloadBytes),
				Retryable: false,
				Field:     "limits.max_payload_bytes",
			},
			Metrics: Metrics{
				ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{},
		}
	}

	// Establish deadline and cancellation context
	deadlineDuration := time.Duration(in.Limits.DeadlineMS) * time.Millisecond
	evalCtx, cancel := context.WithTimeout(parentCtx, deadlineDuration)
	defer cancel()

	// Handle simulated cancellation if cancel_after_ms is specified
	if in.Limits.CancelAfterMS > 0 {
		cancelDuration := time.Duration(in.Limits.CancelAfterMS) * time.Millisecond
		if cancelDuration < deadlineDuration {
			// Trigger early cancellation
			time.Sleep(cancelDuration)
			cancel()
		}
	}

	select {
	case <-evalCtx.Done():
		err := evalCtx.Err()
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0
		if errors.Is(err, context.Canceled) {
			return 499, Result{
				SchemaVersion: CurrentSchemaVersion,
				RequestID:     in.RequestID,
				Status:        "cancelled",
				InputDigest:   digest,
				EngineVersion: EngineVersion,
				Decision: Decision{
					Subject:      in.Subject.ID,
					Resource:     in.Resource.ID,
					Action:       in.Action,
					PolicyDigest: in.PolicyBundle.Digest,
					Allow:        false,
					Reasons:      []DecisionReason{{Code: "request_cancelled", Message: "Request evaluation context was cancelled"}},
					Obligations:  []Obligation{},
				},
				Error: &TypedError{
					Code:      ErrRequestCancelled,
					Message:   "Evaluation was cancelled before decision completion",
					Retryable: true,
				},
				Metrics: Metrics{
					ElapsedMS:      elapsed,
					PayloadBytes:   payloadBytes,
					WithinDeadline: elapsed <= float64(in.Limits.DeadlineMS),
				},
				Warnings: []string{},
			}
		}
		// Context deadline exceeded
		return http.StatusGatewayTimeout, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     in.RequestID,
			Status:        "failed",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Subject:      in.Subject.ID,
				Resource:     in.Resource.ID,
				Action:       in.Action,
				PolicyDigest: in.PolicyBundle.Digest,
				Allow:        false,
				Reasons:      []DecisionReason{{Code: "deadline_exceeded", Message: fmt.Sprintf("Evaluation deadline of %dms exceeded", in.Limits.DeadlineMS)}},
				Obligations:  []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrDecisionTimeout,
				Message:   fmt.Sprintf("Decision deadline of %dms exceeded", in.Limits.DeadlineMS),
				Retryable: true,
			},
			Metrics: Metrics{
				ElapsedMS:      elapsed,
				PayloadBytes:   payloadBytes,
				WithinDeadline: false,
			},
			Warnings: []string{},
		}
	default:
	}

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0

	// 1. Provider availability fail-closed
	if in.PolicyBundle.ProviderState == "unavailable" {
		return http.StatusOK, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     in.RequestID,
			Status:        "complete",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Subject:      in.Subject.ID,
				Resource:     in.Resource.ID,
				Action:       in.Action,
				PolicyDigest: in.PolicyBundle.Digest,
				Allow:        false,
				Reasons:      []DecisionReason{{Code: "provider_unavailable", Message: "Required policy evaluation provider is unavailable"}},
				Obligations:  []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrProviderUnavailable,
				Message:   "Policy evaluation provider is unavailable; failing closed",
				Retryable: true,
			},
			Metrics: Metrics{
				ElapsedMS:      elapsed,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{"provider_outage_detected"},
		}
	}

	// 2. Unsigned or stale bundle fail-closed
	if !in.PolicyBundle.SignatureVerified {
		return http.StatusOK, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     in.RequestID,
			Status:        "complete",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Subject:      in.Subject.ID,
				Resource:     in.Resource.ID,
				Action:       in.Action,
				PolicyDigest: in.PolicyBundle.Digest,
				Allow:        false,
				Reasons:      []DecisionReason{{Code: "unsigned_bundle", Message: "Policy bundle cryptographic signature verification failed"}},
				Obligations:  []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrStaleOrUnsignedBundle,
				Message:   "Policy bundle signature is unverified or invalid",
				Retryable: false,
			},
			Metrics: Metrics{
				ElapsedMS:      elapsed,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{"untrusted_policy_bundle"},
		}
	}

	// 3. Unauthenticated access to private/restricted resource fail-closed
	isPrivate := in.Resource.Classification == "private" || in.Resource.Classification == "restricted" || strings.Contains(in.Resource.ID, "private")
	if isPrivate && !in.Subject.Authenticated {
		return http.StatusOK, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     in.RequestID,
			Status:        "complete",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Subject:      in.Subject.ID,
				Resource:     in.Resource.ID,
				Action:       in.Action,
				PolicyDigest: in.PolicyBundle.Digest,
				Allow:        false,
				Reasons:      []DecisionReason{{Code: "unauthenticated_identity", Message: "Private resources require authenticated identity"}},
				Obligations:  []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrUnauthenticatedIdentity,
				Message:   "Subject is unauthenticated; private resource access denied",
				Retryable: false,
			},
			Metrics: Metrics{
				ElapsedMS:      elapsed,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{"unauthenticated_private_access_attempt"},
		}
	}

	// 4. Role-based authorization evaluation
	hasRole := contains(in.Subject.Roles, "operator") || contains(in.Subject.Roles, "admin")
	if !hasRole {
		return http.StatusOK, Result{
			SchemaVersion: CurrentSchemaVersion,
			RequestID:     in.RequestID,
			Status:        "complete",
			InputDigest:   digest,
			EngineVersion: EngineVersion,
			Decision: Decision{
				Subject:      in.Subject.ID,
				Resource:     in.Resource.ID,
				Action:       in.Action,
				PolicyDigest: in.PolicyBundle.Digest,
				Allow:        false,
				Reasons:      []DecisionReason{{Code: "role_denied", Message: "Subject roles insufficient for requested resource and action"}},
				Obligations:  []Obligation{},
			},
			Error: &TypedError{
				Code:      ErrPrivateResourceFailClosed,
				Message:   "Subject lacks required role for resource access",
				Retryable: false,
			},
			Metrics: Metrics{
				ElapsedMS:      elapsed,
				PayloadBytes:   payloadBytes,
				WithinDeadline: true,
			},
			Warnings: []string{},
		}
	}

	// 5. Positive authorization decision
	return http.StatusOK, Result{
		SchemaVersion: CurrentSchemaVersion,
		RequestID:     in.RequestID,
		Status:        "complete",
		InputDigest:   digest,
		EngineVersion: EngineVersion,
		Decision: Decision{
			Subject:      in.Subject.ID,
			Resource:     in.Resource.ID,
			Action:       in.Action,
			PolicyDigest: in.PolicyBundle.Digest,
			Allow:        true,
			Reasons: []DecisionReason{
				{Code: "policy_allow_role_operator", Message: "Policy granted operator access to requested resource"},
			},
			Obligations: []Obligation{
				{
					ID:   "audit_log_decision",
					Type: "audit",
					Parameters: map[string]interface{}{
						"event":       "authorization_granted",
						"recorded_at": time.Now().UTC().Format(time.RFC3339),
					},
				},
			},
		},
		Error: nil,
		Metrics: Metrics{
			ElapsedMS:      elapsed,
			PayloadBytes:   payloadBytes,
			WithinDeadline: true,
		},
		Warnings: []string{},
	}
}

func schemaError(in Input, digest string, start time.Time, payloadBytes int, field, message string) Result {
	return Result{
		SchemaVersion: CurrentSchemaVersion,
		RequestID:     in.RequestID,
		Status:        "failed",
		InputDigest:   digest,
		EngineVersion: EngineVersion,
		Decision: Decision{
			Allow:       false,
			Reasons:     []DecisionReason{{Code: "schema_validation_failed", Message: fmt.Sprintf("Field '%s' %s", field, message)}},
			Obligations: []Obligation{},
		},
		Error: &TypedError{
			Code:      ErrSchemaValidationFailed,
			Message:   fmt.Sprintf("Schema validation failed: field '%s' %s", field, message),
			Retryable: false,
			Field:     field,
		},
		Metrics: Metrics{
			ElapsedMS:      float64(time.Since(start).Microseconds()) / 1000.0,
			PayloadBytes:   payloadBytes,
			WithinDeadline: true,
		},
		Warnings: []string{},
	}
}
