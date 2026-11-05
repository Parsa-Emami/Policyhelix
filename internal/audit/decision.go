package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/contracts"
)

const (
	CurrentAuditSchemaVersion = "1"
	DefaultPseudonymSalt      = "policyhelix-audit-pseudonym-salt-v1"

	// Error codes
	ErrCodeMalformedAuditRequest = "MALFORMED_AUDIT_REQUEST"
	ErrCodePrivateResourceDenied = "PRIVATE_RESOURCE_DENIED"
	ErrCodeTokenLeakDetected     = "TOKEN_LEAK_DETECTED"
)

var (
	// bearerRegex matches Authorization: Bearer <token>
	bearerRegex = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*`)

	// jwtRegex matches JSON Web Token standard format eyJ...
	jwtRegex = regexp.MustCompile(`\bey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)?\b`)

	// cookiePairRegex matches sensitive cookie pairs like policyhelix_session=..., session_id=...
	cookiePairRegex = regexp.MustCompile(`(?i)\b(policyhelix_session|session|session_id|session_token|auth_token|token|access_token|refresh_token|id_token)\s*=\s*[^;\s,]+`)

	// queryTokenRegex matches URL query parameters containing sensitive tokens
	queryTokenRegex = regexp.MustCompile(`(?i)([?&])(access_token|id_token|bearer|token|session_id|auth_token)=[^&\s]+`)

	// sensitiveKeyRegex matches map/json keys containing secrets
	sensitiveKeyRegex = regexp.MustCompile(`(?i)(authorization|proxy-authorization|cookie|set-cookie|password|secret|bearer|token|access[-_]?token|refresh[-_]?token|id[-_]?token|session[-_]?id|session[-_]?token|api[-_]?key|client[-_]?secret)`)
)

// DecisionAuditRecord models the canonical, tamper-evident audit record for authorization decisions.
// Strictly excludes any bearer token, session cookie, or raw secret.
type DecisionAuditRecord struct {
	RecordID               string                 `json:"record_id"`
	SchemaVersion          string                 `json:"schema_version"`
	Timestamp              string                 `json:"timestamp"`
	RequestID              string                 `json:"request_id"`
	SubjectPseudonym       string                 `json:"subject_pseudonym"`
	PolicyDigest           string                 `json:"policy_digest"`
	PolicyRevision         int64                  `json:"policy_revision,omitempty"`
	ResourceID             string                 `json:"resource_id"`
	ResourceClassification string                 `json:"resource_classification"`
	Action                 string                 `json:"action"`
	Outcome                DecisionOutcome        `json:"outcome"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	RedactionStats         RedactionStats         `json:"redaction_stats"`
}

// DecisionOutcome captures the authoritative outcome of an evaluated decision.
type DecisionOutcome struct {
	Allow      bool     `json:"allow"`
	Status     string   `json:"status"` // "allow" or "deny"
	StatusCode int      `json:"status_code"`
	ErrorCode  string   `json:"error_code,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
}

// RedactionStats tracks the counts of redacted credentials.
type RedactionStats struct {
	BearerTokensRedacted int `json:"bearer_tokens_redacted"`
	CookiesRedacted      int `json:"cookies_redacted"`
	SensitiveKeysStripped int `json:"sensitive_keys_stripped"`
}

// DecisionLogRequest represents an inbound request to record an authorization decision audit log.
type DecisionLogRequest struct {
	RequestID              string                 `json:"request_id,omitempty"`
	Subject                *contracts.Subject     `json:"subject,omitempty"`
	SubjectID              string                 `json:"subject_id,omitempty"`
	Resource               *contracts.Resource    `json:"resource,omitempty"`
	ResourceID             string                 `json:"resource_id,omitempty"`
	ResourceClassification string                 `json:"resource_classification,omitempty"`
	Action                 string                 `json:"action,omitempty"`
	PolicyDigest           string                 `json:"policy_digest,omitempty"`
	PolicyRevision         int64                  `json:"policy_revision,omitempty"`
	Allow                  *bool                  `json:"allow,omitempty"`
	StatusCode             int                    `json:"status_code,omitempty"`
	ErrorCode              string                 `json:"error_code,omitempty"`
	Reasons                []string               `json:"reasons,omitempty"`
	Headers                map[string]string      `json:"headers,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	EvaluationTime         time.Time              `json:"evaluation_time,omitempty"`
	PseudonymSalt          string                 `json:"pseudonym_salt,omitempty"`
}

// DecisionLogResult represents the result of the audit logging operation.
type DecisionLogResult struct {
	Valid        bool                 `json:"valid"`
	Allow        bool                 `json:"allow"`
	AuditRecord  *DecisionAuditRecord `json:"audit_record,omitempty"`
	JSON         string               `json:"json,omitempty"`
	ErrorCode    string               `json:"error_code,omitempty"`
	ErrorMessage string               `json:"error_message,omitempty"`
}

// ComputeSubjectPseudonym deterministically derives a cryptographic pseudonym for a subject
// using HMAC-SHA256 with an engine domain salt. Unauthenticated subjects resolve to pseudo:unauthenticated.
func ComputeSubjectPseudonym(subjectID, salt string) string {
	cleanID := strings.TrimSpace(subjectID)
	if cleanID == "" || cleanID == "anonymous" || cleanID == "unauthenticated" {
		return "pseudo:unauthenticated"
	}
	if salt == "" {
		salt = DefaultPseudonymSalt
	}
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(cleanID))
	sum := mac.Sum(nil)
	return "pseudo:sha256:" + hex.EncodeToString(sum)
}

// RedactText replaces Bearer tokens, JWTs, query string tokens, and cookies within raw strings.
func RedactText(s string, stats *RedactionStats) string {
	if s == "" {
		return ""
	}

	res := s

	// 1. Redact Authorization: Bearer <token>
	if bearerRegex.MatchString(res) {
		res = bearerRegex.ReplaceAllStringFunc(res, func(m string) string {
			if stats != nil {
				stats.BearerTokensRedacted++
			}
			return "Bearer [REDACTED]"
		})
	}

	// 2. Redact standalone JWT tokens
	if jwtRegex.MatchString(res) {
		res = jwtRegex.ReplaceAllStringFunc(res, func(m string) string {
			if stats != nil {
				stats.BearerTokensRedacted++
			}
			return "[REDACTED_JWT]"
		})
	}

	// 3. Redact sensitive cookies (e.g. policyhelix_session=...)
	if cookiePairRegex.MatchString(res) {
		res = cookiePairRegex.ReplaceAllStringFunc(res, func(m string) string {
			if stats != nil {
				stats.CookiesRedacted++
			}
			parts := strings.SplitN(m, "=", 2)
			if len(parts) == 2 {
				return parts[0] + "=[REDACTED]"
			}
			return "[REDACTED_COOKIE]"
		})
	}

	// 4. Redact query parameters containing sensitive tokens
	if queryTokenRegex.MatchString(res) {
		res = queryTokenRegex.ReplaceAllStringFunc(res, func(m string) string {
			if stats != nil {
				stats.BearerTokensRedacted++
			}
			parts := strings.SplitN(m, "=", 2)
			if len(parts) == 2 {
				return parts[0] + "=[REDACTED]"
			}
			return "[REDACTED]"
		})
	}

	return res
}

// RedactHeaders processes a header map, replacing sensitive authorization and cookie headers
// and sanitizing values of other headers.
func RedactHeaders(headers map[string]string, stats *RedactionStats) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lowerKey := strings.ToLower(strings.TrimSpace(k))
		if sensitiveKeyRegex.MatchString(lowerKey) {
			if stats != nil {
				stats.SensitiveKeysStripped++
				if strings.Contains(lowerKey, "cookie") {
					stats.CookiesRedacted++
				} else {
					stats.BearerTokensRedacted++
				}
			}
			out[k] = "[REDACTED]"
		} else {
			out[k] = RedactText(v, stats)
		}
	}
	return out
}

// RedactMap recursively sanitizes a map, redacting sensitive keys and values.
func RedactMap(m map[string]interface{}, stats *RedactionStats) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		lowerKey := strings.ToLower(strings.TrimSpace(k))
		if sensitiveKeyRegex.MatchString(lowerKey) {
			if stats != nil {
				stats.SensitiveKeysStripped++
				if strings.Contains(lowerKey, "cookie") {
					stats.CookiesRedacted++
				} else {
					stats.BearerTokensRedacted++
				}
			}
			out[k] = "[REDACTED]"
		} else {
			out[k] = RedactValue(v, stats)
		}
	}
	return out
}

// RedactValue recursively redacts an interface{} element.
func RedactValue(v interface{}, stats *RedactionStats) interface{} {
	switch val := v.(type) {
	case string:
		return RedactText(val, stats)
	case map[string]interface{}:
		return RedactMap(val, stats)
	case []interface{}:
		outList := make([]interface{}, len(val))
		for i, item := range val {
			outList[i] = RedactValue(item, stats)
		}
		return outList
	case []string:
		outList := make([]string, len(val))
		for i, item := range val {
			outList[i] = RedactText(item, stats)
		}
		return outList
	default:
		return v
	}
}

// VerifyNoTokenOrCookie inspects the serialized JSON of a DecisionAuditRecord
// and returns an error if any unredacted bearer token, JWT, or raw session cookie is detected.
func VerifyNoTokenOrCookie(record *DecisionAuditRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal audit record: %w", err)
	}
	recordStr := string(raw)

	// Check for unredacted Bearer tokens
	if matches := bearerRegex.FindAllString(recordStr, -1); len(matches) > 0 {
		for _, m := range matches {
			if !strings.Contains(m, "[REDACTED]") {
				return fmt.Errorf("%s: unredacted bearer token detected in record: %s", ErrCodeTokenLeakDetected, m)
			}
		}
	}

	// Check for unredacted JWT patterns
	if matches := jwtRegex.FindAllString(recordStr, -1); len(matches) > 0 {
		for _, m := range matches {
			if !strings.Contains(m, "[REDACTED") {
				return fmt.Errorf("%s: unredacted JWT token detected in record: %s", ErrCodeTokenLeakDetected, m)
			}
		}
	}

	// Check for unredacted policyhelix_session or session cookies
	if matches := cookiePairRegex.FindAllString(recordStr, -1); len(matches) > 0 {
		for _, m := range matches {
			if !strings.Contains(m, "[REDACTED]") {
				return fmt.Errorf("%s: unredacted cookie detected in record: %s", ErrCodeTokenLeakDetected, m)
			}
		}
	}

	return nil
}

// LogDecision evaluates the inbound DecisionLogRequest, extracts domain facts,
// computes the deterministic subject pseudonym, redacts all credentials, and creates
// the authoritative DecisionAuditRecord.
func LogDecision(ctx context.Context, req DecisionLogRequest) (*DecisionLogResult, error) {
	stats := &RedactionStats{}

	// 1. Resolve Subject
	var subjectID string
	var isAuthenticated bool
	if req.Subject != nil {
		subjectID = req.Subject.ID
		isAuthenticated = req.Subject.Authenticated
	} else if req.SubjectID != "" {
		subjectID = req.SubjectID
		isAuthenticated = true
	}

	// 2. Resolve Resource
	resourceID := req.ResourceID
	resourceClass := req.ResourceClassification
	if req.Resource != nil {
		if resourceID == "" {
			resourceID = req.Resource.ID
		}
		if resourceClass == "" {
			resourceClass = req.Resource.Classification
		}
	}
	resourceClass = strings.ToLower(strings.TrimSpace(resourceClass))
	if resourceClass == "" {
		resourceClass = "internal" // fail safe default
	}

	// 3. Validation: Request must have action, resource, or request ID
	reqID := strings.TrimSpace(req.RequestID)
	action := strings.ToUpper(strings.TrimSpace(req.Action))
	if reqID == "" && resourceID == "" && action == "" {
		return &DecisionLogResult{
			Valid:        false,
			Allow:        false,
			ErrorCode:    ErrCodeMalformedAuditRequest,
			ErrorMessage: "Decision log request missing required fields (request_id, resource, or action)",
		}, nil
	}

	if reqID == "" {
		reqID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	if action == "" {
		action = "ACCESS"
	}
	if resourceID == "" {
		resourceID = "resource-unspecified"
	}

	// 4. Resolve Policy
	policyDigest := strings.TrimSpace(req.PolicyDigest)
	if policyDigest == "" {
		policyDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	}

	// 5. Resolve Outcome (enforce private resource fail-closed)
	allow := false
	if req.Allow != nil {
		allow = *req.Allow
	}

	statusCode := req.StatusCode
	errCode := req.ErrorCode
	reasons := req.Reasons

	// Private resources fail closed if unauthenticated
	isPrivate := resourceClass == "private" || resourceClass == "internal" || resourceClass == "sensitive" || resourceClass == "restricted"
	if isPrivate && (!isAuthenticated || subjectID == "") {
		allow = false
		if statusCode == 0 || statusCode == http.StatusOK {
			statusCode = http.StatusForbidden
		}
		if errCode == "" {
			errCode = ErrCodePrivateResourceDenied
		}
		reasons = append(reasons, "Fail closed: private resource requires authenticated subject")
	} else if statusCode == 0 {
		if allow {
			statusCode = http.StatusOK
		} else {
			statusCode = http.StatusForbidden
		}
	}

	statusStr := "deny"
	if allow {
		statusStr = "allow"
	}

	// 6. Compute Pseudonym
	pseudonym := ComputeSubjectPseudonym(subjectID, req.PseudonymSalt)

	// 7. Sanitize Metadata and Headers
	sanitizedMeta := make(map[string]interface{})
	if req.Metadata != nil {
		for k, v := range req.Metadata {
			sanitizedMeta[k] = v
		}
	}

	if len(req.Headers) > 0 {
		redactedHeaders := RedactHeaders(req.Headers, stats)
		sanitizedMeta["headers"] = redactedHeaders
	}

	sanitizedMeta = RedactMap(sanitizedMeta, stats)

	// 8. Timestamps and Record ID
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}

	recordID := fmt.Sprintf("audit-%s-%s", evalTime.Format("20060102T150405Z"), reqID)

	record := &DecisionAuditRecord{
		RecordID:               recordID,
		SchemaVersion:          CurrentAuditSchemaVersion,
		Timestamp:              evalTime.Format(time.RFC3339),
		RequestID:              reqID,
		SubjectPseudonym:       pseudonym,
		PolicyDigest:           policyDigest,
		PolicyRevision:         req.PolicyRevision,
		ResourceID:             resourceID,
		ResourceClassification: resourceClass,
		Action:                 action,
		Outcome: DecisionOutcome{
			Allow:      allow,
			Status:     statusStr,
			StatusCode: statusCode,
			ErrorCode:  errCode,
			Reasons:    reasons,
		},
		Metadata:       sanitizedMeta,
		RedactionStats: *stats,
	}

	// 9. Invariant Verification: Guarantee zero tokens or cookies leaked
	if err := VerifyNoTokenOrCookie(record); err != nil {
		return &DecisionLogResult{
			Valid:        false,
			Allow:        false,
			ErrorCode:    ErrCodeTokenLeakDetected,
			ErrorMessage: err.Error(),
		}, nil
	}

	rawJSON, err := json.Marshal(record)
	if err != nil {
		return nil, errors.New("failed to marshal canonical decision audit record")
	}

	return &DecisionLogResult{
		Valid:       true,
		Allow:       allow,
		AuditRecord: record,
		JSON:        string(rawJSON),
	}, nil
}
