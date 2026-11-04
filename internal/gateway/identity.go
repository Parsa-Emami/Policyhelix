package gateway

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/contracts"
)

// Invariant error codes matching PolicyHelix security contracts.
const (
	ErrCodeForgedHeader         = "FORGED_HEADER_REJECTED"
	ErrCodeUnauthenticated      = "UNAUTHENTICATED"
	ErrCodePrivateResource      = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrCodeRevokedSessionDenied = "REVOKED_SESSION_DENIED"
	ErrCodeExpiredSession       = "EXPIRED_SESSION"
	ErrCodeProviderUnavailable  = "PROVIDER_UNAVAILABLE"
	ErrCodeUnrelatedOwnerScope  = "UNRELATED_OWNER_SCOPE"
	ErrCodeMalformedHeader      = "MALFORMED_HEADER"
	ErrCodeInvalidSubject       = "INVALID_SUBJECT"
	ErrCodeWidenedPermission    = "WIDENED_PERMISSION_DENIED"
)

// Downstream canonical header names injected strictly by the gateway for verified subjects.
const (
	HeaderPolicyHelixSubject       = "X-PolicyHelix-Subject"
	HeaderPolicyHelixIssuer        = "X-PolicyHelix-Issuer"
	HeaderPolicyHelixEmail         = "X-PolicyHelix-Email"
	HeaderPolicyHelixRoles         = "X-PolicyHelix-Roles"
	HeaderPolicyHelixSessionEpoch  = "X-PolicyHelix-Session-Epoch"
	HeaderPolicyHelixAuthenticated = "X-PolicyHelix-Authenticated"
	HeaderPolicyHelixSessionID     = "X-PolicyHelix-Session-Id"
	HeaderPolicyHelixTenantID      = "X-PolicyHelix-Tenant-Id"
)

// ReservedPrefix is the namespace reserved exclusively for trusted internal gateway headers.
const ReservedPrefix = "X-PolicyHelix-"

// ProhibitedClientIdentityHeaders defines headers that untrusted clients are strictly forbidden
// from setting to prevent identity spoofing or privilege escalation.
var ProhibitedClientIdentityHeaders = []string{
	"X-User-Id",
	"X-User",
	"X-Subject",
	"X-Sub",
	"X-Email",
	"X-User-Email",
	"X-Roles",
	"X-Role",
	"X-Groups",
	"X-Group",
	"X-Tenant-Id",
	"X-Tenant",
	"X-Org-Id",
	"X-Organization",
	"X-Authenticated-User",
	"X-Authenticated",
	"X-Auth-User",
	"X-Session-Id",
	"X-Session-Epoch",
	"X-Issuer",
	"X-Auth-Issuer",
	"X-Scopes",
	"X-Scope",
	"X-Consumer-Custom-Id",
}

var (
	roleRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
)

// NormalizeIdentityRequest represents an inbound gateway request requiring identity stripping
// and subject context normalization.
type NormalizeIdentityRequest struct {
	RequestID                string            `json:"request_id,omitempty"`
	Headers                  map[string]string `json:"headers"`
	SessionID                string            `json:"session_id,omitempty"`
	ClientIP                 string            `json:"client_ip,omitempty"`
	UserAgent                string            `json:"user_agent,omitempty"`
	UntrustedHeadersStripped bool              `json:"untrusted_headers_stripped"`
	ForgedHeaders            map[string]string `json:"forged_headers,omitempty"`
	ProviderUnavailable      bool              `json:"provider_unavailable,omitempty"`
	ProviderState            string            `json:"provider_state,omitempty"`
	ResourceClassification   string            `json:"resource_classification,omitempty"`
	TargetOwnerScope         string            `json:"target_owner_scope,omitempty"`
	ObjectScope              string            `json:"object_scope,omitempty"`
	RequestedPath            string            `json:"requested_path,omitempty"`
	RequestedProvider        string            `json:"requested_provider,omitempty"`
	ExpectedIssuer           string            `json:"expected_issuer,omitempty"`
	EvaluationTime           time.Time         `json:"evaluation_time,omitempty"`
}

// NormalizedSubjectContext represents the verified, canonical subject context constructed
// strictly after client identity headers have been stripped.
type NormalizedSubjectContext struct {
	Subject                   contracts.Subject `json:"subject"`
	TenantID                  string            `json:"tenant_id,omitempty"`
	Scopes                    []string          `json:"scopes,omitempty"`
	AuthMethod                string            `json:"auth_method"`
	SessionID                 string            `json:"session_id,omitempty"`
	StrippedHeaders           []string          `json:"stripped_headers"`
	DownstreamInjectedHeaders map[string]string `json:"downstream_injected_headers"`
}

// NormalizeIdentityResult is the authoritative outcome of identity normalization.
type NormalizeIdentityResult struct {
	Valid                     bool                      `json:"valid"`
	Allow                     bool                      `json:"allow"`
	ErrorCode                 string                    `json:"error_code,omitempty"`
	ErrorMessage              string                    `json:"error_message,omitempty"`
	Subject                   *contracts.Subject        `json:"subject,omitempty"`
	NormalizedContext         *NormalizedSubjectContext `json:"normalized_context,omitempty"`
	StrippedHeaders           []string                  `json:"stripped_headers"`
	DownstreamInjectedHeaders map[string]string         `json:"downstream_injected_headers,omitempty"`
}

// IsProhibitedIdentityHeader returns true if the header name matches any known prohibited identity header
// or begins with the reserved internal gateway prefix (case-insensitively).
func IsProhibitedIdentityHeader(headerKey string) bool {
	canonical := http.CanonicalHeaderKey(strings.TrimSpace(headerKey))
	if strings.HasPrefix(strings.ToLower(canonical), strings.ToLower(ReservedPrefix)) {
		return true
	}
	for _, prohibited := range ProhibitedClientIdentityHeaders {
		if strings.EqualFold(canonical, prohibited) {
			return true
		}
	}
	return false
}

// StripUntrustedHeaders removes all prohibited client identity headers and reserved gateway headers
// from the provided HTTP headers map, returning a sanitized copy and the list of stripped header keys.
func StripUntrustedHeaders(headers map[string]string) (map[string]string, []string) {
	sanitized := make(map[string]string, len(headers))
	stripped := make([]string, 0)

	for k, v := range headers {
		if IsProhibitedIdentityHeader(k) {
			stripped = append(stripped, k)
		} else {
			sanitized[k] = v
		}
	}
	sort.Strings(stripped)
	return sanitized, stripped
}

// StripHTTPHeader performs in-place header stripping on an http.Header object,
// returning the list of stripped header names.
func StripHTTPHeader(h http.Header) []string {
	stripped := make([]string, 0)
	for k := range h {
		if IsProhibitedIdentityHeader(k) {
			stripped = append(stripped, k)
			h.Del(k)
		}
	}
	sort.Strings(stripped)
	return stripped
}

// NormalizeSubjectContext validates the inbound request, enforces header stripping invariants,
// authenticates through server-held sessions/revocations, and builds the trusted subject context.
func NormalizeSubjectContext(
	ctx context.Context,
	req NormalizeIdentityRequest,
	sessStore auth.SessionStore,
	revStore auth.RevocationStore,
) (*NormalizeIdentityResult, error) {
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}

	// 1. Check for malformed or oversized header inputs
	for k, v := range req.Headers {
		if len(k) > 256 || len(v) > 8192 || strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
			return &NormalizeIdentityResult{
				Valid:        false,
				Allow:        false,
				ErrorCode:    ErrCodeMalformedHeader,
				ErrorMessage: fmt.Sprintf("Malformed or oversized header '%s'", k),
			}, nil
		}
	}

	// 2. Identify prohibited identity headers in incoming headers
	sanitizedHeaders, strippedHeaders := StripUntrustedHeaders(req.Headers)

	// Combine explicitly declared forged headers with stripped prohibited headers
	forgedDetected := len(strippedHeaders) > 0 || len(req.ForgedHeaders) > 0

	// Invariant: If untrusted headers were NOT stripped by the outer edge adapter, or if explicit forged
	// headers were injected, fail closed immediately before any authentication or side effects.
	if !req.UntrustedHeadersStripped || len(req.ForgedHeaders) > 0 {
		return &NormalizeIdentityResult{
			Valid:           false,
			Allow:           false,
			ErrorCode:       ErrCodeForgedHeader,
			ErrorMessage:    "Fail closed: untrusted or forged identity headers were not stripped by the edge adapter",
			StrippedHeaders: strippedHeaders,
		}, nil
	}

	// 3. Reject when upstream identity provider is unavailable
	if req.ProviderUnavailable || strings.EqualFold(strings.TrimSpace(req.ProviderState), "unavailable") {
		return &NormalizeIdentityResult{
			Valid:           false,
			Allow:           false,
			ErrorCode:       ErrCodeProviderUnavailable,
			ErrorMessage:    "Fail closed: upstream identity provider is unavailable",
			StrippedHeaders: strippedHeaders,
		}, nil
	}

	// 4. Check for widened provider or path permissions
	if req.RequestedProvider != "" && strings.EqualFold(req.RequestedProvider, "wildcard") {
		return &NormalizeIdentityResult{
			Valid:           false,
			Allow:           false,
			ErrorCode:       ErrCodeWidenedPermission,
			ErrorMessage:    "Fail closed: widened path or wildcard provider permission is denied",
			StrippedHeaders: strippedHeaders,
		}, nil
	}

	// 5. Authentication check via SessionStore
	sessionID := strings.TrimSpace(req.SessionID)
	var session *auth.SessionRecord

	if sessionID != "" && sessStore != nil {
		rec, err := sessStore.GetSession(ctx, sessionID)
		if err != nil {
			return nil, fmt.Errorf("session store lookup error: %w", err)
		}
		if rec != nil {
			// Check expiration
			if evalTime.After(rec.ExpiresAt) {
				return &NormalizeIdentityResult{
					Valid:           false,
					Allow:           false,
					ErrorCode:       ErrCodeExpiredSession,
					ErrorMessage:    fmt.Sprintf("Session '%s' has expired at %s", sessionID, rec.ExpiresAt.Format(time.RFC3339)),
					StrippedHeaders: strippedHeaders,
				}, nil
			}

			// Check revocation
			if revStore != nil {
				// 1. Check explicit session revocation
				if sessRev, err := revStore.GetSessionRevocation(ctx, sessionID); err == nil && sessRev != nil {
					if !evalTime.Before(sessRev.RevokedAt) {
						return &NormalizeIdentityResult{
							Valid:           false,
							Allow:           false,
							ErrorCode:       ErrCodeRevokedSessionDenied,
							ErrorMessage:    fmt.Sprintf("Session '%s' was revoked (%s)", sessionID, sessRev.Reason),
							StrippedHeaders: strippedHeaders,
						}, nil
					}
				}

				// 2. Check subject-wide epoch revocation
				if subjRev, err := revStore.GetSubjectRevocation(ctx, rec.SubjectID); err == nil && subjRev != nil {
					if !evalTime.Before(subjRev.RevokedAt) && rec.SessionEpoch < subjRev.MinRequiredEpoch {
						return &NormalizeIdentityResult{
							Valid:           false,
							Allow:           false,
							ErrorCode:       ErrCodeRevokedSessionDenied,
							ErrorMessage:    fmt.Sprintf("Subject '%s' epoch is below minimum required epoch (%s)", rec.SubjectID, subjRev.Reason),
							StrippedHeaders: strippedHeaders,
						}, nil
					}
				}

				// 3. Check scope revocation
				if rec.OwnerScope != "" {
					if scopeRev, err := revStore.GetScopeRevocation(ctx, rec.OwnerScope); err == nil && scopeRev != nil {
						if !evalTime.Before(scopeRev.RevokedAt) && rec.SessionEpoch < scopeRev.MinRequiredEpoch {
							return &NormalizeIdentityResult{
								Valid:           false,
								Allow:           false,
								ErrorCode:       ErrCodeRevokedSessionDenied,
								ErrorMessage:    fmt.Sprintf("Scope '%s' was revoked (%s)", rec.OwnerScope, scopeRev.Reason),
								StrippedHeaders: strippedHeaders,
							}, nil
						}
					}
				}
			}

			// Check tenant / owner scope binding if requested
			if req.TargetOwnerScope != "" && rec.OwnerScope != "" && rec.OwnerScope != req.TargetOwnerScope {
				return &NormalizeIdentityResult{
					Valid:           false,
					Allow:           false,
					ErrorCode:       ErrCodeUnrelatedOwnerScope,
					ErrorMessage:    fmt.Sprintf("Caller scope '%s' does not match target owner scope '%s'", rec.OwnerScope, req.TargetOwnerScope),
					StrippedHeaders: strippedHeaders,
				}, nil
			}

			session = rec
		}
	}

	// 6. Handle Unauthenticated Requests
	if session == nil {
		// Private resources fail closed when unauthenticated
		if strings.EqualFold(req.ResourceClassification, "private") {
			return &NormalizeIdentityResult{
				Valid:           false,
				Allow:           false,
				ErrorCode:       ErrCodePrivateResource,
				ErrorMessage:    "Fail closed: unauthenticated request to private resource",
				StrippedHeaders: strippedHeaders,
			}, nil
		}

		// Public or unclassified resource: construct clean unauthenticated context
		anonSubject := contracts.Subject{
			ID:            "anonymous",
			Issuer:        "https://policyhelix.local/auth",
			Roles:         []string{"public"},
			Authenticated: false,
			SessionEpoch:  0,
		}

		downstreamHeaders := make(map[string]string, len(sanitizedHeaders)+5)
		for k, v := range sanitizedHeaders {
			downstreamHeaders[k] = v
		}
		downstreamHeaders[HeaderPolicyHelixSubject] = anonSubject.ID
		downstreamHeaders[HeaderPolicyHelixIssuer] = anonSubject.Issuer
		downstreamHeaders[HeaderPolicyHelixRoles] = "public"
		downstreamHeaders[HeaderPolicyHelixAuthenticated] = "false"
		downstreamHeaders[HeaderPolicyHelixSessionEpoch] = "0"

		return &NormalizeIdentityResult{
			Valid:   true,
			Allow:   true,
			Subject: &anonSubject,
			NormalizedContext: &NormalizedSubjectContext{
				Subject:                   anonSubject,
				AuthMethod:                "none",
				StrippedHeaders:           strippedHeaders,
				DownstreamInjectedHeaders: downstreamHeaders,
			},
			StrippedHeaders:           strippedHeaders,
			DownstreamInjectedHeaders: downstreamHeaders,
		}, nil
	}

	// 7. Construct Trusted Subject Context from Server-Held Session
	// Roles are deduplicated, sanitized against regex, and sorted.
	rawRoles := session.Roles
	if len(rawRoles) == 0 {
		rawRoles = []string{"user"}
	}
	roleSet := make(map[string]struct{}, len(rawRoles))
	for _, r := range rawRoles {
		r = strings.TrimSpace(r)
		if roleRegex.MatchString(r) {
			roleSet[r] = struct{}{}
		}
	}
	cleanRoles := make([]string, 0, len(roleSet))
	for r := range roleSet {
		cleanRoles = append(cleanRoles, r)
	}
	sort.Strings(cleanRoles)

	issuer := session.Issuer
	if issuer == "" {
		if req.ExpectedIssuer != "" {
			issuer = req.ExpectedIssuer
		} else {
			issuer = "https://issuer.policyhelix.local"
		}
	}

	trustedSubject := contracts.Subject{
		ID:            session.SubjectID,
		Issuer:        issuer,
		Roles:         cleanRoles,
		Authenticated: true,
		SessionEpoch:  session.SessionEpoch,
	}

	// 8. Inject Canonical Downstream Headers
	downstreamHeaders := make(map[string]string, len(sanitizedHeaders)+7)
	for k, v := range sanitizedHeaders {
		downstreamHeaders[k] = v
	}
	downstreamHeaders[HeaderPolicyHelixSubject] = trustedSubject.ID
	downstreamHeaders[HeaderPolicyHelixIssuer] = trustedSubject.Issuer
	downstreamHeaders[HeaderPolicyHelixRoles] = strings.Join(trustedSubject.Roles, ",")
	downstreamHeaders[HeaderPolicyHelixAuthenticated] = "true"
	downstreamHeaders[HeaderPolicyHelixSessionEpoch] = fmt.Sprintf("%d", trustedSubject.SessionEpoch)
	downstreamHeaders[HeaderPolicyHelixSessionID] = session.SessionID

	if session.OwnerScope != "" {
		downstreamHeaders[HeaderPolicyHelixTenantID] = session.OwnerScope
	}

	normCtx := &NormalizedSubjectContext{
		Subject:                   trustedSubject,
		TenantID:                  session.OwnerScope,
		Scopes:                    cleanRoles,
		AuthMethod:                "session",
		SessionID:                 session.SessionID,
		StrippedHeaders:           strippedHeaders,
		DownstreamInjectedHeaders: downstreamHeaders,
	}

	_ = forgedDetected

	return &NormalizeIdentityResult{
		Valid:                     true,
		Allow:                     true,
		Subject:                   &trustedSubject,
		NormalizedContext:         normCtx,
		StrippedHeaders:           strippedHeaders,
		DownstreamInjectedHeaders: downstreamHeaders,
	}, nil
}

// GatewayIdentityMiddleware wraps an http.Handler to enforce client identity header stripping
// and inject normalized subject context onto the request.
func GatewayIdentityMiddleware(sessStore auth.SessionStore, revStore auth.RevocationStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stripped := StripHTTPHeader(r.Header)

			headersMap := make(map[string]string)
			for k := range r.Header {
				headersMap[k] = r.Header.Get(k)
			}

			// Extract session cookie if present
			var sessionID string
			if c, err := r.Cookie("policyhelix_session"); err == nil && c != nil {
				sessionID = c.Value
			}

			normReq := NormalizeIdentityRequest{
				RequestID:                r.Header.Get("X-Request-Id"),
				Headers:                  headersMap,
				SessionID:                sessionID,
				ClientIP:                 r.RemoteAddr,
				UserAgent:                r.UserAgent(),
				UntrustedHeadersStripped: true,
				RequestedPath:            r.URL.Path,
			}

			result, err := NormalizeSubjectContext(r.Context(), normReq, sessStore, revStore)
			if err != nil || result == nil || !result.Valid {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				errMsg := "Forbidden: identity normalization failed"
				if result != nil && result.ErrorMessage != "" {
					errMsg = result.ErrorMessage
				}
				_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"%s","stripped_headers":%d}`, errMsg, len(stripped))))
				return
			}

			// Inject canonical downstream headers into request
			for k, v := range result.DownstreamInjectedHeaders {
				r.Header.Set(k, v)
			}

			next.ServeHTTP(w, r)
		})
	}
}
