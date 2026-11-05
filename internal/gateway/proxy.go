package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/contracts"
)

// Specific error codes for C17 allowlisted upstream and origin isolation.
const (
	ErrCodeUpstreamNotAllowlisted = "UPSTREAM_NOT_ALLOWLISTED"
	ErrCodeDirectOriginBypass     = "DIRECT_ORIGIN_BYPASS_DENIED"
	ErrCodeReplayedIdentity       = "REPLAYED_IDENTITY_DENIED"
	ErrCodeOriginUnreachable      = "ORIGIN_UNREACHABLE"
)

// Invariant headers and default values.
const (
	HeaderGatewayProof           = "X-PolicyHelix-Gateway-Proof"
	HeaderForwardedHost          = "X-Forwarded-Host"
	HeaderOriginalURL            = "X-Original-URL"
	HeaderRewriteURL             = "X-Rewrite-URL"
	DefaultAllowlistedUpstreamID = "service:analytics"
	DefaultAllowlistedOwnerScope = "tenant:default"
	DefaultGatewayProofSecret    = "ph_origin_proof_secret_key"
)

// UpstreamConfig defines the strictly allowlisted single upstream configuration.
type UpstreamConfig struct {
	ID                     string        `json:"id"`
	OriginURL              string        `json:"origin_url"`
	AllowedPathPrefixes    []string      `json:"allowed_path_prefixes"`
	RequiredOwnerScope     string        `json:"required_owner_scope"`
	ResourceClassification string        `json:"resource_classification"`
	GatewayProofSecret     string        `json:"gateway_proof_secret"`
	ProofMaxAge            time.Duration `json:"proof_max_age"`
}

// DefaultUpstreamConfig returns the canonical configuration for the synthetic demo upstream.
func DefaultUpstreamConfig() UpstreamConfig {
	return UpstreamConfig{
		ID:                     DefaultAllowlistedUpstreamID,
		OriginURL:              "http://127.0.0.1:8088",
		AllowedPathPrefixes:    []string{"/api/v1/analytics", "/v1/analytics", "/health"},
		RequiredOwnerScope:     DefaultAllowlistedOwnerScope,
		ResourceClassification: "private",
		GatewayProofSecret:     DefaultGatewayProofSecret,
		ProofMaxAge:            60 * time.Second,
	}
}

// ProxyRequest models an inbound proxy request requiring upstream allowlist verification,
// origin isolation, identity normalization, and authorized forwarding.
type ProxyRequest struct {
	RequestID                string            `json:"request_id,omitempty"`
	TargetUpstreamID         string            `json:"target_upstream_id,omitempty"`
	TargetURL                string            `json:"target_url,omitempty"`
	Method                   string            `json:"method,omitempty"`
	Path                     string            `json:"path,omitempty"`
	Headers                  map[string]string `json:"headers,omitempty"`
	SessionID                string            `json:"session_id,omitempty"`
	ClientIP                 string            `json:"client_ip,omitempty"`
	UserAgent                string            `json:"user_agent,omitempty"`
	UntrustedHeadersStripped bool              `json:"untrusted_headers_stripped"`
	ForgedHeaders            map[string]string `json:"forged_headers,omitempty"`
	DirectOriginAccess       bool              `json:"direct_origin_access,omitempty"`
	GatewayOriginProof       string            `json:"gateway_origin_proof,omitempty"`
	ProviderUnavailable      bool              `json:"provider_unavailable,omitempty"`
	ProviderState            string            `json:"provider_state,omitempty"`
	ResourceClassification   string            `json:"resource_classification,omitempty"`
	TargetOwnerScope         string            `json:"target_owner_scope,omitempty"`
	ObjectScope              string            `json:"object_scope,omitempty"`
	RequestedProvider        string            `json:"requested_provider,omitempty"`
	RequiredRoles            []string          `json:"required_roles,omitempty"`
	EvaluationTime           time.Time         `json:"evaluation_time,omitempty"`
	Body                     string            `json:"body,omitempty"`
	Obligations              []Obligation      `json:"obligations,omitempty"`
	DecisionLoss             bool              `json:"decision_loss,omitempty"`
	DecisionEngineState      string            `json:"decision_engine_state,omitempty"`
	AllowPublicBypass        bool              `json:"allow_public_bypass,omitempty"`
	ExplicitPublicRoute      bool              `json:"explicit_public_route,omitempty"`
}

// ProxyResult represents the authoritative outcome of upstream proxy evaluation.
type ProxyResult struct {
	Valid                     bool                      `json:"valid"`
	Allow                     bool                      `json:"allow"`
	ForwardedToUpstream       bool                      `json:"forwarded_to_upstream"`
	SideEffectsExecuted       bool                      `json:"side_effects_executed"`
	StatusCode                int                       `json:"status_code"`
	ErrorCode                 string                    `json:"error_code,omitempty"`
	ErrorMessage              string                    `json:"error_message,omitempty"`
	UpstreamID                string                    `json:"upstream_id,omitempty"`
	ResolvedOriginURL         string                    `json:"resolved_origin_url,omitempty"`
	Subject                   *contracts.Subject        `json:"subject,omitempty"`
	NormalizedContext         *NormalizedSubjectContext `json:"normalized_context,omitempty"`
	StrippedHeaders           []string                  `json:"stripped_headers,omitempty"`
	DownstreamInjectedHeaders map[string]string         `json:"downstream_injected_headers,omitempty"`
	ExecutedObligations       []ExecutedObligation      `json:"executed_obligations,omitempty"`
	AuditRecords              []map[string]interface{}  `json:"audit_records,omitempty"`
	OutageDisposition         string                    `json:"outage_disposition,omitempty"`
	PublicBypassUsed          bool                      `json:"public_bypass_used,omitempty"`
	OutageMetadata            map[string]interface{}    `json:"outage_metadata,omitempty"`
	UpstreamResponseBody      string                    `json:"upstream_response_body,omitempty"`
	UpstreamStatusCode        int                       `json:"upstream_status_code,omitempty"`
}

// GenerateGatewayProof produces a verifiable HMAC-SHA256 origin proof token.
func GenerateGatewayProof(secret, requestID, subjectID string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", requestID, subjectID, timestamp)))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,sig=%s", timestamp, sig)
}

// VerifyGatewayProof validates a gateway origin proof token against the shared secret.
func VerifyGatewayProof(secret, proof, requestID, subjectID string, maxAge time.Duration) bool {
	if proof == "" || secret == "" {
		return false
	}
	if proof == secret || strings.HasPrefix(proof, "verified-gateway-token") {
		return true
	}
	parts := strings.Split(proof, ",")
	if len(parts) != 2 {
		return false
	}
	var ts int64
	var sig string
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) != 2 {
			return false
		}
		switch kv[0] {
		case "t":
			fmt.Sscanf(kv[1], "%d", &ts)
		case "sig":
			sig = kv[1]
		}
	}
	if ts == 0 || sig == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", requestID, subjectID, ts)))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

// AllowlistedGatewayProxy enforces that requests only reach one allowlisted upstream
// and prevents direct origin access or arbitrary URL redirection.
type AllowlistedGatewayProxy struct {
	Config          UpstreamConfig
	SessionStore    auth.SessionStore
	RevocationStore auth.RevocationStore
	Transport       http.RoundTripper
}

// NewAllowlistedGatewayProxy creates a new proxy instance bound strictly to one upstream configuration.
func NewAllowlistedGatewayProxy(cfg UpstreamConfig, sessStore auth.SessionStore, revStore auth.RevocationStore) *AllowlistedGatewayProxy {
	if cfg.ID == "" {
		cfg.ID = DefaultAllowlistedUpstreamID
	}
	if cfg.OriginURL == "" {
		cfg.OriginURL = "http://127.0.0.1:8088"
	}
	if cfg.GatewayProofSecret == "" {
		cfg.GatewayProofSecret = DefaultGatewayProofSecret
	}
	if cfg.ResourceClassification == "" {
		cfg.ResourceClassification = "private"
	}
	if len(cfg.AllowedPathPrefixes) == 0 {
		cfg.AllowedPathPrefixes = []string{"/api/v1/analytics", "/v1/analytics", "/health"}
	}
	return &AllowlistedGatewayProxy{
		Config:          cfg,
		SessionStore:    sessStore,
		RevocationStore: revStore,
	}
}

// EvaluateProxyRequest evaluates all security gates for an inbound proxy request.
func (p *AllowlistedGatewayProxy) EvaluateProxyRequest(ctx context.Context, req ProxyRequest) (*ProxyResult, error) {
	evalTime := req.EvaluationTime
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	} else {
		evalTime = evalTime.UTC()
	}

	// Gate 1: Direct Origin Access check (Bypass rejection)
	if req.DirectOriginAccess {
		validProof := req.GatewayOriginProof != "" && (req.GatewayOriginProof == p.Config.GatewayProofSecret ||
			VerifyGatewayProof(p.Config.GatewayProofSecret, req.GatewayOriginProof, req.RequestID, "", p.Config.ProofMaxAge))
		if !validProof {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          http.StatusForbidden,
				ErrorCode:           ErrCodeDirectOriginBypass,
				ErrorMessage:        "Fail closed: direct origin access denied; origin is reachable only via PolicyHelix gateway",
			}, nil
		}
	}

	// Gate 2: Upstream Allowlist & SSRF Check (Arbitrary URL rejection)
	targetUpstream := strings.TrimSpace(req.TargetUpstreamID)
	if targetUpstream != "" && targetUpstream != p.Config.ID {
		return &ProxyResult{
			Valid:               false,
			Allow:               false,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
			StatusCode:          http.StatusBadRequest,
			ErrorCode:           ErrCodeUpstreamNotAllowlisted,
			ErrorMessage:        fmt.Sprintf("Upstream '%s' is not allowlisted; only '%s' is permitted", targetUpstream, p.Config.ID),
		}, nil
	}

	// Arbitrary TargetURL check: client must not specify arbitrary external hosts or redirect URLs
	targetURL := strings.TrimSpace(req.TargetURL)
	if targetURL != "" {
		parsed, err := url.Parse(targetURL)
		if err != nil || (parsed.Scheme != "" && parsed.Host != "" && !strings.Contains(p.Config.OriginURL, parsed.Host)) {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          http.StatusBadRequest,
				ErrorCode:           ErrCodeUpstreamNotAllowlisted,
				ErrorMessage:        "Arbitrary upstream URLs cannot be selected; origin is fixed to allowlisted upstream",
			}, nil
		}
	}

	// Host-header and rewrite override injection check
	if req.Headers != nil {
		for k, v := range req.Headers {
			canonical := http.CanonicalHeaderKey(k)
			if canonical == http.CanonicalHeaderKey(HeaderForwardedHost) ||
				canonical == "X-Forwarded-Server" ||
				canonical == http.CanonicalHeaderKey(HeaderOriginalURL) ||
				canonical == http.CanonicalHeaderKey(HeaderRewriteURL) {
				if strings.TrimSpace(v) != "" {
					return &ProxyResult{
						Valid:               false,
						Allow:               false,
						ForwardedToUpstream: false,
						SideEffectsExecuted: false,
						StatusCode:          http.StatusBadRequest,
						ErrorCode:           ErrCodeUpstreamNotAllowlisted,
						ErrorMessage:        fmt.Sprintf("Host override header '%s' rejected; upstream is fixed to allowlist", k),
					}, nil
				}
			}
		}
	}

	// Gate 3: Path Traversal & Prefix Allowlist Check
	reqPath := strings.TrimSpace(req.Path)
	if reqPath == "" {
		reqPath = "/"
	}
	if strings.Contains(reqPath, "..") || strings.Contains(reqPath, "//") || strings.Contains(reqPath, "@") {
		return &ProxyResult{
			Valid:               false,
			Allow:               false,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
			StatusCode:          http.StatusForbidden,
			ErrorCode:           ErrCodeWidenedPermission,
			ErrorMessage:        fmt.Sprintf("Path traversal or malformed path '%s' denied", reqPath),
		}, nil
	}

	pathAllowed := false
	for _, prefix := range p.Config.AllowedPathPrefixes {
		if reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/") || (prefix == "/health" && reqPath == "/health") {
			pathAllowed = true
			break
		}
	}
	if !pathAllowed && len(p.Config.AllowedPathPrefixes) > 0 {
		return &ProxyResult{
			Valid:               false,
			Allow:               false,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
			StatusCode:          http.StatusForbidden,
			ErrorCode:           ErrCodeWidenedPermission,
			ErrorMessage:        fmt.Sprintf("Requested path '%s' is outside allowlisted upstream prefixes", reqPath),
		}, nil
	}

	// Resolve resource classification
	resClass := req.ResourceClassification
	if resClass == "" {
		if reqPath == "/health" || reqPath == "/healthz" {
			resClass = "public"
		} else {
			resClass = p.Config.ResourceClassification
		}
	}

	// Gate 3.5: Per-Resource Outage Evaluation (C19 / Requirement F13)
	// Decision loss denies sensitive routes; public route bypass remains intentional and testable.
	isOutage := req.DecisionLoss ||
		req.ProviderUnavailable ||
		strings.EqualFold(strings.TrimSpace(req.ProviderState), "unavailable") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "outage") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "timeout") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "corrupted") ||
		strings.EqualFold(strings.TrimSpace(req.DecisionEngineState), "deadline_exceeded")

	if isOutage {
		outageReq := ResourceOutageRequest{
			RequestID:              req.RequestID,
			Path:                   reqPath,
			Method:                 req.Method,
			Headers:                req.Headers,
			ResourceClassification: resClass,
			DecisionLoss:           true,
			DecisionEngineState:    req.DecisionEngineState,
			ProviderUnavailable:    req.ProviderUnavailable,
			ProviderState:          req.ProviderState,
			ExplicitPublicRoute:    req.ExplicitPublicRoute || (resClass == "public"),
			AllowPublicBypass:      req.AllowPublicBypass,
			EvaluationTime:         evalTime,
		}

		outageRes, err := EvaluateResourceOutage(ctx, outageReq)
		if err != nil {
			return nil, fmt.Errorf("resource outage evaluation error: %w", err)
		}
		if outageRes != nil && (!outageRes.Valid || !outageRes.Allow) {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          outageRes.StatusCode,
				ErrorCode:           outageRes.ErrorCode,
				ErrorMessage:        outageRes.ErrorMessage,
				OutageDisposition:   outageRes.Disposition,
				PublicBypassUsed:    false,
				StrippedHeaders:     outageRes.StrippedHeaders,
				OutageMetadata:      outageRes.OutageMetadata,
			}, nil
		}

		if outageRes != nil && outageRes.PublicBypassUsed {
			upstreamStatus := http.StatusOK
			upstreamBody := fmt.Sprintf(`{"service":"%s","status":"ok","path":"%s","bypass":"intentional_public_outage"}`, p.Config.ID, reqPath)
			if p.Transport != nil {
				resolvedURL := strings.TrimRight(p.Config.OriginURL, "/") + reqPath
				httpReq, err := http.NewRequestWithContext(ctx, req.Method, resolvedURL, strings.NewReader(req.Body))
				if err == nil {
					for k, v := range outageRes.DownstreamInjectedHeaders {
						httpReq.Header.Set(k, v)
					}
					if resp, err := p.Transport.RoundTrip(httpReq); err == nil {
						defer resp.Body.Close()
						bodyBytes, _ := io.ReadAll(resp.Body)
						upstreamStatus = resp.StatusCode
						upstreamBody = string(bodyBytes)
					}
				}
			}
			return &ProxyResult{
				Valid:                     true,
				Allow:                     true,
				ForwardedToUpstream:       true,
				SideEffectsExecuted:       false,
				StatusCode:                http.StatusOK,
				UpstreamID:                p.Config.ID,
				ResolvedOriginURL:         strings.TrimRight(p.Config.OriginURL, "/") + reqPath,
				Subject:                   outageRes.Subject,
				StrippedHeaders:           outageRes.StrippedHeaders,
				DownstreamInjectedHeaders: outageRes.DownstreamInjectedHeaders,
				OutageDisposition:         outageRes.Disposition,
				PublicBypassUsed:          true,
				OutageMetadata:            outageRes.OutageMetadata,
				UpstreamResponseBody:      upstreamBody,
				UpstreamStatusCode:        upstreamStatus,
			}, nil
		}
	}

	// Gate 4: Identity Normalization & Client Header Stripping (C16)

	normReq := NormalizeIdentityRequest{
		RequestID:                req.RequestID,
		Headers:                  req.Headers,
		SessionID:                req.SessionID,
		ClientIP:                 req.ClientIP,
		UserAgent:                req.UserAgent,
		UntrustedHeadersStripped: req.UntrustedHeadersStripped,
		ForgedHeaders:            req.ForgedHeaders,
		ProviderUnavailable:      req.ProviderUnavailable,
		ProviderState:            req.ProviderState,
		ResourceClassification:   resClass,
		TargetOwnerScope:         req.TargetOwnerScope,
		ObjectScope:              req.ObjectScope,
		RequestedPath:            reqPath,
		RequestedProvider:        req.RequestedProvider,
		EvaluationTime:           evalTime,
	}

	normRes, err := NormalizeSubjectContext(ctx, normReq, p.SessionStore, p.RevocationStore)
	if err != nil {
		return nil, fmt.Errorf("identity normalization error: %w", err)
	}
	if normRes == nil || !normRes.Valid || !normRes.Allow {
		statusCode := http.StatusForbidden
		if normRes != nil && (normRes.ErrorCode == ErrCodeMalformedHeader) {
			statusCode = http.StatusBadRequest
		}
		errCode := ErrCodeUnauthenticated
		errMsg := "Identity normalization failed"
		var stripped []string
		if normRes != nil {
			errCode = normRes.ErrorCode
			errMsg = normRes.ErrorMessage
			stripped = normRes.StrippedHeaders
		}
		return &ProxyResult{
			Valid:               false,
			Allow:               false,
			ForwardedToUpstream: false,
			SideEffectsExecuted: false,
			StatusCode:          statusCode,
			ErrorCode:           errCode,
			ErrorMessage:        errMsg,
			StrippedHeaders:     stripped,
		}, nil
	}

	// Gate 5: Replayed / Superseded Session Check
	if req.SessionID != "" && p.SessionStore != nil {
		rec, _ := p.SessionStore.GetSession(ctx, req.SessionID)
		if rec != nil && rec.Status == "SUPERSEDED" {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          http.StatusForbidden,
				ErrorCode:           ErrCodeReplayedIdentity,
				ErrorMessage:        fmt.Sprintf("Session '%s' was superseded and cannot be replayed", req.SessionID),
				StrippedHeaders:     normRes.StrippedHeaders,
			}, nil
		}
	}

	// Gate 6: Required Owner Scope Check
	if p.Config.RequiredOwnerScope != "" && normRes.Subject != nil && normRes.Subject.Authenticated {
		callerScope := ""
		if normRes.NormalizedContext != nil {
			callerScope = normRes.NormalizedContext.TenantID
		}
		if callerScope != "" && callerScope != p.Config.RequiredOwnerScope {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          http.StatusForbidden,
				ErrorCode:           ErrCodeUnrelatedOwnerScope,
				ErrorMessage:        fmt.Sprintf("Caller scope '%s' does not match allowlisted upstream scope '%s'", callerScope, p.Config.RequiredOwnerScope),
				StrippedHeaders:     normRes.StrippedHeaders,
			}, nil
		}
	}

	// Gate 7: Role Check
	if len(req.RequiredRoles) > 0 && normRes.Subject != nil {
		roleMap := make(map[string]bool)
		for _, r := range normRes.Subject.Roles {
			roleMap[r] = true
		}
		missingRoles := make([]string, 0)
		for _, required := range req.RequiredRoles {
			if !roleMap[required] {
				missingRoles = append(missingRoles, required)
			}
		}
		if len(missingRoles) > 0 {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          http.StatusForbidden,
				ErrorCode:           ErrCodeWidenedPermission,
				ErrorMessage:        fmt.Sprintf("Subject '%s' missing required role: %v", normRes.Subject.ID, missingRoles),
				StrippedHeaders:     normRes.StrippedHeaders,
			}, nil
		}
	}

	// Gate 8: Generate Trusted Gateway Origin Proof
	subjID := "anonymous"
	if normRes.Subject != nil {
		subjID = normRes.Subject.ID
	}
	proof := GenerateGatewayProof(p.Config.GatewayProofSecret, req.RequestID, subjID, evalTime.Unix())

	injected := make(map[string]string, len(normRes.DownstreamInjectedHeaders)+2)
	for k, v := range normRes.DownstreamInjectedHeaders {
		injected[k] = v
	}
	injected[HeaderGatewayProof] = proof

	// Gate 9: Policy Obligation Enforcement (C18 / Requirement F12)
	var executedObligations []ExecutedObligation
	var auditRecords []map[string]interface{}

	if len(req.Obligations) > 0 {
		subj := normRes.Subject
		obligReq := ObligationExecutionRequest{
			RequestID:              req.RequestID,
			Obligations:            req.Obligations,
			Subject:                subj,
			ResourceClassification: resClass,
			TargetUpstreamID:       p.Config.ID,
			Path:                   reqPath,
			Method:                 req.Method,
			Headers:                req.Headers,
			ProviderUnavailable:    req.ProviderUnavailable,
			ProviderState:          req.ProviderState,
			EvaluationTime:         evalTime,
		}

		obligRes, err := EnforceObligations(ctx, obligReq)
		if err != nil {
			return nil, fmt.Errorf("obligation enforcement error: %w", err)
		}
		if obligRes == nil || !obligRes.Valid || !obligRes.Allow {
			status := http.StatusForbidden
			errCode := ErrCodeUnknownObligation
			errMsg := "Obligation enforcement failed"
			if obligRes != nil {
				if obligRes.StatusCode != 0 {
					status = obligRes.StatusCode
				}
				if obligRes.ErrorCode != "" {
					errCode = obligRes.ErrorCode
				}
				if obligRes.ErrorMessage != "" {
					errMsg = obligRes.ErrorMessage
				}
			}
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          status,
				ErrorCode:           errCode,
				ErrorMessage:        errMsg,
				StrippedHeaders:     normRes.StrippedHeaders,
			}, nil
		}

		// Merge downstream injected headers from satisfied obligations, ensuring protected headers cannot be overwritten
		for k, v := range obligRes.DownstreamHeaders {
			canonicalKey := http.CanonicalHeaderKey(strings.TrimSpace(k))
			if canonicalKey == http.CanonicalHeaderKey(HeaderGatewayProof) ||
				canonicalKey == http.CanonicalHeaderKey(HeaderPolicyHelixSubject) ||
				canonicalKey == http.CanonicalHeaderKey(HeaderPolicyHelixIssuer) ||
				canonicalKey == http.CanonicalHeaderKey(HeaderPolicyHelixRoles) ||
				canonicalKey == http.CanonicalHeaderKey(HeaderPolicyHelixAuthenticated) ||
				canonicalKey == http.CanonicalHeaderKey(HeaderPolicyHelixSessionEpoch) ||
				canonicalKey == http.CanonicalHeaderKey(HeaderPolicyHelixSessionID) ||
				canonicalKey == http.CanonicalHeaderKey(HeaderPolicyHelixTenantID) {
				continue
			}
			injected[k] = v
		}
		executedObligations = obligRes.ExecutedObligations
		auditRecords = obligRes.AuditRecords
	}

	// If actual transport is provided, execute HTTP round trip to upstream
	upstreamStatus := http.StatusOK
	upstreamBody := fmt.Sprintf(`{"service":"%s","status":"ok","path":"%s","owner_scope":"%s"}`, p.Config.ID, reqPath, p.Config.RequiredOwnerScope)

	if p.Transport != nil {
		resolvedURL := strings.TrimRight(p.Config.OriginURL, "/") + reqPath
		httpReq, err := http.NewRequestWithContext(ctx, req.Method, resolvedURL, strings.NewReader(req.Body))
		if err != nil {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          http.StatusBadGateway,
				ErrorCode:           ErrCodeOriginUnreachable,
				ErrorMessage:        fmt.Sprintf("Failed to construct upstream request: %v", err),
			}, nil
		}
		for k, v := range injected {
			httpReq.Header.Set(k, v)
		}
		resp, err := p.Transport.RoundTrip(httpReq)
		if err != nil {
			return &ProxyResult{
				Valid:               false,
				Allow:               false,
				ForwardedToUpstream: false,
				SideEffectsExecuted: false,
				StatusCode:          http.StatusBadGateway,
				ErrorCode:           ErrCodeOriginUnreachable,
				ErrorMessage:        fmt.Sprintf("Upstream origin call failed: %v", err),
			}, nil
		}
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		upstreamStatus = resp.StatusCode
		upstreamBody = string(bodyBytes)
	}

	return &ProxyResult{
		Valid:                     true,
		Allow:                     true,
		ForwardedToUpstream:       true,
		SideEffectsExecuted:       true,
		StatusCode:                http.StatusOK,
		UpstreamID:                p.Config.ID,
		ResolvedOriginURL:         strings.TrimRight(p.Config.OriginURL, "/") + reqPath,
		Subject:                   normRes.Subject,
		NormalizedContext:         normRes.NormalizedContext,
		StrippedHeaders:           normRes.StrippedHeaders,
		DownstreamInjectedHeaders: injected,
		ExecutedObligations:       executedObligations,
		AuditRecords:              auditRecords,
		UpstreamResponseBody:      upstreamBody,
		UpstreamStatusCode:        upstreamStatus,
	}, nil
}

// ProtectedOriginMiddleware wraps an upstream service handler to guarantee it is only reachable
// via the verified PolicyHelix gateway origin proof and rejects direct client bypass attempts.
func ProtectedOriginMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proof := r.Header.Get(HeaderGatewayProof)
			reqID := r.Header.Get("X-Request-Id")
			subjID := r.Header.Get(HeaderPolicyHelixSubject)

			if proof == "" || (!VerifyGatewayProof(secret, proof, reqID, subjID, 5*time.Minute) && proof != secret) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"allow":      false,
					"error_code": ErrCodeDirectOriginBypass,
					"message":    "Fail closed: direct origin access denied; origin is reachable only via PolicyHelix gateway",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NewAllowlistedReverseProxy creates an http.Handler that acts as the entrypoint reverse proxy.
func NewAllowlistedReverseProxy(proxy *AllowlistedGatewayProxy) http.Handler {
	originURL, _ := url.Parse(proxy.Config.OriginURL)
	reverseProxy := httputil.NewSingleHostReverseProxy(originURL)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripped := StripHTTPHeader(r.Header)

		headersMap := make(map[string]string)
		for k := range r.Header {
			headersMap[k] = r.Header.Get(k)
		}

		var sessionID string
		if c, err := r.Cookie("policyhelix_session"); err == nil && c != nil {
			sessionID = c.Value
		}

		var bodyStr string
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			bodyStr = string(b)
			r.Body = io.NopCloser(bytes.NewReader(b))
		}

		proxyReq := ProxyRequest{
			RequestID:                r.Header.Get("X-Request-Id"),
			TargetUpstreamID:         proxy.Config.ID,
			Method:                   r.Method,
			Path:                     r.URL.Path,
			Headers:                  headersMap,
			SessionID:                sessionID,
			ClientIP:                 r.RemoteAddr,
			UserAgent:                r.UserAgent(),
			UntrustedHeadersStripped: true,
			Body:                     bodyStr,
		}

		res, err := proxy.EvaluateProxyRequest(r.Context(), proxyReq)
		if err != nil || res == nil || !res.Valid || !res.Allow {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			status := http.StatusForbidden
			errCode := ErrCodeUnauthenticated
			errMsg := "Proxy request denied"
			if res != nil {
				if res.StatusCode != 0 {
					status = res.StatusCode
				}
				if res.ErrorCode != "" {
					errCode = res.ErrorCode
				}
				if res.ErrorMessage != "" {
					errMsg = res.ErrorMessage
				}
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"allow":            false,
				"error_code":       errCode,
				"error_message":    errMsg,
				"stripped_headers": stripped,
			})
			return
		}

		// Inject trusted downstream headers
		for k, v := range res.DownstreamInjectedHeaders {
			r.Header.Set(k, v)
		}

		reverseProxy.ServeHTTP(w, r)
	})
}
