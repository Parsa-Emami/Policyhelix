package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	ErrCodeUnsafeImportPayload = "UNSAFE_IMPORT_PAYLOAD_REJECTED"
	MaxImportPayloadBytes      = 65536
	MaxImportNestingDepth      = 32
	MaxImportNodeCount         = 20000
)

var forbiddenImportKeys = map[string]bool{
	"__proto__":   true,
	"prototype":   true,
	"constructor": true,
}

// SecurityBoundaryFixture models a C27 security and authorization boundary test case
// covering missing/expired/replayed identity, cross-owner/object IDOR, forged headers,
// widened path/provider permissions, IdP unavailability, XSS/prototype-pollution imports,
// and fail-closed private resource enforcement (Requirement N27).
type SecurityBoundaryFixture struct {
	FixtureID          string                       `json:"fixture_id"`
	CommitID           string                       `json:"commit_id,omitempty"`
	Description        string                       `json:"description,omitempty"`
	SchemaVersion      string                       `json:"schema_version"`
	Vector             string                       `json:"vector"`
	Surface            string                       `json:"surface"`
	EvaluationTime     string                       `json:"evaluation_time,omitempty"`
	TrustedKeys        []bundles.TrustedKey         `json:"trusted_keys,omitempty"`
	PreloadBundle      *bundles.ActivationRequest   `json:"preload_bundle,omitempty"`
	PreloadSessions    []auth.SessionRecord         `json:"preload_sessions,omitempty"`
	PreloadRevocations []auth.RevocationRecord      `json:"preload_revocations,omitempty"`
	PreloadRecords     []storage.WriteRequest       `json:"preload_records,omitempty"`
	AttemptedWrite     *storage.WriteRequest        `json:"attempted_write,omitempty"`
	UntrustedImportRaw string                       `json:"untrusted_import_raw,omitempty"`
	UpstreamConfig     *UpstreamConfig              `json:"upstream_config,omitempty"`
	ProxyRequest       *ProxyRequest                `json:"proxy_request,omitempty"`
	Expected           SecurityBoundaryExpectations `json:"expected"`
}

// SecurityBoundaryExpectations defines the expected outcome of a SecurityBoundaryFixture.
type SecurityBoundaryExpectations struct {
	Allow               bool   `json:"allow"`
	ForwardedToUpstream bool   `json:"forwarded_to_upstream"`
	SideEffectsExecuted bool   `json:"side_effects_executed"`
	StatusCode          int    `json:"status_code"`
	ErrorCode           string `json:"error_code,omitempty"`
	StorageErrorCode    string `json:"storage_error_code,omitempty"`
	ImportRejected      *bool  `json:"import_rejected,omitempty"`
	XSSInert            *bool  `json:"xss_inert,omitempty"`
}

// SecurityBoundaryReport is the authoritative result of executing a SecurityBoundaryFixture.
type SecurityBoundaryReport struct {
	FixtureID            string                 `json:"fixture_id"`
	Vector               string                 `json:"vector"`
	Surface              string                 `json:"surface"`
	SchemaVersion        string                 `json:"schema_version"`
	Passed               bool                   `json:"passed"`
	Allow                bool                   `json:"allow"`
	ForwardedToUpstream  bool                   `json:"forwarded_to_upstream"`
	SideEffectsExecuted  bool                   `json:"side_effects_executed"`
	StatusCode           int                    `json:"status_code"`
	ErrorCode            string                 `json:"error_code,omitempty"`
	ErrorMessage         string                 `json:"error_message,omitempty"`
	StorageWriteAllowed  bool                   `json:"storage_write_allowed"`
	StorageErrorCode     string                 `json:"storage_error_code,omitempty"`
	ImportRejected       bool                   `json:"import_rejected"`
	XSSInert             bool                   `json:"xss_inert"`
	EscapedPreviewSample string                 `json:"escaped_preview_sample,omitempty"`
	RecordsBeforeAttempt int                    `json:"records_before_attempt"`
	RecordsAfterAttempt  int                    `json:"records_after_attempt"`
	ProxyResult          *ProxyResult           `json:"proxy_result,omitempty"`
	BundleDecision       *policy.BundleDecision `json:"bundle_decision,omitempty"`
}

// ValidateUntrustedImportPayload enforces the same structural, size, complexity,
// and prototype-pollution boundaries as apps/web/src/lib/preview.mjs, plus safe HTML escaping.
func ValidateUntrustedImportPayload(raw string) (escapedSample string, xssInert bool, err error) {
	rawBytes := []byte(raw)
	if len(rawBytes) > MaxImportPayloadBytes {
		return "", true, fmt.Errorf("%s: payload exceeds %d bytes limit", ErrCodeUnsafeImportPayload, MaxImportPayloadBytes)
	}

	dec := json.NewDecoder(bytes.NewReader(rawBytes))
	dec.UseNumber()
	var root interface{}
	if err := dec.Decode(&root); err != nil {
		return "", true, fmt.Errorf("%s: malformed JSON document: %v", ErrCodeUnsafeImportPayload, err)
	}

	rootObj, ok := root.(map[string]interface{})
	if !ok || rootObj == nil {
		return "", true, fmt.Errorf("%s: document root must be a JSON object", ErrCodeUnsafeImportPayload)
	}

	type frame struct {
		val   interface{}
		depth int
	}
	stack := []frame{{val: rootObj, depth: 0}}
	nodeCount := 0
	var rawSnippets []string

	for len(stack) > 0 {
		curr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodeCount++
		if nodeCount > MaxImportNodeCount || curr.depth > MaxImportNestingDepth {
			return "", true, fmt.Errorf("%s: document exceeds complexity or depth bounds (nodes=%d depth=%d)", ErrCodeUnsafeImportPayload, nodeCount, curr.depth)
		}

		switch typed := curr.val.(type) {
		case map[string]interface{}:
			for k, v := range typed {
				if forbiddenImportKeys[k] {
					return "", true, fmt.Errorf("%s: forbidden prototype-pollution key %q", ErrCodeUnsafeImportPayload, k)
				}
				if strings.Contains(k, "<") || strings.Contains(k, ">") || strings.Contains(strings.ToLower(k), "onerror") || strings.Contains(strings.ToLower(k), "javascript:") {
					rawSnippets = append(rawSnippets, k)
				}
				stack = append(stack, frame{val: v, depth: curr.depth + 1})
			}
		case []interface{}:
			for _, item := range typed {
				stack = append(stack, frame{val: item, depth: curr.depth + 1})
			}
		case string:
			if strings.Contains(typed, "<") || strings.Contains(typed, ">") || strings.Contains(strings.ToLower(typed), "onerror") || strings.Contains(strings.ToLower(typed), "javascript:") {
				rawSnippets = append(rawSnippets, typed)
			}
		}
	}

	escaped := EscapeUntrustedText(strings.Join(rawSnippets, " | "))
	inert := !strings.Contains(escaped, "<script") && !strings.Contains(escaped, "<img")
	return escaped, inert, nil
}

// EscapeUntrustedText converts HTML/script control characters into inert entities.
func EscapeUntrustedText(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

// EvaluateSecurityBoundaryFixture executes a C27 security and authorization boundary fixture
// against real durable storage, session/revocation stores, bundle authority, and gateway proxy.
func EvaluateSecurityBoundaryFixture(ctx context.Context, storageDir string, fx SecurityBoundaryFixture) (SecurityBoundaryReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rep := SecurityBoundaryReport{
		FixtureID:     fx.FixtureID,
		Vector:        fx.Vector,
		Surface:       fx.Surface,
		SchemaVersion: "1",
		XSSInert:      true,
	}

	evalTime := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	if strings.TrimSpace(fx.EvaluationTime) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(fx.EvaluationTime))
		if err != nil {
			rep.ErrorCode = "INVALID_EVALUATION_TIME"
			rep.ErrorMessage = err.Error()
			rep.StatusCode = http.StatusBadRequest
			return rep, err
		}
		evalTime = parsed.UTC()
	}

	ad, _, err := storage.Open(storageDir)
	if err != nil {
		rep.ErrorCode = bundles.ErrCodeActivationStoreUnavail
		rep.ErrorMessage = err.Error()
		rep.StatusCode = http.StatusServiceUnavailable
		return rep, err
	}
	defer ad.Close()

	// Stage 1: Untrusted Import / XSS / Prototype-Pollution Gate (if specified)
	if strings.TrimSpace(fx.UntrustedImportRaw) != "" {
		escaped, inert, impErr := ValidateUntrustedImportPayload(fx.UntrustedImportRaw)
		rep.EscapedPreviewSample = EscapeUntrustedText(fx.UntrustedImportRaw)
		if escaped != "" {
			rep.EscapedPreviewSample = escaped
		}
		rep.XSSInert = inert && !strings.Contains(rep.EscapedPreviewSample, "<script")
		if impErr != nil {
			rep.ImportRejected = true
			rep.Allow = false
			rep.ForwardedToUpstream = false
			rep.SideEffectsExecuted = false
			rep.StatusCode = http.StatusUnprocessableEntity
			rep.ErrorCode = ErrCodeUnsafeImportPayload
			rep.ErrorMessage = impErr.Error()
			if err := verifySecurityExpectations(fx.Expected, &rep); err != nil {
				return rep, err
			}
			rep.Passed = true
			return rep, nil
		}
	}

	// Stage 2: Preload Trusted Keys, Bundle, Sessions, Revocations & Baseline Scoped Records
	mgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(fx.TrustedKeys...))
	mgr.Now = func() time.Time { return evalTime }

	if fx.PreloadBundle != nil {
		preRes := mgr.ActivateBundle(ctx, *fx.PreloadBundle, fx.EvaluationTime)
		if preRes.Status == bundles.ActivationStatusRejected {
			rep.ErrorCode = preRes.ErrorCode
			rep.ErrorMessage = fmt.Sprintf("preload bundle rejected: %s", preRes.Message)
			rep.StatusCode = http.StatusForbidden
			return rep, fmt.Errorf("%s: %s", rep.ErrorCode, rep.ErrorMessage)
		}
	}

	sessStore := auth.NewStorageSessionStore(ad)
	revStore := auth.NewStorageRevocationStore(ad)
	for _, s := range fx.PreloadSessions {
		_ = sessStore.SaveSession(ctx, s)
	}
	for _, r := range fx.PreloadRevocations {
		if r.SessionID != "" {
			_ = revStore.SaveSessionRevocation(ctx, r)
		}
		if r.SubjectID != "" && r.MinRequiredEpoch > 0 {
			_ = revStore.SaveSubjectRevocation(ctx, r)
		}
		if r.OwnerScope != "" {
			_ = revStore.SaveScopeRevocation(ctx, r)
		}
	}
	for _, rec := range fx.PreloadRecords {
		if _, wErr := ad.WriteRecord(ctx, rec); wErr != nil {
			rep.ErrorCode = wErr.Code
			rep.ErrorMessage = fmt.Sprintf("preload record write failed: %s", wErr.Message)
			rep.StatusCode = http.StatusForbidden
			return rep, fmt.Errorf("%s: %s", rep.ErrorCode, rep.ErrorMessage)
		}
	}

	if mfBefore, mfErr := ad.GetManifest(); mfErr == nil && mfBefore != nil {
		rep.RecordsBeforeAttempt = len(mfBefore.Records)
		rep.RecordsAfterAttempt = len(mfBefore.Records)
	}

	// Stage 3: Evaluate Attempted Storage Object Write (IDOR / OwnerScope & Identity Boundary)
	if fx.AttemptedWrite != nil {
		_, sErr := ad.WriteRecord(ctx, *fx.AttemptedWrite)
		if sErr != nil {
			rep.StorageWriteAllowed = false
			rep.StorageErrorCode = sErr.Code
		} else {
			rep.StorageWriteAllowed = true
			rep.SideEffectsExecuted = true
		}
		if mfAfter, mfErr := ad.GetManifest(); mfErr == nil && mfAfter != nil {
			rep.RecordsAfterAttempt = len(mfAfter.Records)
		}
	}

	// Stage 4: Evaluate Gateway Proxy & Policy Bundle Enforcement
	if fx.ProxyRequest != nil {
		cfg := DefaultUpstreamConfig()
		if fx.UpstreamConfig != nil {
			cfg = *fx.UpstreamConfig
		}
		proxy := NewAllowlistedGatewayProxy(cfg, sessStore, revStore)
		pReq := *fx.ProxyRequest
		if pReq.EvaluationTime.IsZero() {
			pReq.EvaluationTime = evalTime
		}

		pRes, pErr := proxy.EvaluateProxyRequest(ctx, pReq)
		if pErr != nil {
			rep.ErrorCode = "PROXY_EVALUATION_ERROR"
			rep.ErrorMessage = pErr.Error()
			rep.StatusCode = http.StatusInternalServerError
			return rep, pErr
		}
		rep.ProxyResult = pRes
		rep.Allow = pRes.Allow
		rep.ForwardedToUpstream = pRes.ForwardedToUpstream
		rep.StatusCode = pRes.StatusCode
		rep.ErrorCode = pRes.ErrorCode
		rep.ErrorMessage = pRes.ErrorMessage

		// Enforce active policy bundle on allowed private/internal/restricted requests
		isPublicRoute := pRes.PublicBypassUsed || pReq.ExplicitPublicRoute || strings.EqualFold(pReq.ResourceClassification, "public") || pReq.Path == "/health"
		if rep.Allow && !isPublicRoute {
			kState := mgr.State()
			if !kState.Active {
				rep.Allow = false
				rep.ForwardedToUpstream = false
				rep.SideEffectsExecuted = false
				rep.StatusCode = http.StatusForbidden
				rep.ErrorCode = policy.ErrCodeNoActiveBundle
				rep.ErrorMessage = "Fail closed: no active policy bundle"
			} else {
				sub := policy.SubjectIdentity{Authenticated: false}
				if pRes.Subject != nil {
					sub = policy.SubjectIdentity{
						ID:            pRes.Subject.ID,
						Issuer:        pRes.Subject.Issuer,
						Roles:         pRes.Subject.Roles,
						Authenticated: pRes.Subject.Authenticated,
						SessionEpoch:  pRes.Subject.SessionEpoch,
					}
				}
				action := "read"
				if strings.EqualFold(pReq.Method, "POST") || strings.EqualFold(pReq.Method, "PUT") || strings.EqualFold(pReq.Method, "DELETE") {
					action = "write"
				}
				bDec := mgr.Evaluate(ctx, policy.BundleEvalInput{
					RequestID:  pReq.RequestID,
					Path:       pReq.Path,
					Action:     action,
					Subject:    sub,
					ResourceID: pReq.Path,
					DeadlineMS: 50,
					EvalTime:   evalTime.Format(time.RFC3339),
				})
				rep.BundleDecision = &bDec
				if !bDec.Allow {
					rep.Allow = false
					rep.ForwardedToUpstream = false
					rep.SideEffectsExecuted = false
					rep.StatusCode = http.StatusForbidden
					if bDec.Error != nil && bDec.Error.Code != "" {
						rep.ErrorCode = bDec.Error.Code
						rep.ErrorMessage = bDec.Error.Message
					} else {
						rep.ErrorCode = ErrCodeWidenedPermission
						rep.ErrorMessage = "Policy bundle denied request"
					}
				}
			}
		}

		// If proxy allowed and either storage write succeeded or request was forwarded to upstream, mark side effects
		if rep.Allow && (rep.ForwardedToUpstream || rep.StorageWriteAllowed) {
			rep.SideEffectsExecuted = true
		} else if !rep.Allow {
			rep.SideEffectsExecuted = false
			// Ensure no unapproved storage mutation leaked on rejected request
			if rep.RecordsAfterAttempt != rep.RecordsBeforeAttempt {
				return rep, fmt.Errorf("security violation: rejected request mutated durable storage (%d -> %d)", rep.RecordsBeforeAttempt, rep.RecordsAfterAttempt)
			}
		}
	}

	if err := verifySecurityExpectations(fx.Expected, &rep); err != nil {
		return rep, err
	}
	rep.Passed = true
	return rep, nil
}

func verifySecurityExpectations(exp SecurityBoundaryExpectations, rep *SecurityBoundaryReport) error {
	if rep.Allow != exp.Allow {
		return fmt.Errorf("allow mismatch: expected %v, got %v (error_code=%s msg=%s)", exp.Allow, rep.Allow, rep.ErrorCode, rep.ErrorMessage)
	}
	if rep.ForwardedToUpstream != exp.ForwardedToUpstream {
		return fmt.Errorf("forwarded_to_upstream mismatch: expected %v, got %v", exp.ForwardedToUpstream, rep.ForwardedToUpstream)
	}
	if rep.SideEffectsExecuted != exp.SideEffectsExecuted {
		return fmt.Errorf("side_effects_executed mismatch: expected %v, got %v", exp.SideEffectsExecuted, rep.SideEffectsExecuted)
	}
	if exp.StatusCode != 0 && rep.StatusCode != exp.StatusCode {
		return fmt.Errorf("status_code mismatch: expected %d, got %d (error_code=%s)", exp.StatusCode, rep.StatusCode, rep.ErrorCode)
	}
	if exp.ErrorCode != "" && rep.ErrorCode != exp.ErrorCode {
		return fmt.Errorf("error_code mismatch: expected %q, got %q (msg=%s)", exp.ErrorCode, rep.ErrorCode, rep.ErrorMessage)
	}
	if exp.StorageErrorCode != "" && rep.StorageErrorCode != exp.StorageErrorCode {
		return fmt.Errorf("storage_error_code mismatch: expected %q, got %q", exp.StorageErrorCode, rep.StorageErrorCode)
	}
	if exp.ImportRejected != nil && rep.ImportRejected != *exp.ImportRejected {
		return fmt.Errorf("import_rejected mismatch: expected %v, got %v", *exp.ImportRejected, rep.ImportRejected)
	}
	if exp.XSSInert != nil && rep.XSSInert != *exp.XSSInert {
		return fmt.Errorf("xss_inert mismatch: expected %v, got %v", *exp.XSSInert, rep.XSSInert)
	}
	return nil
}
