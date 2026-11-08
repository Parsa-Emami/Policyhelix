package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/policy"
)

// EnforcementMatrixFixture models an end-to-end C26 enforcement scenario verifying
// direct origin bypass, forged headers, revoked sessions, expired/stale/tampered bundles,
// and policy outages (Requirement F20).
type EnforcementMatrixFixture struct {
	FixtureID          string                        `json:"fixture_id"`
	CommitID           string                        `json:"commit_id,omitempty"`
	Description        string                        `json:"description,omitempty"`
	SchemaVersion      string                        `json:"schema_version"`
	Vector             string                        `json:"vector"`
	EvaluationTime     string                        `json:"evaluation_time,omitempty"`
	TrustedKeys        []bundles.TrustedKey          `json:"trusted_keys,omitempty"`
	PreloadBundle      *bundles.ActivationRequest    `json:"preload_bundle,omitempty"`
	CandidateBundle    *bundles.ActivationRequest    `json:"candidate_bundle,omitempty"`
	TamperCandidate    string                        `json:"tamper_candidate,omitempty"` // "modify_rego_byte", "modify_signature_byte", "missing_signature"
	PreloadSessions    []auth.SessionRecord          `json:"preload_sessions,omitempty"`
	PreloadRevocations []auth.RevocationRecord       `json:"preload_revocations,omitempty"`
	UpstreamConfig     *UpstreamConfig               `json:"upstream_config,omitempty"`
	ProxyRequest       ProxyRequest                  `json:"proxy_request"`
	Expected           EnforcementMatrixExpectations `json:"expected"`
}

// EnforcementMatrixExpectations defines the expected outcome of an EnforcementMatrixFixture.
type EnforcementMatrixExpectations struct {
	Allow                 bool   `json:"allow"`
	ForwardedToUpstream   bool   `json:"forwarded_to_upstream"`
	StatusCode            int    `json:"status_code,omitempty"`
	ErrorCode             string `json:"error_code,omitempty"`
	CandidateBundleStatus string `json:"candidate_bundle_status,omitempty"`
	CandidateErrorCode    string `json:"candidate_error_code,omitempty"`
	ActiveBundleRetained  *bool  `json:"active_bundle_retained,omitempty"`
	RetainedRevision      int64  `json:"retained_revision,omitempty"`
	OutageDisposition     string `json:"outage_disposition,omitempty"`
	PublicBypassUsed      *bool  `json:"public_bypass_used,omitempty"`
}

// EnforcementMatrixReport is the authoritative result of executing an EnforcementMatrixFixture.
type EnforcementMatrixReport struct {
	FixtureID             string                    `json:"fixture_id"`
	Vector                string                    `json:"vector"`
	SchemaVersion         string                    `json:"schema_version"`
	Passed                bool                      `json:"passed"`
	Allow                 bool                      `json:"allow"`
	ForwardedToUpstream   bool                      `json:"forwarded_to_upstream"`
	StatusCode            int                       `json:"status_code"`
	ErrorCode             string                    `json:"error_code,omitempty"`
	ErrorMessage          string                    `json:"error_message,omitempty"`
	CandidateBundleStatus string                    `json:"candidate_bundle_status,omitempty"`
	CandidateErrorCode    string                    `json:"candidate_error_code,omitempty"`
	ActiveBundleActive    bool                      `json:"active_bundle_active"`
	ActiveBundleID        string                    `json:"active_bundle_id,omitempty"`
	ActiveRevision        int64                     `json:"active_revision"`
	HighestRevision       int64                     `json:"highest_revision"`
	OutageDisposition     string                    `json:"outage_disposition,omitempty"`
	PublicBypassUsed      bool                      `json:"public_bypass_used"`
	ProxyResult           *ProxyResult              `json:"proxy_result,omitempty"`
	BundleDecision        *policy.BundleDecision    `json:"bundle_decision,omitempty"`
}

// EvaluateEnforcementFixture executes a complete C26 enforcement matrix fixture against
// durable bundle storage, session/revocation stores, and the gateway proxy pipeline.
func EvaluateEnforcementFixture(ctx context.Context, storageDir string, fx EnforcementMatrixFixture) (EnforcementMatrixReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rep := EnforcementMatrixReport{
		FixtureID:     fx.FixtureID,
		Vector:        fx.Vector,
		SchemaVersion: "1",
	}

	evalTime := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
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

	env, err := SetupGatewayFixtureEnv(ctx, storageDir, fx.TrustedKeys, fx.PreloadBundle, fx.EvaluationTime, evalTime, fx.PreloadSessions, fx.PreloadRevocations)
	if err != nil {
		rep.ErrorCode = bundles.ErrCodeActivationStoreUnavail
		rep.ErrorMessage = err.Error()
		rep.StatusCode = http.StatusServiceUnavailable
		return rep, err
	}
	defer env.Close()

	mgr := env.KeyManager
	sessStore := env.SessionStore
	revStore := env.RevocationStore

	// Stage 1: Durable Bundle Authority & Anti-Rollback / Anti-Tamper Gate
	if fx.CandidateBundle != nil {
		candReq := *fx.CandidateBundle
		switch fx.TamperCandidate {
		case "modify_rego_byte":
			candReq.Bundle.RegoModule += "\n# tampered_byte"
		case "modify_signature_byte":
			if strings.HasPrefix(candReq.Bundle.Signature, "ed25519:") {
				sigHex := strings.TrimPrefix(candReq.Bundle.Signature, "ed25519:")
				if len(sigHex) > 2 {
					last := sigHex[len(sigHex)-1]
					repChar := "a"
					if last == 'a' {
						repChar = "b"
					}
					candReq.Bundle.Signature = "ed25519:" + sigHex[:len(sigHex)-1] + repChar
				}
			}
		case "missing_signature":
			candReq.Bundle.Signature = ""
			candReq.Bundle.SignatureVerified = false
		}

		candRes := mgr.ActivateBundle(ctx, candReq, fx.EvaluationTime)
		rep.CandidateBundleStatus = candRes.Status
		rep.CandidateErrorCode = candRes.ErrorCode
	}

	kState := mgr.State()
	rep.ActiveBundleActive = kState.Active
	rep.ActiveBundleID = kState.ActiveBundleID
	rep.ActiveRevision = kState.ActiveRevision
	rep.HighestRevision = kState.HighestRevision

	cfg := DefaultUpstreamConfig()
	if fx.UpstreamConfig != nil {
		cfg = *fx.UpstreamConfig
	}

	proxy := NewAllowlistedGatewayProxy(cfg, sessStore, revStore)
	pReq := fx.ProxyRequest
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
	rep.OutageDisposition = pRes.OutageDisposition
	rep.PublicBypassUsed = pRes.PublicBypassUsed

	// Stage 3: Policy Bundle Enforcement Check
	// Shared with the live local runtime so fixture proof and product behavior cannot diverge.
	if dec := EnforcePolicyAuthority(ctx, mgr, pReq, pRes, evalTime, rep.CandidateErrorCode); dec != nil {
		rep.BundleDecision = dec
	}
	rep.Allow = pRes.Allow
	rep.ForwardedToUpstream = pRes.ForwardedToUpstream
	rep.StatusCode = pRes.StatusCode
	rep.ErrorCode = pRes.ErrorCode
	rep.ErrorMessage = pRes.ErrorMessage
	rep.OutageDisposition = pRes.OutageDisposition
	rep.PublicBypassUsed = pRes.PublicBypassUsed

	if err := verifyEnforcementExpectations(fx.Expected, &rep); err != nil {
		rep.Passed = false
		return rep, err
	}

	rep.Passed = true
	return rep, nil
}

func verifyEnforcementExpectations(exp EnforcementMatrixExpectations, rep *EnforcementMatrixReport) error {
	if rep.Allow != exp.Allow {
		return fmt.Errorf("expected allow=%v, got %v (error_code=%s msg=%s)", exp.Allow, rep.Allow, rep.ErrorCode, rep.ErrorMessage)
	}
	if rep.ForwardedToUpstream != exp.ForwardedToUpstream {
		return fmt.Errorf("expected forwarded_to_upstream=%v, got %v", exp.ForwardedToUpstream, rep.ForwardedToUpstream)
	}
	if exp.StatusCode > 0 && rep.StatusCode != exp.StatusCode {
		return fmt.Errorf("expected status_code=%d, got %d", exp.StatusCode, rep.StatusCode)
	}
	if exp.ErrorCode != "" && rep.ErrorCode != exp.ErrorCode {
		return fmt.Errorf("expected error_code=%s, got %s", exp.ErrorCode, rep.ErrorCode)
	}
	if exp.CandidateBundleStatus != "" && rep.CandidateBundleStatus != exp.CandidateBundleStatus {
		return fmt.Errorf("expected candidate_bundle_status=%s, got %s", exp.CandidateBundleStatus, rep.CandidateBundleStatus)
	}
	if exp.CandidateErrorCode != "" && rep.CandidateErrorCode != exp.CandidateErrorCode {
		return fmt.Errorf("expected candidate_error_code=%s, got %s", exp.CandidateErrorCode, rep.CandidateErrorCode)
	}
	if exp.ActiveBundleRetained != nil && rep.ActiveBundleActive != *exp.ActiveBundleRetained {
		return fmt.Errorf("expected active_bundle_retained=%v, got %v", *exp.ActiveBundleRetained, rep.ActiveBundleActive)
	}
	if exp.RetainedRevision > 0 && rep.ActiveRevision != exp.RetainedRevision {
		return fmt.Errorf("expected retained_revision=%d, got %d", exp.RetainedRevision, rep.ActiveRevision)
	}
	if exp.OutageDisposition != "" && rep.OutageDisposition != exp.OutageDisposition {
		return fmt.Errorf("expected outage_disposition=%s, got %s", exp.OutageDisposition, rep.OutageDisposition)
	}
	if exp.PublicBypassUsed != nil && rep.PublicBypassUsed != *exp.PublicBypassUsed {
		return fmt.Errorf("expected public_bypass_used=%v, got %v", *exp.PublicBypassUsed, rep.PublicBypassUsed)
	}
	return nil
}
