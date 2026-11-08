package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/policy"
)

// EnforcePolicyAuthority applies the active durable policy bundle to an already evaluated
// private proxy request. The hermetic C26 enforcement matrix and the live local runtime call
// this single implementation so both enforce identical rules. Any missing authority or denied
// decision fails closed and never leaves a forwarded request.
func EnforcePolicyAuthority(
	ctx context.Context,
	mgr *bundles.KeyRotationManager,
	req ProxyRequest,
	res *ProxyResult,
	evalTime time.Time,
	noActiveCode string,
) *policy.BundleDecision {
	if res == nil || !res.Allow {
		return nil
	}

	// Intentional public outage bypass and explicit public routes are documented exceptions.
	isPublicHealth := res.PublicBypassUsed || req.ExplicitPublicRoute ||
		strings.EqualFold(req.ResourceClassification, "public") || req.Path == "/health"
	if isPublicHealth {
		return nil
	}

	failClosed := func(code, message string) *policy.BundleDecision {
		res.Allow = false
		res.ForwardedToUpstream = false
		res.SideEffectsExecuted = false
		res.StatusCode = http.StatusForbidden
		res.ErrorCode = code
		res.ErrorMessage = message
		return nil
	}

	if mgr == nil {
		return failClosed(policy.ErrCodeNoActiveBundle, "Fail closed: policy authority is unavailable")
	}

	if state := mgr.State(); !state.Active {
		code := policy.ErrCodeNoActiveBundle
		if noActiveCode != "" {
			code = noActiveCode
		}
		return failClosed(code, "Fail closed: no valid active policy bundle in force")
	}

	subject := policy.SubjectIdentity{Authenticated: false}
	if res.Subject != nil {
		subject = policy.SubjectIdentity{
			ID:            res.Subject.ID,
			Issuer:        res.Subject.Issuer,
			Roles:         res.Subject.Roles,
			Authenticated: res.Subject.Authenticated,
			SessionEpoch:  res.Subject.SessionEpoch,
		}
	}

	action := "read"
	if strings.EqualFold(req.Method, "POST") || strings.EqualFold(req.Method, "PUT") || strings.EqualFold(req.Method, "DELETE") {
		action = "write"
	}

	decision := mgr.Evaluate(ctx, policy.BundleEvalInput{
		RequestID:  req.RequestID,
		Path:       req.Path,
		Action:     action,
		Subject:    subject,
		ResourceID: req.Path,
		DeadlineMS: 50,
		EvalTime:   evalTime.Format(time.RFC3339),
	})
	res.BundleDecision = &decision
	if decision.Allow {
		return &decision
	}

	res.Allow = false
	res.ForwardedToUpstream = false
	res.SideEffectsExecuted = false
	res.StatusCode = http.StatusForbidden
	switch {
	case decision.Error != nil && decision.Error.Code != "":
		res.ErrorCode = decision.Error.Code
		res.ErrorMessage = decision.Error.Message
	case len(decision.Reasons) > 0:
		res.ErrorCode = decision.Reasons[0]
		res.ErrorMessage = "Policy bundle denied request"
	default:
		res.ErrorCode = ErrCodePrivateResource
		res.ErrorMessage = "Private resource denied by policy bundle"
	}
	return &decision
}

// UpstreamProbe is the typed result of a real loopback upstream health check.
// A probe is evidence only when it actually contacted the configured origin.
type UpstreamProbe struct {
	Ready        bool    `json:"ready"`
	Verification string  `json:"verification"`
	StatusCode   int     `json:"status_code,omitempty"`
	LatencyMs    float64 `json:"latency_ms"`
	ErrorCode    string  `json:"error_code,omitempty"`
	Message      string  `json:"message,omitempty"`
	CheckedAt    string  `json:"checked_at"`
}

// ProbeUpstream performs a bounded HTTP request to the allowlisted origin /health endpoint.
// A connection failure is reported as an unavailable provider; it is never treated as success.
func ProbeUpstream(ctx context.Context, cfg UpstreamConfig, transport http.RoundTripper) UpstreamProbe {
	start := time.Now()
	checkedAt := start.UTC().Format(time.RFC3339)
	probe := UpstreamProbe{Verification: "http_probe", CheckedAt: checkedAt}

	if strings.TrimSpace(cfg.OriginURL) == "" {
		probe.ErrorCode = ErrCodeUpstreamUnavailable
		probe.Message = "no allowlisted upstream origin is configured"
		return probe
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, strings.TrimRight(cfg.OriginURL, "/")+"/health", nil)
	if err != nil {
		probe.ErrorCode = ErrCodeUpstreamUnavailable
		probe.Message = fmt.Sprintf("failed to construct upstream health request: %v", err)
		return probe
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		probe.ErrorCode = ErrCodeUpstreamUnavailable
		probe.Message = "allowlisted upstream origin is unreachable"
		probe.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
		return probe
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	probe.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	probe.StatusCode = resp.StatusCode

	if resp.StatusCode != http.StatusOK {
		probe.ErrorCode = ErrCodeUpstreamUnavailable
		probe.Message = fmt.Sprintf("upstream health endpoint returned HTTP %d", resp.StatusCode)
		return probe
	}

	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Status != "ok" {
		probe.ErrorCode = ErrCodeUpstreamUnavailable
		probe.Message = "upstream health endpoint did not report status ok"
		return probe
	}

	probe.Ready = true
	return probe
}

// DirectOriginProbe performs an unfiltered request to the configured origin without a gateway
// proof header. The owned upstream must reject it, proving direct origin access is blocked.
type DirectOriginProbe struct {
	Blocked      bool   `json:"blocked"`
	StatusCode   int    `json:"status_code"`
	ErrorCode    string `json:"error_code,omitempty"`
	UpstreamBody string `json:"upstream_body,omitempty"`
	CheckedAt    string `json:"checked_at"`
}

// ProbeDirectOrigin proves origin isolation with a real network request rather than a fixture.
func ProbeDirectOrigin(ctx context.Context, cfg UpstreamConfig, transport http.RoundTripper, path string) DirectOriginProbe {
	now := time.Now().UTC()
	probe := DirectOriginProbe{StatusCode: http.StatusBadGateway, CheckedAt: now.Format(time.RFC3339)}
	if strings.TrimSpace(path) == "" {
		path = "/api/v1/analytics/reports"
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, strings.TrimRight(cfg.OriginURL, "/")+path, nil)
	if err != nil {
		probe.ErrorCode = ErrCodeDirectOriginBypass
		probe.UpstreamBody = "failed to construct direct origin request"
		return probe
	}
	// Deliberately no gateway proof and no normalized identity headers.
	resp, err := transport.RoundTrip(req)
	if err != nil {
		probe.ErrorCode = ErrCodeOriginUnreachable
		probe.UpstreamBody = "origin unreachable"
		return probe
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	probe.StatusCode = resp.StatusCode
	probe.UpstreamBody = string(body)
	probe.Blocked = resp.StatusCode == http.StatusForbidden
	if probe.Blocked {
		probe.ErrorCode = ErrCodeDirectOriginBypass
	}
	return probe
}
