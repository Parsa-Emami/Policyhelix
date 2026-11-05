package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/contracts"
	"github.com/parsa-emami/policyhelix/internal/gateway"
)

const (
	c18FixtureDir = "fixtures/policyhelix/C18"
)

type c18FixtureEnvelope struct {
	FixtureID     string                             `json:"fixture_id"`
	CommitID      string                             `json:"commit_id"`
	Description   string                             `json:"description"`
	SchemaVersion string                             `json:"schema_version"`
	Request       gateway.ObligationExecutionRequest `json:"request"`
	Expected      struct {
		Valid      bool   `json:"valid"`
		Allow      bool   `json:"allow"`
		StatusCode int    `json:"status_code"`
		ErrorCode  string `json:"error_code,omitempty"`
	} `json:"expected"`
}

func TestC18_ManifestIntegrity(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c18FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C18 manifest: %v", err)
	}

	var manifest struct {
		CommitID string `json:"commit_id"`
		Fixtures []struct {
			FixtureID string `json:"fixture_id"`
			Path      string `json:"path"`
			SHA256    string `json:"sha256"`
			Type      string `json:"type"`
			License   string `json:"license"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C18 manifest: %v", err)
	}
	if manifest.CommitID != "C18" {
		t.Fatalf("expected commit_id C18, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 10 {
		t.Fatalf("expected at least 10 C18 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c18FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		sum := sha256.Sum256(raw)
		if actual := hex.EncodeToString(sum[:]); actual != entry.SHA256 {
			t.Fatalf("SHA-256 mismatch on %s: manifest=%s computed=%s", entry.Path, entry.SHA256, actual)
		}
		if entry.License != "Apache-2.0" {
			t.Fatalf("unexpected license %s on %s", entry.License, entry.Path)
		}
	}
}

func TestC18_FixturesSuite(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c18FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C18 manifest: %v", err)
	}

	var manifest struct {
		CommitID string `json:"commit_id"`
		Fixtures []struct {
			FixtureID string `json:"fixture_id"`
			Path      string `json:"path"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C18 manifest: %v", err)
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c18FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		// CLI fixtures are tested explicitly in TestC18_EngineCLIObligations
		if base == "cli-obligations-clean.json" || base == "cli-obligations-rejected.json" {
			continue
		}

		t.Run(entry.FixtureID, func(t *testing.T) {
			var fixture c18FixtureEnvelope
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatalf("failed to unmarshal fixture envelope %s: %v", entry.Path, err)
			}

			res, err := gateway.EnforceObligations(context.Background(), fixture.Request)
			if err != nil {
				t.Fatalf("unexpected obligation enforcement error: %v", err)
			}
			if res == nil {
				t.Fatalf("enforcement returned nil result")
			}

			if res.Allow != fixture.Expected.Allow {
				t.Errorf("allow mismatch on %s: expected %v, got %v (err_code=%s, msg=%s)",
					entry.FixtureID, fixture.Expected.Allow, res.Allow, res.ErrorCode, res.ErrorMessage)
			}
			if res.Valid != fixture.Expected.Valid {
				t.Errorf("valid mismatch on %s: expected %v, got %v",
					entry.FixtureID, fixture.Expected.Valid, res.Valid)
			}
			if fixture.Expected.StatusCode != 0 && res.StatusCode != fixture.Expected.StatusCode {
				t.Errorf("status_code mismatch on %s: expected %d, got %d",
					entry.FixtureID, fixture.Expected.StatusCode, res.StatusCode)
			}
			if fixture.Expected.ErrorCode != "" && res.ErrorCode != fixture.Expected.ErrorCode {
				t.Errorf("error_code mismatch on %s: expected %s, got %s",
					entry.FixtureID, fixture.Expected.ErrorCode, res.ErrorCode)
			}
		})
	}
}

// TestC18_UnknownMandatoryObligation_Denies_F12 explicitly verifies Requirement F12:
// Unknown mandatory obligation denies rather than being ignored.
func TestC18_UnknownMandatoryObligation_Denies_F12(t *testing.T) {
	ctx := context.Background()

	// 1. Explicit mandatory: true
	trueVal := true
	reqExplicit := gateway.ObligationExecutionRequest{
		RequestID:              "req-f12-explicit",
		TargetUpstreamID:       "service:analytics",
		Method:                 "POST",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		Subject: &contracts.Subject{
			ID:            "user-f12-01",
			Authenticated: true,
			Roles:         []string{"operator"},
		},
		Obligations: []gateway.Obligation{
			{
				ID:        "ob-f12-unknown-explicit",
				Type:      "unrecognized_custom_obligation_gate",
				Mandatory: &trueVal,
			},
		},
	}

	resExplicit, err := gateway.EnforceObligations(ctx, reqExplicit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resExplicit.Allow {
		t.Fatal("F12 violation: unknown mandatory obligation (explicit true) was permitted")
	}
	if resExplicit.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resExplicit.StatusCode)
	}
	if resExplicit.ErrorCode != gateway.ErrCodeUnknownObligation {
		t.Fatalf("expected %s, got %s", gateway.ErrCodeUnknownObligation, resExplicit.ErrorCode)
	}

	// 2. Default mandatory (nil pointer)
	reqDefault := gateway.ObligationExecutionRequest{
		RequestID:              "req-f12-default",
		TargetUpstreamID:       "service:analytics",
		Method:                 "POST",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		Subject: &contracts.Subject{
			ID:            "user-f12-02",
			Authenticated: true,
			Roles:         []string{"operator"},
		},
		Obligations: []gateway.Obligation{
			{
				ID:        "ob-f12-unknown-default",
				Type:      "future_quantum_compliance_gate",
				Mandatory: nil, // Must default to mandatory == true
			},
		},
	}

	resDefault, err := gateway.EnforceObligations(ctx, reqDefault)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resDefault.Allow {
		t.Fatal("F12 violation: unknown obligation with default mandatory was permitted")
	}
	if resDefault.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resDefault.StatusCode)
	}
	if resDefault.ErrorCode != gateway.ErrCodeUnknownObligation {
		t.Fatalf("expected %s, got %s", gateway.ErrCodeUnknownObligation, resDefault.ErrorCode)
	}
}

func TestC18_SupportedObligations_Positive(t *testing.T) {
	ctx := context.Background()

	req := gateway.ObligationExecutionRequest{
		RequestID:              "req-supported-01",
		TargetUpstreamID:       "service:analytics",
		Method:                 "POST",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		Subject: &contracts.Subject{
			ID:            "user-supported-01",
			Authenticated: true,
			Roles:         []string{"operator"},
		},
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-audit-1",
				Type: "audit",
				Parameters: map[string]interface{}{
					"action": "export_records",
				},
			},
			{
				ID:   "ob-header-1",
				Type: "header_inject",
				Parameters: map[string]interface{}{
					"headers": map[string]interface{}{
						"X-PolicyHelix-Tier": "enterprise",
					},
				},
			},
			{
				ID:   "ob-rate-1",
				Type: "rate_limit",
				Parameters: map[string]interface{}{
					"limit": float64(100),
				},
			},
			{
				ID:   "ob-redact-1",
				Type: "redact",
				Parameters: map[string]interface{}{
					"fields": []string{"ssn", "secret_key"},
				},
			},
		},
	}

	res, err := gateway.EnforceObligations(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected allow, got deny: %+v", res)
	}
	if len(res.ExecutedObligations) != 4 {
		t.Fatalf("expected 4 executed obligations, got %d", len(res.ExecutedObligations))
	}
	if len(res.AuditRecords) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(res.AuditRecords))
	}
	if res.DownstreamHeaders["X-PolicyHelix-Tier"] != "enterprise" {
		t.Fatalf("expected injected header X-PolicyHelix-Tier: enterprise, got %v", res.DownstreamHeaders)
	}
}

func TestC18_AdvisoryObligation_Permitted(t *testing.T) {
	ctx := context.Background()
	falseVal := false

	req := gateway.ObligationExecutionRequest{
		RequestID:              "req-advisory-01",
		TargetUpstreamID:       "service:analytics",
		Method:                 "GET",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		Subject: &contracts.Subject{
			ID:            "user-advisory-01",
			Authenticated: true,
			Roles:         []string{"operator"},
		},
		Obligations: []gateway.Obligation{
			{
				ID:        "ob-advice-01",
				Type:      "unknown_telemetry_advice",
				Mandatory: &falseVal,
			},
		},
	}

	res, err := gateway.EnforceObligations(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected advisory obligation to allow, got deny: %+v", res)
	}
	if len(res.ExecutedObligations) != 1 {
		t.Fatalf("expected 1 executed obligation, got %d", len(res.ExecutedObligations))
	}
	if res.ExecutedObligations[0].Status != gateway.ObligationStatusIgnoredAdvice {
		t.Fatalf("expected status ignored_advice, got %s", res.ExecutedObligations[0].Status)
	}
}

func TestC18_MixedObligations_FailClosed(t *testing.T) {
	ctx := context.Background()

	req := gateway.ObligationExecutionRequest{
		RequestID:              "req-mixed-01",
		TargetUpstreamID:       "service:analytics",
		Method:                 "POST",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		Subject: &contracts.Subject{
			ID:            "user-mixed-01",
			Authenticated: true,
			Roles:         []string{"operator"},
		},
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-valid-audit",
				Type: "audit",
			},
			{
				ID:   "ob-invalid-mandatory",
				Type: "hardware_zk_proof_enclave", // Unknown mandatory
			},
		},
	}

	res, err := gateway.EnforceObligations(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Fatal("expected fail-closed denial on mixed obligations with unknown mandatory")
	}
	if res.ErrorCode != gateway.ErrCodeUnknownObligation {
		t.Fatalf("expected %s, got %s", gateway.ErrCodeUnknownObligation, res.ErrorCode)
	}
	if len(res.DownstreamHeaders) > 0 {
		t.Fatalf("atomic failure: no downstream headers should be emitted on deny, got: %v", res.DownstreamHeaders)
	}
}

func TestC18_ProxyIntegration(t *testing.T) {
	ctx := context.Background()
	cfg := gateway.DefaultUpstreamConfig()
	proxy := gateway.NewAllowlistedGatewayProxy(cfg, nil, nil)

	// 1. Proxy with unknown mandatory obligation -> fails closed at Gate 9
	reqRejected := gateway.ProxyRequest{
		RequestID:                "req-proxy-oblig-neg",
		TargetUpstreamID:         "service:analytics",
		Method:                   "GET",
		Path:                     "/api/v1/analytics",
		UntrustedHeadersStripped: true,
		ResourceClassification:   "public", // public path still enforces policy obligations if present
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-gate9-fail",
				Type: "unknown_mandatory_telemetry_lock",
			},
		},
	}

	resRejected, err := proxy.EvaluateProxyRequest(ctx, reqRejected)
	if err != nil {
		t.Fatalf("unexpected proxy eval error: %v", err)
	}
	if resRejected.Allow || resRejected.ForwardedToUpstream {
		t.Fatalf("expected proxy Gate 9 fail-closed denial, got: %+v", resRejected)
	}
	if resRejected.ErrorCode != gateway.ErrCodeUnknownObligation {
		t.Fatalf("expected error code %s, got %s", gateway.ErrCodeUnknownObligation, resRejected.ErrorCode)
	}

	// 2. Proxy with valid obligations -> succeeds and merges downstream headers
	reqAllowed := gateway.ProxyRequest{
		RequestID:                "req-proxy-oblig-pos",
		TargetUpstreamID:         "service:analytics",
		Method:                   "GET",
		Path:                     "/health",
		UntrustedHeadersStripped: true,
		ResourceClassification:   "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-gate9-audit",
				Type: "audit",
			},
			{
				ID:   "ob-gate9-header",
				Type: "header_inject",
				Parameters: map[string]interface{}{
					"headers": map[string]interface{}{
						"X-PolicyHelix-Gate9-Token": "verified-gate9",
					},
				},
			},
		},
	}

	resAllowed, err := proxy.EvaluateProxyRequest(ctx, reqAllowed)
	if err != nil {
		t.Fatalf("unexpected proxy eval error: %v", err)
	}
	if !resAllowed.Allow || !resAllowed.ForwardedToUpstream {
		t.Fatalf("expected proxy forward to succeed, got: %+v", resAllowed)
	}
	if resAllowed.DownstreamInjectedHeaders["X-PolicyHelix-Gate9-Token"] != "verified-gate9" {
		t.Fatalf("expected injected header X-PolicyHelix-Gate9-Token, got: %v", resAllowed.DownstreamInjectedHeaders)
	}
	if len(resAllowed.ExecutedObligations) != 2 {
		t.Fatalf("expected 2 executed obligations, got %d", len(resAllowed.ExecutedObligations))
	}
}

func TestC18_EngineCLIObligations(t *testing.T) {
	binaryPath := filepath.Join("..", "dist", "engine", "policyhelix")
	if _, err := os.Stat(binaryPath); err != nil {
		buildCmd := exec.Command("go", "build", "-o", filepath.Join("dist", "engine", "policyhelix"), "./cmd/policyhelix")
		buildCmd.Dir = ".."
		if out, bErr := buildCmd.CombinedOutput(); bErr != nil {
			t.Skipf("cannot build policyhelix binary for CLI tests: %v: %s", bErr, string(out))
		}
		binaryPath = filepath.Join("..", "dist", "engine", "policyhelix")
	}

	// 1. Positive clean fixture
	cleanPath := filepath.Join(c18FixtureDir, "cli-obligations-clean.json")
	cmdClean := exec.Command(binaryPath, "-enforce-obligations", cleanPath)
	outClean, errClean := cmdClean.Output()
	if errClean != nil {
		t.Fatalf("clean CLI execution failed: %v, out: %s", errClean, string(outClean))
	}

	var resClean gateway.ObligationExecutionResult
	if err := json.Unmarshal(outClean, &resClean); err != nil {
		t.Fatalf("failed to parse clean CLI output: %v", err)
	}
	if !resClean.Valid || !resClean.Allow {
		t.Fatalf("expected allow from clean CLI, got: %+v", resClean)
	}

	// 2. Rejected fixture
	rejectedPath := filepath.Join(c18FixtureDir, "cli-obligations-rejected.json")
	cmdRejected := exec.Command(binaryPath, "-enforce-obligations", rejectedPath)
	outRejected, errRejected := cmdRejected.Output()
	if errRejected == nil {
		t.Fatalf("expected rejected CLI execution to return exit code 1, but succeeded with output: %s", string(outRejected))
	}

	var resRejected gateway.ObligationExecutionResult
	if len(outRejected) > 0 {
		_ = json.Unmarshal(outRejected, &resRejected)
		if resRejected.Allow {
			t.Fatalf("expected rejected outcome, got: %+v", resRejected)
		}
		if resRejected.ErrorCode != gateway.ErrCodeUnknownObligation {
			t.Fatalf("expected error code %s, got %s", gateway.ErrCodeUnknownObligation, resRejected.ErrorCode)
		}
	}
}

func TestC18_HTTPObligationsEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--port", fmt.Sprintf("%d", port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 40; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("engine server did not become healthy in time")
	}

	// 1. Positive POST /api/v1/gateway/obligations/enforce
	validReq := gateway.ObligationExecutionRequest{
		RequestID:              "req-http-01",
		TargetUpstreamID:       "service:analytics",
		Method:                 "GET",
		Path:                   "/health",
		ResourceClassification: "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-http-audit",
				Type: "audit",
			},
		},
	}
	reqBytes, _ := json.Marshal(validReq)
	resp, err := client.Post(baseURL+"/api/v1/gateway/obligations/enforce", "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		t.Fatalf("HTTP post failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var resBody gateway.ObligationExecutionResult
	_ = json.NewDecoder(resp.Body).Decode(&resBody)
	_ = resp.Body.Close()
	if !resBody.Allow {
		t.Fatalf("expected allow: true, got %+v", resBody)
	}

	// 2. Negative POST with unknown mandatory obligation -> 403 Forbidden
	invalidReq := gateway.ObligationExecutionRequest{
		RequestID:              "req-http-02",
		TargetUpstreamID:       "service:analytics",
		Method:                 "GET",
		Path:                   "/health",
		ResourceClassification: "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-unknown",
				Type: "unknown_mandatory_satellite_uplink",
			},
		},
	}
	reqBytesInv, _ := json.Marshal(invalidReq)
	respInv, err := client.Post(baseURL+"/api/v1/gateway/obligations", "application/json", bytes.NewReader(reqBytesInv))
	if err != nil {
		t.Fatalf("HTTP post failed: %v", err)
	}
	if respInv.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", respInv.StatusCode)
	}
	var resBodyInv gateway.ObligationExecutionResult
	_ = json.NewDecoder(respInv.Body).Decode(&resBodyInv)
	_ = respInv.Body.Close()
	if resBodyInv.Allow || resBodyInv.ErrorCode != gateway.ErrCodeUnknownObligation {
		t.Fatalf("expected UNKNOWN_MANDATORY_OBLIGATION, got: %+v", resBodyInv)
	}

	// 3. Negative POST with malformed JSON -> 400 Bad Request
	respMalformed, err := client.Post(baseURL+"/api/v1/gateway/obligations/enforce", "application/json", bytes.NewReader([]byte("{invalid-json")))
	if err != nil {
		t.Fatalf("HTTP post failed: %v", err)
	}
	if respMalformed.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", respMalformed.StatusCode)
	}
	_ = respMalformed.Body.Close()

	// 4. Method not allowed on GET -> 405
	respGet, err := client.Get(baseURL + "/api/v1/gateway/obligations/enforce")
	if err != nil {
		t.Fatalf("HTTP get failed: %v", err)
	}
	if respGet.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", respGet.StatusCode)
	}
	_ = respGet.Body.Close()
}

func TestC18_NegativeCases(t *testing.T) {
	ctx := context.Background()

	// 1. Malformed obligation (empty type)
	reqMalformed := gateway.ObligationExecutionRequest{
		RequestID: "req-malformed-01",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-bad",
				Type: "   ",
			},
		},
	}
	resMalformed, err := gateway.EnforceObligations(ctx, reqMalformed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resMalformed.Allow || resMalformed.ErrorCode != gateway.ErrCodeMalformedObligation {
		t.Fatalf("expected MALFORMED_OBLIGATION, got: %+v", resMalformed)
	}
	if resMalformed.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resMalformed.StatusCode)
	}

	// 2. Unauthenticated access to private resource
	reqPrivate := gateway.ObligationExecutionRequest{
		RequestID:              "req-priv-01",
		ResourceClassification: "private",
		Subject:                nil, // Unauthenticated
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-1",
				Type: "audit",
			},
		},
	}
	resPrivate, err := gateway.EnforceObligations(ctx, reqPrivate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resPrivate.Allow || resPrivate.ErrorCode != gateway.ErrCodePrivateResource {
		t.Fatalf("expected PRIVATE_RESOURCE_FAIL_CLOSED, got: %+v", resPrivate)
	}

	// 3. Obligation provider unavailable
	reqUnavail := gateway.ObligationExecutionRequest{
		RequestID:           "req-unavail-01",
		ProviderUnavailable: true,
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-1",
				Type: "audit",
			},
		},
	}
	resUnavail, err := gateway.EnforceObligations(ctx, reqUnavail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resUnavail.Allow || resUnavail.ErrorCode != gateway.ErrCodeProviderUnavailable {
		t.Fatalf("expected PROVIDER_UNAVAILABLE, got: %+v", resUnavail)
	}
	if resUnavail.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resUnavail.StatusCode)
	}

	// 4. Simulated handler execution failure
	reqFail := gateway.ObligationExecutionRequest{
		RequestID:              "req-fail-01",
		ResourceClassification: "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-fail",
				Type: "audit",
				Parameters: map[string]interface{}{
					"fail": true,
				},
			},
		},
	}
	resFail, err := gateway.EnforceObligations(ctx, reqFail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resFail.Allow || resFail.ErrorCode != gateway.ErrCodeObligationFailed {
		t.Fatalf("expected OBLIGATION_EXECUTION_FAILED, got: %+v", resFail)
	}
}

func TestC18_RestartInvariant(t *testing.T) {
	ctx := context.Background()

	req := gateway.ObligationExecutionRequest{
		RequestID:              "req-restart-01",
		TargetUpstreamID:       "service:analytics",
		Method:                 "GET",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		Subject: &contracts.Subject{
			ID:            "user-restart-01",
			Authenticated: true,
			Roles:         []string{"operator"},
		},
		EvaluationTime: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC),
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-audit-restart",
				Type: "audit",
				Parameters: map[string]interface{}{
					"audit_id": "aud-1234",
				},
			},
		},
	}

	// Run multiple times simulating service reboots
	res1, _ := gateway.EnforceObligations(ctx, req)
	res2, _ := gateway.EnforceObligations(ctx, req)

	json1, _ := json.Marshal(res1)
	json2, _ := json.Marshal(res2)

	if !bytes.Equal(json1, json2) {
		t.Fatalf("restart invariant violation: results not deterministic:\n1: %s\n2: %s", string(json1), string(json2))
	}
}

func TestC18_Security_HeaderInjectionCRLF(t *testing.T) {
	ctx := context.Background()

	// 1. CRLF in header name
	reqBadKey := gateway.ObligationExecutionRequest{
		RequestID:              "req-crlf-01",
		ResourceClassification: "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-crlf-key",
				Type: "header_inject",
				Parameters: map[string]interface{}{
					"headers": map[string]interface{}{
						"X-Custom-Token\r\nEvil: forged": "value",
					},
				},
			},
		},
	}
	resBadKey, err := gateway.EnforceObligations(ctx, reqBadKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resBadKey.Allow || resBadKey.ErrorCode != gateway.ErrCodeMalformedObligation {
		t.Fatalf("expected MALFORMED_OBLIGATION for CRLF header name, got: %+v", resBadKey)
	}

	// 2. CRLF in header value
	reqBadVal := gateway.ObligationExecutionRequest{
		RequestID:              "req-crlf-02",
		ResourceClassification: "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-crlf-val",
				Type: "header_inject",
				Parameters: map[string]interface{}{
					"header_name":  "X-Custom-Token",
					"header_value": "innocent\r\nInjected-Header: evil",
				},
			},
		},
	}
	resBadVal, err := gateway.EnforceObligations(ctx, reqBadVal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resBadVal.Allow || resBadVal.ErrorCode != gateway.ErrCodeMalformedObligation {
		t.Fatalf("expected MALFORMED_OBLIGATION for CRLF header value, got: %+v", resBadVal)
	}
}

func TestC18_Security_ReservedHeaderHijack(t *testing.T) {
	ctx := context.Background()

	reservedHeaders := []string{
		gateway.HeaderGatewayProof,
		gateway.HeaderPolicyHelixSubject,
		gateway.HeaderPolicyHelixRoles,
		gateway.HeaderPolicyHelixAuthenticated,
		"X-User-Id",
		"X-Subject",
	}

	for _, reserved := range reservedHeaders {
		t.Run("hijack_"+reserved, func(t *testing.T) {
			req := gateway.ObligationExecutionRequest{
				RequestID:              "req-hijack-" + reserved,
				ResourceClassification: "public",
				Obligations: []gateway.Obligation{
					{
						ID:   "ob-hijack",
						Type: "header_inject",
						Parameters: map[string]interface{}{
							"headers": map[string]interface{}{
								reserved: "attacker-controlled-value",
							},
						},
					},
				},
			}
			res, err := gateway.EnforceObligations(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Allow || res.ErrorCode != gateway.ErrCodeMalformedObligation {
				t.Fatalf("expected MALFORMED_OBLIGATION when attempting to inject reserved header %s, got: %+v", reserved, res)
			}
		})
	}
}

func TestC18_Security_NumericLimitVariations(t *testing.T) {
	ctx := context.Background()

	// Negative limit as int
	reqInt := gateway.ObligationExecutionRequest{
		RequestID:              "req-lim-int",
		ResourceClassification: "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-rate-neg-int",
				Type: "rate_limit",
				Parameters: map[string]interface{}{
					"limit": -5,
				},
			},
		},
	}
	resInt, err := gateway.EnforceObligations(ctx, reqInt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resInt.Allow || resInt.ErrorCode != gateway.ErrCodeMalformedObligation {
		t.Fatalf("expected MALFORMED_OBLIGATION for negative int limit, got: %+v", resInt)
	}

	// Negative limit as float64
	reqFloat := gateway.ObligationExecutionRequest{
		RequestID:              "req-lim-float",
		ResourceClassification: "public",
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-rate-neg-float",
				Type: "rate_limit",
				Parameters: map[string]interface{}{
					"limit": float64(-10.5),
				},
			},
		},
	}
	resFloat, err := gateway.EnforceObligations(ctx, reqFloat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resFloat.Allow || resFloat.ErrorCode != gateway.ErrCodeMalformedObligation {
		t.Fatalf("expected MALFORMED_OBLIGATION for negative float limit, got: %+v", resFloat)
	}
}
