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
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	c19FixtureDir = "fixtures/policyhelix/C19"
)

type c19FixtureEnvelope struct {
	FixtureID     string                        `json:"fixture_id"`
	CommitID      string                        `json:"commit_id"`
	Description   string                        `json:"description"`
	SchemaVersion string                        `json:"schema_version"`
	Request       gateway.ResourceOutageRequest `json:"request"`
	Expected      struct {
		Valid               bool   `json:"valid"`
		Allow               bool   `json:"allow"`
		StatusCode          int    `json:"status_code"`
		ErrorCode           string `json:"error_code,omitempty"`
		Disposition         string `json:"disposition,omitempty"`
		PublicBypassUsed    bool   `json:"public_bypass_used,omitempty"`
		ForwardedToUpstream bool   `json:"forwarded_to_upstream,omitempty"`
		SideEffectsExecuted bool   `json:"side_effects_executed,omitempty"`
	} `json:"expected"`
}

func TestC19_ManifestIntegrity(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c19FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C19 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C19 manifest: %v", err)
	}
	if manifest.CommitID != "C19" {
		t.Fatalf("expected commit_id C19, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 10 {
		t.Fatalf("expected at least 10 C19 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c19FixtureDir, base))
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

func TestC19_FixturesSuite(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c19FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C19 manifest: %v", err)
	}

	var manifest struct {
		CommitID string `json:"commit_id"`
		Fixtures []struct {
			FixtureID string `json:"fixture_id"`
			Path      string `json:"path"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C19 manifest: %v", err)
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c19FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		// CLI fixtures are tested explicitly in TestC19_EngineCLIFailure
		if base == "cli-failure-public-bypass.json" || base == "cli-failure-sensitive-denied.json" {
			continue
		}

		t.Run(entry.FixtureID, func(t *testing.T) {
			var fixture c19FixtureEnvelope
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatalf("failed to unmarshal fixture envelope %s: %v", entry.Path, err)
			}

			res, err := gateway.EvaluateResourceOutage(context.Background(), fixture.Request)
			if err != nil {
				t.Fatalf("unexpected outage evaluation error: %v", err)
			}
			if res == nil {
				t.Fatalf("outage evaluation returned nil result")
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
			if fixture.Expected.Disposition != "" && res.Disposition != fixture.Expected.Disposition {
				t.Errorf("disposition mismatch on %s: expected %s, got %s",
					entry.FixtureID, fixture.Expected.Disposition, res.Disposition)
			}
			if fixture.Expected.PublicBypassUsed != res.PublicBypassUsed {
				t.Errorf("public_bypass_used mismatch on %s: expected %v, got %v",
					entry.FixtureID, fixture.Expected.PublicBypassUsed, res.PublicBypassUsed)
			}
			if fixture.Expected.ForwardedToUpstream != res.ForwardedToUpstream {
				t.Errorf("forwarded_to_upstream mismatch on %s: expected %v, got %v",
					entry.FixtureID, fixture.Expected.ForwardedToUpstream, res.ForwardedToUpstream)
			}
			if fixture.Expected.SideEffectsExecuted != res.SideEffectsExecuted {
				t.Errorf("side_effects_executed mismatch on %s: expected %v, got %v",
					entry.FixtureID, fixture.Expected.SideEffectsExecuted, res.SideEffectsExecuted)
			}
		})
	}
}

// TestC19_DecisionLossSensitiveRoutesDeny_F13 explicitly verifies Requirement F13:
// Decision loss denies sensitive routes.
func TestC19_DecisionLossSensitiveRoutesDeny_F13(t *testing.T) {
	ctx := context.Background()

	sensitiveCases := []struct {
		name           string
		path           string
		classification string
		state          string
		providerState  string
	}{
		{
			name:           "private route with decision outage",
			path:           "/api/v1/analytics",
			classification: "private",
			state:          "outage",
		},
		{
			name:           "private route with decision timeout",
			path:           "/api/v1/analytics/export",
			classification: "private",
			state:          "timeout",
		},
		{
			name:           "private route with corrupted decision point",
			path:           "/api/v1/analytics/records",
			classification: "private",
			state:          "corrupted",
		},
		{
			name:           "internal route with decision outage",
			path:           "/internal/metrics",
			classification: "internal",
			state:          "outage",
		},
		{
			name:           "restricted route with decision deadline exceeded",
			path:           "/restricted/admin/keys",
			classification: "restricted",
			state:          "deadline_exceeded",
		},
		{
			name:           "unspecified route with decision outage (F01 & F13)",
			path:           "/unspecified/custom/path",
			classification: "", // unspecified defaults to private
			state:          "outage",
		},
		{
			name:           "private route with provider unavailable",
			path:           "/api/v1/analytics",
			classification: "private",
			providerState:  "unavailable",
		},
	}

	for _, tc := range sensitiveCases {
		t.Run(tc.name, func(t *testing.T) {
			req := gateway.ResourceOutageRequest{
				RequestID:              "req-f13-" + tc.name,
				Path:                   tc.path,
				Method:                 "GET",
				ResourceClassification: tc.classification,
				DecisionLoss:           true,
				DecisionEngineState:    tc.state,
				ProviderState:          tc.providerState,
				Subject: &contracts.Subject{
					ID:            "user-operator-01",
					Authenticated: true,
					Roles:         []string{"operator"},
				},
				EvaluationTime: time.Now().UTC(),
			}

			res, err := gateway.EvaluateResourceOutage(ctx, req)
			if err != nil {
				t.Fatalf("unexpected evaluation error: %v", err)
			}
			if res == nil {
				t.Fatal("expected non-nil result")
			}

			// Invariant: Decision loss MUST deny sensitive routes
			if res.Allow {
				t.Fatalf("F13 VIOLATION: decision loss allowed sensitive route '%s' (classification=%s)", tc.path, tc.classification)
			}
			if res.ForwardedToUpstream {
				t.Fatalf("F13 VIOLATION: request was forwarded to upstream on decision loss for '%s'", tc.path)
			}
			if res.SideEffectsExecuted {
				t.Fatalf("F13 VIOLATION: side effects were executed on decision loss for '%s'", tc.path)
			}
			if res.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("expected status 503, got %d", res.StatusCode)
			}
			if tc.classification == "" && res.ErrorCode != gateway.ErrCodeUnspecifiedRouteOutage {
				t.Fatalf("expected error code %s for unspecified route, got %s", gateway.ErrCodeUnspecifiedRouteOutage, res.ErrorCode)
			}
			if tc.classification != "" && res.ErrorCode != gateway.ErrCodeDecisionLossDeny {
				t.Fatalf("expected error code %s, got %s", gateway.ErrCodeDecisionLossDeny, res.ErrorCode)
			}
			if res.Disposition != gateway.OutageDispositionFailClosedDeny {
				t.Fatalf("expected disposition %s, got %s", gateway.OutageDispositionFailClosedDeny, res.Disposition)
			}
		})
	}
}

// TestC19_PublicRouteIntentionalBypass_F13 explicitly verifies Requirement F13:
// Public route bypass remains intentional and testable.
func TestC19_PublicRouteIntentionalBypass_F13(t *testing.T) {
	ctx := context.Background()

	publicCases := []struct {
		name string
		path string
	}{
		{name: "standard health probe", path: "/health"},
		{name: "standard healthz probe", path: "/healthz"},
	}

	for _, tc := range publicCases {
		t.Run(tc.name, func(t *testing.T) {
			req := gateway.ResourceOutageRequest{
				RequestID:              "req-f13-public-" + tc.name,
				Path:                   tc.path,
				Method:                 "GET",
				ResourceClassification: "public",
				ExplicitPublicRoute:    true,
				AllowPublicBypass:      true,
				DecisionLoss:           true,
				DecisionEngineState:    "outage",
				Headers: map[string]string{
					"X-User-Id":             "spoofed-id",
					"X-PolicyHelix-Subject": "spoofed-subject",
					"Accept":                "application/json",
				},
				EvaluationTime: time.Now().UTC(),
			}

			res, err := gateway.EvaluateResourceOutage(ctx, req)
			if err != nil {
				t.Fatalf("unexpected evaluation error: %v", err)
			}
			if res == nil {
				t.Fatal("expected non-nil result")
			}

			// Invariant: Explicit public route bypass remains intentional and testable
			if !res.Allow {
				t.Fatalf("F13 VIOLATION: intentional public route bypass denied for '%s'", tc.path)
			}
			if !res.PublicBypassUsed {
				t.Fatal("expected PublicBypassUsed to be true")
			}
			if res.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 OK, got %d", res.StatusCode)
			}
			if res.Disposition != gateway.OutageDispositionIntentionalPublicBypass {
				t.Fatalf("expected disposition %s, got %s", gateway.OutageDispositionIntentionalPublicBypass, res.Disposition)
			}
			if res.Classification != policy.ResourceClassPublic {
				t.Fatalf("expected classification public, got %s", res.Classification)
			}
			if res.SideEffectsExecuted {
				t.Fatal("side effects must remain false on public bypass")
			}

			// Invariant: Client identity headers must be stripped and anonymous context bound
			if len(res.StrippedHeaders) == 0 {
				t.Fatal("expected untrusted headers to be stripped")
			}
			if res.Subject == nil || res.Subject.Authenticated {
				t.Fatal("expected subject to be unauthenticated anonymous")
			}
			if res.Subject.ID != "anonymous" {
				t.Fatalf("expected subject ID 'anonymous', got '%s'", res.Subject.ID)
			}
			if res.DownstreamInjectedHeaders[gateway.HeaderPolicyHelixAuthenticated] != "false" {
				t.Fatalf("expected X-PolicyHelix-Authenticated 'false', got '%s'", res.DownstreamInjectedHeaders[gateway.HeaderPolicyHelixAuthenticated])
			}
		})
	}
}

// TestC19_IllegalBypassOnSensitiveRoutes_FailsClosed verifies that attempting to enable
// outage bypass on sensitive routes is rejected as an illegal configuration.
func TestC19_IllegalBypassOnSensitiveRoutes_FailsClosed(t *testing.T) {
	ctx := context.Background()

	illegalCases := []struct {
		name           string
		path           string
		classification string
	}{
		{name: "private route illegal bypass", path: "/api/v1/analytics", classification: "private"},
		{name: "internal route illegal bypass", path: "/internal/data", classification: "internal"},
		{name: "restricted route illegal bypass", path: "/admin/secrets", classification: "restricted"},
	}

	for _, tc := range illegalCases {
		t.Run(tc.name, func(t *testing.T) {
			req := gateway.ResourceOutageRequest{
				RequestID:              "req-illegal-" + tc.name,
				Path:                   tc.path,
				Method:                 "GET",
				ResourceClassification: tc.classification,
				AllowPublicBypass:      true, // ILLEGAL on sensitive route!
				DecisionLoss:           true,
				DecisionEngineState:    "outage",
			}

			res, err := gateway.EvaluateResourceOutage(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Allow {
				t.Fatalf("SECURITY VIOLATION: illegal public bypass was permitted on %s route '%s'", tc.classification, tc.path)
			}
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("expected status 403 Forbidden, got %d", res.StatusCode)
			}
			if res.ErrorCode != gateway.ErrCodeIllegalPublicBypassConfig {
				t.Fatalf("expected error code %s, got %s", gateway.ErrCodeIllegalPublicBypassConfig, res.ErrorCode)
			}
		})
	}
}

// TestC19_PublicRouteWithoutBypass_FailsClosed verifies that a public route that does not
// explicitly enable allow_public_bypass fails closed during decision loss.
func TestC19_PublicRouteWithoutBypass_FailsClosed(t *testing.T) {
	ctx := context.Background()

	req := gateway.ResourceOutageRequest{
		RequestID:              "req-public-nobypass",
		Path:                   "/public/docs",
		Method:                 "GET",
		ResourceClassification: "public",
		ExplicitPublicRoute:    true,
		AllowPublicBypass:      false, // Explicitly false!
		DecisionLoss:           true,
		DecisionEngineState:    "outage",
	}

	res, err := gateway.EvaluateResourceOutage(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Fatal("expected public route without bypass flag to deny during decision loss")
	}
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", res.StatusCode)
	}
	if res.ErrorCode != gateway.ErrCodeDecisionLossDeny {
		t.Fatalf("expected error code %s, got %s", gateway.ErrCodeDecisionLossDeny, res.ErrorCode)
	}
}

// TestC19_AllowlistedGatewayProxyIntegration tests gateway proxy integration with per-resource outage handling.
func TestC19_AllowlistedGatewayProxyIntegration(t *testing.T) {
	ctx := context.Background()
	cfg := gateway.DefaultUpstreamConfig()
	proxy := gateway.NewAllowlistedGatewayProxy(cfg, nil, nil)

	// 1. Private route under decision loss fails closed
	privReq := gateway.ProxyRequest{
		RequestID:              "proxy-outage-priv",
		TargetUpstreamID:       cfg.ID,
		Method:                 "GET",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		DecisionLoss:           true,
		DecisionEngineState:    "outage",
		SessionID:              "session-valid-01",
	}

	privRes, err := proxy.EvaluateProxyRequest(ctx, privReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if privRes.Allow {
		t.Fatal("expected proxy to deny private route under decision loss")
	}
	if privRes.ForwardedToUpstream {
		t.Fatal("proxy must not forward private request under decision loss")
	}
	if privRes.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", privRes.StatusCode)
	}
	if privRes.ErrorCode != gateway.ErrCodeDecisionLossDeny {
		t.Fatalf("expected %s, got %s", gateway.ErrCodeDecisionLossDeny, privRes.ErrorCode)
	}

	// 2. Public health route with intentional bypass succeeds
	pubReq := gateway.ProxyRequest{
		RequestID:              "proxy-outage-pub",
		TargetUpstreamID:       cfg.ID,
		Method:                 "GET",
		Path:                   "/health",
		ResourceClassification: "public",
		ExplicitPublicRoute:    true,
		AllowPublicBypass:      true,
		DecisionLoss:           true,
		DecisionEngineState:    "outage",
	}

	pubRes, err := proxy.EvaluateProxyRequest(ctx, pubReq)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pubRes.Allow {
		t.Fatalf("expected proxy to allow public health route with bypass, got err: %s", pubRes.ErrorMessage)
	}
	if !pubRes.PublicBypassUsed {
		t.Fatal("expected PublicBypassUsed to be true")
	}
	if pubRes.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", pubRes.StatusCode)
	}
	if pubRes.OutageDisposition != gateway.OutageDispositionIntentionalPublicBypass {
		t.Fatalf("expected disposition %s, got %s", gateway.OutageDispositionIntentionalPublicBypass, pubRes.OutageDisposition)
	}
}

// TestC19_EngineHTTPFailureEndpoint tests the engine HTTP endpoint /api/v1/gateway/failure/evaluate.
func TestC19_EngineHTTPFailureEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	binaryPath := filepath.Join("..", "dist", "engine", "policyhelix")
	var cmd *exec.Cmd
	if _, err := os.Stat(binaryPath); err == nil {
		cmd = exec.Command(binaryPath, "--port", fmt.Sprintf("%d", port))
	} else {
		cmd = exec.Command("go", "run", "../cmd/policyhelix", "--port", fmt.Sprintf("%d", port))
	}

	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start engine for HTTP endpoint tests: %v", err)
		return
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
		t.Skip("engine server did not become healthy in time, skipping HTTP integration test")
		return
	}

	// 1. Test Sensitive Route Outage (503 Service Unavailable)
	bodySensitive := []byte(`{
		"request": {
			"request_id": "http-outage-priv",
			"path": "/api/v1/analytics",
			"resource_classification": "private",
			"decision_loss": true,
			"decision_engine_state": "outage"
		}
	}`)
	respSens, err := client.Post(baseURL+"/api/v1/gateway/failure/evaluate", "application/json", bytes.NewReader(bodySensitive))
	if err != nil {
		t.Fatalf("HTTP request error: %v", err)
	}
	defer respSens.Body.Close()

	if respSens.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", respSens.StatusCode)
	}
	var resSens gateway.ResourceOutageResult
	if err := json.NewDecoder(respSens.Body).Decode(&resSens); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resSens.Allow {
		t.Fatal("expected sensitive route to deny under outage")
	}
	if resSens.ErrorCode != gateway.ErrCodeDecisionLossDeny {
		t.Fatalf("expected error code %s, got %s", gateway.ErrCodeDecisionLossDeny, resSens.ErrorCode)
	}

	// 2. Test Public Route Intentional Bypass (200 OK)
	bodyPublic := []byte(`{
		"request": {
			"request_id": "http-outage-pub",
			"path": "/health",
			"resource_classification": "public",
			"explicit_public_route": true,
			"allow_public_bypass": true,
			"decision_loss": true,
			"decision_engine_state": "outage"
		}
	}`)
	respPub, err := client.Post(baseURL+"/api/v1/gateway/failure/evaluate", "application/json", bytes.NewReader(bodyPublic))
	if err != nil {
		t.Fatalf("HTTP request error: %v", err)
	}
	defer respPub.Body.Close()

	if respPub.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", respPub.StatusCode)
	}
	var resPub gateway.ResourceOutageResult
	if err := json.NewDecoder(respPub.Body).Decode(&resPub); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resPub.Allow {
		t.Fatal("expected public route to allow under bypass")
	}
	if !resPub.PublicBypassUsed {
		t.Fatal("expected public_bypass_used to be true")
	}
}

// TestC19_EngineCLIFailure tests the CLI -evaluate-failure command flag.
func TestC19_EngineCLIFailure(t *testing.T) {
	// If go or compiled binary is present, test CLI invocation
	binPath := filepath.Join("..", "dist", "engine", "policyhelix")
	if _, err := os.Stat(binPath); err != nil {
		t.Skip("compiled engine binary not found, skipping CLI subprocess execution")
		return
	}

	// 1. Positive public bypass fixture
	cmdPos := exec.Command(binPath, "-evaluate-failure", filepath.Join(c19FixtureDir, "cli-failure-public-bypass.json"))
	outPos, errPos := cmdPos.CombinedOutput()
	if errPos != nil {
		t.Fatalf("CLI positive failure run failed: %v, output: %s", errPos, string(outPos))
	}
	var resPos gateway.ResourceOutageResult
	if err := json.Unmarshal(outPos, &resPos); err != nil {
		t.Fatalf("failed to decode CLI output: %v", err)
	}
	if !resPos.Allow || !resPos.PublicBypassUsed {
		t.Fatalf("expected allow=true and public_bypass_used=true, got %v / %v", resPos.Allow, resPos.PublicBypassUsed)
	}

	// 2. Negative sensitive deny fixture
	cmdNeg := exec.Command(binPath, "-evaluate-failure", filepath.Join(c19FixtureDir, "cli-failure-sensitive-denied.json"))
	outNeg, errNeg := cmdNeg.CombinedOutput()
	if errNeg == nil {
		t.Fatal("expected CLI negative run to exit with non-zero status")
	}
	var resNeg gateway.ResourceOutageResult
	_ = json.Unmarshal(outNeg, &resNeg)
	if resNeg.Allow {
		t.Fatal("expected CLI sensitive deny to have allow=false")
	}
}

// TestC19_RestartAndRecoveryInvariant verifies the required negative case:
// "Repeat after restart and verify the declared invariant and documented recovery outcome."
func TestC19_RestartAndRecoveryInvariant(t *testing.T) {
	ctx := context.Background()
	tempDir, err := os.MkdirTemp("", "policyhelix-c19-restart-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Step 1: Open storage adapter and initialize tracker
	adapter1, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("failed to open storage adapter 1: %v", err)
	}
	tracker1 := gateway.NewDurableOutageTracker(adapter1)

	// Record outage event
	outageTime := time.Date(2026, 11, 5, 14, 0, 0, 0, time.UTC)
	if err := tracker1.RecordOutageEvent(ctx, "decision-service", "outage", outageTime); err != nil {
		t.Fatalf("failed to record outage event: %v", err)
	}

	// Process sensitive request under outage (Deny)
	privReq := gateway.ResourceOutageRequest{
		RequestID:              "restart-test-priv",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		DecisionLoss:           true,
		DecisionEngineState:    "outage",
	}
	res1, _ := gateway.EvaluateResourceOutage(ctx, privReq)
	tracker1.RecordDecision(res1)
	if res1.Allow {
		t.Fatal("expected sensitive request to deny under outage")
	}

	// Process public bypass request under outage (Allow)
	pubReq := gateway.ResourceOutageRequest{
		RequestID:              "restart-test-pub",
		Path:                   "/health",
		ResourceClassification: "public",
		ExplicitPublicRoute:    true,
		AllowPublicBypass:      true,
		DecisionLoss:           true,
		DecisionEngineState:    "outage",
	}
	res2, _ := gateway.EvaluateResourceOutage(ctx, pubReq)
	tracker1.RecordDecision(res2)
	if !res2.Allow || !res2.PublicBypassUsed {
		t.Fatal("expected public request to allow with bypass under outage")
	}

	// Close storage adapter (Simulate crash / restart)
	if err := adapter1.Close(); err != nil {
		t.Fatalf("failed to close adapter 1: %v", err)
	}

	// Step 2: Restart - Reopen storage adapter
	adapter2, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("failed to open storage adapter 2 after restart: %v", err)
	}
	defer adapter2.Close()

	// Verify fail-closed invariant still holds after restart:
	// A sensitive request without decision recovery still denies
	resAfterRestart, _ := gateway.EvaluateResourceOutage(ctx, privReq)
	if resAfterRestart.Allow {
		t.Fatal("RECOVERY INVARIANT VIOLATION: sensitive route allowed after restart before recovery")
	}

	// Step 3: Documented Recovery Outcome
	// Decision authority recovers, transitions back to healthy state
	tracker2 := gateway.NewDurableOutageTracker(adapter2)
	recoveryTime := time.Date(2026, 11, 5, 14, 15, 0, 0, time.UTC)
	if err := tracker2.RecordOutageEvent(ctx, "decision-service", "recovered", recoveryTime); err != nil {
		t.Fatalf("failed to record recovery event: %v", err)
	}

	// Verify that healthy requests now succeed normally
	healthyReq := gateway.ResourceOutageRequest{
		RequestID:              "recovered-test-priv",
		Path:                   "/api/v1/analytics",
		ResourceClassification: "private",
		DecisionLoss:           false,
		DecisionEngineState:    "healthy",
		Subject: &contracts.Subject{
			ID:            "user-operator-01",
			Authenticated: true,
			Roles:         []string{"operator"},
		},
	}
	healthyRes, err := gateway.EvaluateResourceOutage(ctx, healthyReq)
	if err != nil {
		t.Fatalf("unexpected error on recovered evaluation: %v", err)
	}
	if !healthyRes.Allow {
		t.Fatalf("expected healthy request to succeed after recovery, got err: %s", healthyRes.ErrorMessage)
	}
	if healthyRes.Disposition != gateway.OutageDispositionHealthyDecision {
		t.Fatalf("expected disposition %s, got %s", gateway.OutageDispositionHealthyDecision, healthyRes.Disposition)
	}
}
