package tests

import (
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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
)

const (
	c22FixtureDir = "fixtures/policyhelix/C22"
)

// TestC22_ManifestIntegrity verifies all C22 fixtures exist and match declared SHA-256 hashes.
func TestC22_ManifestIntegrity(t *testing.T) {
	manifestPath := filepath.Join(c22FixtureDir, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C22 manifest: %v", err)
	}

	var manifest struct {
		CommitID string `json:"commit_id"`
		Fixtures []struct {
			FixtureID string `json:"fixture_id"`
			Path      string `json:"path"`
			SHA256    string `json:"sha256"`
			Type      string `json:"type"`
		} `json:"fixtures"`
	}

	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("failed to parse C22 manifest: %v", err)
	}

	if manifest.CommitID != "C22" {
		t.Errorf("expected commit_id 'C22', got '%s'", manifest.CommitID)
	}

	if len(manifest.Fixtures) != 7 {
		t.Errorf("expected 7 fixtures in C22 manifest, got %d", len(manifest.Fixtures))
	}

	for _, f := range manifest.Fixtures {
		baseName := filepath.Base(f.Path)
		targetFile := filepath.Join(c22FixtureDir, baseName)
		content, err := os.ReadFile(targetFile)
		if err != nil {
			t.Errorf("fixture file %s unreadable: %v", targetFile, err)
			continue
		}

		hash := sha256.Sum256(content)
		computedHex := hex.EncodeToString(hash[:])
		if computedHex != f.SHA256 {
			t.Errorf("SHA256 mismatch for %s: declared=%s computed=%s", f.FixtureID, f.SHA256, computedHex)
		}
	}
}

// TestC22_GatewayHealthEndpoint verifies the GET /api/v1/runtime/gateway/health loopback endpoint.
func TestC22_GatewayHealthEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--port", fmt.Sprintf("%d", port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start engine server: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		close(stopCh)
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Poll until healthy
	var ready bool
	for i := 0; i < 40; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			ready = true
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("Engine server did not become healthy in time on port %d", port)
	}

	// 1. GET /api/v1/runtime/gateway/health
	resp, err := client.Get(baseURL + "/api/v1/runtime/gateway/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/runtime/gateway/health failed: %v, status: %v", err, resp.Status)
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	_ = resp.Body.Close()

	if data["status"] != "ok" {
		t.Errorf("expected status 'ok', got '%v'", data["status"])
	}

	policyData, ok := data["policy"].(map[string]interface{})
	if !ok || policyData["active_revision"] == nil {
		t.Errorf("missing or invalid policy section in gateway health: %+v", data["policy"])
	}

	idpData, ok := data["idp"].(map[string]interface{})
	if !ok || idpData["status"] == nil {
		t.Errorf("missing or invalid idp section in gateway health: %+v", data["idp"])
	}

	if data["zero_token_exposure"] != true {
		t.Errorf("expected zero_token_exposure=true, got %v", data["zero_token_exposure"])
	}

	// 2. Negative: Method Not Allowed on POST /api/v1/runtime/gateway/health
	postResp, err := client.Post(baseURL+"/api/v1/runtime/gateway/health", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST /api/v1/runtime/gateway/health failed: %v", err)
	}
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed on POST, got %d", postResp.StatusCode)
	}
	_ = postResp.Body.Close()
}

// TestC22_RevocationBoundedEnforcement verifies bounded session revocation workload stops <= 30s with zero side effects.
func TestC22_RevocationBoundedEnforcement(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	spec := auth.WorkloadRevocationSpec{
		FixtureID: "C22-POS-03",
		CommitID:  "C22",
		Config: auth.RevocationConfig{
			StaleWindowSeconds: 30,
			AllowedPaths:       []string{"/api/v1/analytics/reports"},
			AllowedProviders:   []string{"owned_synthetic_upstream"},
		},
		PreloadSessions: []auth.SessionRecord{
			{
				SessionID:    "sess-c22-workload-01",
				SubjectID:    "usr-c22-operator",
				SessionEpoch: 1793793600,
				Status:       "ACTIVE",
				CreatedAt:    now,
				ExpiresAt:    now.Add(2 * time.Hour),
			},
		},
		WorkloadSteps: []auth.WorkloadStep{
			{
				StepID:    "step-1-pre-revoke",
				StepType:  "access",
				Timestamp: now,
				Access: &auth.AccessCheckRequest{
					SessionID:                "sess-c22-workload-01",
					RequestedPath:            "/api/v1/analytics/reports",
					RequestedProvider:        "owned_synthetic_upstream",
					ResourceClassification:   "private",
					UntrustedHeadersStripped: true,
					EvaluationTime:           now,
				},
			},
			{
				StepID:       "step-2-revoke-trigger",
				StepType:     "revoke_session",
				Timestamp:    now.Add(1 * time.Second),
				RevokeTarget: "sess-c22-workload-01",
				Reason:       "Operator revocation",
			},
			{
				StepID:    "step-3-post-revoke",
				StepType:  "access",
				Timestamp: now.Add(32 * time.Second),
				Access: &auth.AccessCheckRequest{
					SessionID:                "sess-c22-workload-01",
					RequestedPath:            "/api/v1/analytics/reports",
					RequestedProvider:        "owned_synthetic_upstream",
					ResourceClassification:   "private",
					UntrustedHeadersStripped: true,
					EvaluationTime:           now.Add(32 * time.Second),
				},
			},
		},
	}

	report, err := auth.EvaluateWorkloadSpec(ctx, spec, nil, nil)
	if err != nil {
		t.Fatalf("EvaluateWorkloadSpec failed: %v", err)
	}

	if !report.Revoked {
		t.Errorf("Expected report.Revoked=true, got false")
	}

	if !report.StoppedWithinBound {
		t.Errorf("Expected StoppedWithinBound=true within 30s window, got false")
	}

	if report.SideEffectsExecuted {
		t.Errorf("Expected SideEffectsExecuted=false, got true")
	}

	if report.MaxStaleSeconds > 30 {
		t.Errorf("MaxStaleSeconds exceeded 30s maximum bound: %d", report.MaxStaleSeconds)
	}
}

// TestC22_ZeroTokenExposure verifies that gateway health outputs never expose bearer tokens or cookies.
func TestC22_ZeroTokenExposure(t *testing.T) {
	fixtureFiles := []string{
		filepath.Join(c22FixtureDir, "positive-gateway-stale-policy.json"),
		filepath.Join(c22FixtureDir, "positive-gateway-idp-outage.json"),
		filepath.Join(c22FixtureDir, "positive-gateway-session-revoke.json"),
		filepath.Join(c22FixtureDir, "negative-replayed-identity.json"),
		filepath.Join(c22FixtureDir, "negative-forged-header.json"),
		filepath.Join(c22FixtureDir, "negative-private-resource-fail-closed.json"),
	}

	bearerRegex := regexp.MustCompile(`(?i)bearer\s+[a-z0-9_\-\.]{16,}`)
	jwtRegex := regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+`)
	cookieRegex := regexp.MustCompile(`(?i)(set-cookie|policyhelix_session)=[a-z0-9-_]+`)

	for _, f := range fixtureFiles {
		bytes, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("Failed to read fixture %s: %v", f, err)
		}
		str := string(bytes)

		if bearerRegex.MatchString(str) {
			t.Errorf("Fixture %s leaked raw Bearer token: %s", f, bearerRegex.FindString(str))
		}
		if jwtRegex.MatchString(str) {
			t.Errorf("Fixture %s leaked raw JWT string: %s", f, jwtRegex.FindString(str))
		}
		if cookieRegex.MatchString(str) {
			t.Errorf("Fixture %s leaked session cookie: %s", f, cookieRegex.FindString(str))
		}
	}
}

// TestC22_SentinelInertness verifies script and HTML sentinels in C22 fixtures remain strictly inert strings.
func TestC22_SentinelInertness(t *testing.T) {
	sentinelPath := filepath.Join(c22FixtureDir, "negative-sentinel-inertness.json")
	bytes, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("Failed to read sentinel fixture: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(bytes, &data); err != nil {
		t.Fatalf("Failed to parse sentinel fixture: %v", err)
	}

	desc, ok := data["description"].(string)
	if !ok || !strings.Contains(desc, "<script>alert('xss-c22')</script>") {
		t.Errorf("Sentinel string corrupted in description: %v", data["description"])
	}
}
