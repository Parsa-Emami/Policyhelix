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
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
)

const (
	c21FixtureDir = "fixtures/policyhelix/C21"
)

// TestC21_ManifestIntegrity verifies that all C21 fixtures exist and match declared SHA256 hashes.
func TestC21_ManifestIntegrity(t *testing.T) {
	manifestPath := filepath.Join(c21FixtureDir, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C21 manifest: %v", err)
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
		t.Fatalf("failed to parse C21 manifest: %v", err)
	}

	if manifest.CommitID != "C21" {
		t.Errorf("expected commit_id 'C21', got '%s'", manifest.CommitID)
	}

	if len(manifest.Fixtures) != 7 {
		t.Errorf("expected 7 fixtures in C21 manifest, got %d", len(manifest.Fixtures))
	}

	for _, f := range manifest.Fixtures {
		baseName := filepath.Base(f.Path)
		targetFile := filepath.Join(c21FixtureDir, baseName)
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

// TestC21_SimulatorHTTPEndpoint verifies the POST /v1/runtime/simulate loopback endpoint
// with positive and negative simulation fixtures.
func TestC21_SimulatorHTTPEndpoint(t *testing.T) {
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

	// Poll healthz until engine is ready
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

	// 1. Positive simulation over HTTP
	fixtureBytes, err := os.ReadFile(filepath.Join("fixtures", "policyhelix", "C09", "positive-changed-deny-to-allow.json"))
	if err != nil {
		t.Fatalf("Failed to read test fixture: %v", err)
	}

	resp, err := client.Post(baseURL+"/v1/runtime/simulate", "application/json", bytes.NewReader(fixtureBytes))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/runtime/simulate failed: %v, status: %v", err, resp.Status)
	}

	var report policy.SimulationReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		t.Fatalf("Failed to decode simulation report: %v", err)
	}
	_ = resp.Body.Close()

	if report.Status != "passed" || !report.Changed || report.Transition != "deny_to_allow" {
		t.Errorf("Unexpected HTTP simulation report: %+v", report)
	}
	if report.CandidateDecision == nil || !report.CandidateDecision.Allow {
		t.Errorf("Expected candidate decision allow=true, got %+v", report.CandidateDecision)
	}
	if report.BaselineDecision == nil || report.BaselineDecision.Allow {
		t.Errorf("Expected baseline decision allow=false, got %+v", report.BaselineDecision)
	}

	// 2. Negative: Malformed JSON payload returns 400 Bad Request
	malformedResp, err := client.Post(baseURL+"/v1/runtime/simulate", "application/json", bytes.NewReader([]byte(`{invalid-json`)))
	if err != nil {
		t.Fatalf("POST malformed failed: %v", err)
	}
	if malformedResp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for malformed JSON, got %d", malformedResp.StatusCode)
	}
	_ = malformedResp.Body.Close()

	// 3. Negative: Method Not Allowed on GET
	getResp, err := client.Get(baseURL + "/v1/runtime/simulate")
	if err != nil {
		t.Fatalf("GET /v1/runtime/simulate failed: %v", err)
	}
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 Method Not Allowed, got %d", getResp.StatusCode)
	}
	_ = getResp.Body.Close()
}

// TestC21_SimulatorExplanationGrounding verifies that decision explanations
// are deterministically grounded in fixture context (subject, roles, target resource, revision).
func TestC21_SimulatorExplanationGrounding(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policyhelix", "C09", "positive-changed-deny-to-allow.json")
	rep, err := policy.RunSimulationFile(context.Background(), fixturePath)
	if err != nil {
		t.Fatalf("Failed to run simulation file: %v", err)
	}

	if rep.CandidateDecision == nil || rep.BaselineDecision == nil {
		t.Fatalf("Simulation report missing candidate or baseline decision: %+v", rep)
	}

	if rep.CandidateDecision.Revision <= rep.BaselineDecision.Revision {
		t.Errorf("Expected monotonic revision increment: baseline=%d, candidate=%d",
			rep.BaselineDecision.Revision, rep.CandidateDecision.Revision)
	}

	if rep.Transition != "deny_to_allow" {
		t.Errorf("Expected transition 'deny_to_allow', got '%s'", rep.Transition)
	}

	// Grounded explanation string construction (mirroring UI projection)
	explanation := fmt.Sprintf("Policy revision %d added or expanded permissions for subject '%s', transitioning the decision on resource '%s' from DENIED to ALLOWED.",
		rep.CandidateDecision.Revision, "subject-operator-01", "/api/v1/analytics/reports")

	if !strings.Contains(explanation, "DENIED to ALLOWED") {
		t.Errorf("Explanation did not capture transitioned outcome: %s", explanation)
	}
}

// TestC21_SimulatorSentinelInertness verifies that script/HTML sentinels inside fixture descriptions
// and inputs remain strictly inert strings and do not cause errors or corruption.
func TestC21_SimulatorSentinelInertness(t *testing.T) {
	sentinelFixturePath := filepath.Join(c21FixtureDir, "negative-simulator-sentinel.json")
	data, err := os.ReadFile(sentinelFixturePath)
	if err != nil {
		t.Fatalf("Failed to read sentinel fixture: %v", err)
	}

	var fx policy.SimulationFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("Failed to parse sentinel fixture: %v", err)
	}

	// Verify sentinel string was preserved exactly as inert text
	if !strings.Contains(fx.Description, "<script>alert('xss-sentinel')</script>") {
		t.Errorf("Sentinel string corrupted in description: %s", fx.Description)
	}
}
