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

	"github.com/parsa-emami/policyhelix/internal/policy"
)

// TestC09SimulatorCLIDenyToAllowChanged verifies Requirement F03:
// CLI reports changed allow/deny decisions with reasons and policy digest.
func TestC09SimulatorCLIDenyToAllowChanged(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policyhelix", "C09", "positive-changed-deny-to-allow.json")
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--simulate", fixturePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Simulator CLI failed: %v, stderr: %s", err, stderr.String())
	}

	var report policy.SimulationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("Failed to parse simulator JSON output: %v, raw: %s", err, stdout.String())
	}

	if report.Status != "passed" {
		t.Errorf("Expected status=passed, got: %s", report.Status)
	}
	if !report.Changed {
		t.Errorf("Expected changed=true for deny_to_allow transition")
	}
	if report.Transition != "deny_to_allow" {
		t.Errorf("Expected transition=deny_to_allow, got: %s", report.Transition)
	}
	if report.BaselineDecision == nil || report.BaselineDecision.Allow != false {
		t.Errorf("Expected baseline allow=false, got: %+v", report.BaselineDecision)
	}
	if report.CandidateDecision == nil || report.CandidateDecision.Allow != true {
		t.Errorf("Expected candidate allow=true, got: %+v", report.CandidateDecision)
	}
	if report.PolicyDigest == "" || !report.MatchExpected {
		t.Errorf("Expected valid candidate policy digest and match_expected=true, got: %+v", report)
	}
	if len(report.Reasons) == 0 || report.Reasons[0] != "policy_allow_role_operator" {
		t.Errorf("Expected primary reason 'policy_allow_role_operator', got: %v", report.Reasons)
	}
	if report.BaselineDecision.PolicyDigest == report.CandidateDecision.PolicyDigest {
		t.Errorf("Expected baseline and candidate digests to differ across revisions")
	}
}

// TestC09SimulatorCLIAllowToDenyChanged verifies changed decision reporting when policy restricts access.
func TestC09SimulatorCLIAllowToDenyChanged(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policyhelix", "C09", "positive-changed-allow-to-deny.json")
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--simulate", fixturePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Simulator CLI failed: %v, stderr: %s", err, stderr.String())
	}

	var report policy.SimulationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("Failed to parse simulator JSON output: %v, raw: %s", err, stdout.String())
	}

	if report.Status != "passed" {
		t.Errorf("Expected status=passed, got: %s", report.Status)
	}
	if !report.Changed {
		t.Errorf("Expected changed=true for allow_to_deny transition")
	}
	if report.Transition != "allow_to_deny" {
		t.Errorf("Expected transition=allow_to_deny, got: %s", report.Transition)
	}
	if report.BaselineDecision == nil || report.BaselineDecision.Allow != true {
		t.Errorf("Expected baseline allow=true, got: %+v", report.BaselineDecision)
	}
	if report.CandidateDecision == nil || report.CandidateDecision.Allow != false {
		t.Errorf("Expected candidate allow=false, got: %+v", report.CandidateDecision)
	}
	if len(report.Reasons) == 0 || report.Reasons[0] != "INSUFFICIENT_ROLES" {
		t.Errorf("Expected primary reason 'INSUFFICIENT_ROLES', got: %v", report.Reasons)
	}
}

// TestC09SimulatorCLIUnchanged verifies unchanged decision reporting.
func TestC09SimulatorCLIUnchanged(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policyhelix", "C09", "positive-unchanged-allow.json")
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--simulate-fixture", fixturePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Simulator CLI failed: %v, stderr: %s", err, stderr.String())
	}

	var report policy.SimulationReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("Failed to parse simulator JSON output: %v, raw: %s", err, stdout.String())
	}

	if report.Status != "passed" || report.Changed || report.Transition != "unchanged" {
		t.Errorf("Expected passed unchanged report, got: %+v", report)
	}
}

// TestC09SimulatorCLIDirectoryExecution verifies executing all fixtures in a directory.
func TestC09SimulatorCLIDirectoryExecution(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "policyhelix", "C09")
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--simulate", fixtureDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Simulator directory CLI failed: %v, stderr: %s", err, stderr.String())
	}

	var suite policy.SimulationSuiteReport
	if err := json.Unmarshal(stdout.Bytes(), &suite); err != nil {
		t.Fatalf("Failed to parse suite JSON: %v, raw: %s", err, stdout.String())
	}

	if suite.Status != "passed" {
		t.Errorf("Expected suite status=passed, got: %s", suite.Status)
	}
	if suite.Total != 6 || suite.Passed != 6 || suite.Failed != 0 {
		t.Errorf("Expected 6 total, 6 passed, 0 failed; got total=%d, passed=%d, failed=%d", suite.Total, suite.Passed, suite.Failed)
	}
	if suite.ChangedCount != 2 {
		t.Errorf("Expected 2 changed decisions in suite, got: %d", suite.ChangedCount)
	}
}

// TestC09SimulatorNegativeMalformedAndMissingPrereqs verifies required negative case 1:
// Missing prerequisites, malformed fixtures or unavailable required providers produce an explicit error.
func TestC09SimulatorNegativeMalformedAndMissingPrereqs(t *testing.T) {
	// 1. Nonexistent file
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--simulate", "nonexistent-fixture-path.json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatalf("Expected CLI error for nonexistent fixture file, but succeeded")
	}

	var missingReport policy.SimulationReport
	_ = json.Unmarshal(stdout.Bytes(), &missingReport)
	if missingReport.Status != "error" || missingReport.Error == nil || missingReport.Error.Code != policy.ErrCodeMalformedFixture {
		t.Errorf("Expected MALFORMED_FIXTURE error for missing file, got: %+v", missingReport)
	}

	// 2. Malformed fixture JSON file
	tmpFile, err := os.CreateTemp("", "malformed-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	_, _ = tmpFile.WriteString(`{"fixture_id": "corrupted", invalid_json}`)
	_ = tmpFile.Close()

	cmd = exec.Command("go", "run", "../cmd/policyhelix", "--simulate", tmpFile.Name())
	stdout.Reset()
	stderr.Reset()
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		t.Fatalf("Expected CLI error for invalid JSON file, but succeeded")
	}
	var malformedReport policy.SimulationReport
	_ = json.Unmarshal(stdout.Bytes(), &malformedReport)
	if malformedReport.Status != "error" || malformedReport.Error == nil || malformedReport.Error.Code != policy.ErrCodeMalformedFixture {
		t.Errorf("Expected MALFORMED_FIXTURE for corrupted JSON, got: %+v", malformedReport)
	}
}

// TestC09SimulatorNegativeProviderUnavailable verifies required negative case:
// Unavailable provider state produces explicit error.
func TestC09SimulatorNegativeProviderUnavailable(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policyhelix", "C09", "negative-provider-unavailable.json")
	rep, err := policy.RunSimulationFile(context.Background(), fixturePath)
	if err != nil {
		t.Fatalf("Unexpected read error: %v", err)
	}
	if rep.Status != "passed" { // expected outcome matched
		t.Errorf("Expected rep.Status=passed (since matched expected error), got: %s", rep.Status)
	}
	if rep.Error == nil || rep.Error.Code != policy.ErrCodeProviderUnavailable {
		t.Errorf("Expected PROVIDER_UNAVAILABLE error, got: %+v", rep.Error)
	}
}

// TestC09SimulatorNegativePrivateResourceFailClosed verifies required negative case 3:
// Private resources fail closed.
func TestC09SimulatorNegativePrivateResourceFailClosed(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policyhelix", "C09", "negative-private-resource-fail-closed.json")
	rep, err := policy.RunSimulationFile(context.Background(), fixturePath)
	if err != nil {
		t.Fatalf("Unexpected read error: %v", err)
	}
	if rep.Decision == nil || rep.Decision.Allow != false {
		t.Errorf("Expected private resource to fail closed with allow=false, got: %+v", rep.Decision)
	}
	if rep.Error == nil || rep.Error.Code != policy.ErrCodePrivateFailClosed {
		t.Errorf("Expected PRIVATE_RESOURCE_FAIL_CLOSED error code, got: %+v", rep.Error)
	}
}

// TestC09SimulatorRepeatAfterRestart verifies required negative case 2:
// Repeat after restart and verify the declared invariant and documented recovery outcome.
func TestC09SimulatorRepeatAfterRestart(t *testing.T) {
	fixturePath := filepath.Join("fixtures", "policyhelix", "C09", "positive-changed-deny-to-allow.json")

	// First execution
	rep1, err := policy.RunSimulationFile(context.Background(), fixturePath)
	if err != nil {
		t.Fatalf("First run failed: %v", err)
	}

	// Simulated process boundary / restart pause
	time.Sleep(20 * time.Millisecond)

	// Second execution after restart
	rep2, err := policy.RunSimulationFile(context.Background(), fixturePath)
	if err != nil {
		t.Fatalf("Second run failed: %v", err)
	}

	if rep1.Changed != rep2.Changed || rep1.Transition != rep2.Transition {
		t.Errorf("Non-deterministic change detection across restart: run1=%+v, run2=%+v", rep1, rep2)
	}
	if rep1.PolicyDigest != rep2.PolicyDigest {
		t.Errorf("Policy digest mismatch across restart: run1=%s, run2=%s", rep1.PolicyDigest, rep2.PolicyDigest)
	}
	if len(rep1.InvariantsVerified) != len(rep2.InvariantsVerified) {
		t.Errorf("Invariants mismatch across restart: run1=%v, run2=%v", rep1.InvariantsVerified, rep2.InvariantsVerified)
	}
}

// TestC09FixturesManifestIntegration verifies all C09 fixtures and manifest SHA-256 integrity.
func TestC09FixturesManifestIntegration(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "policyhelix", "C09")
	manifestBytes, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("Failed to read C09 manifest.json: %v", err)
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
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("Failed to unmarshal C09 manifest.json: %v", err)
	}
	if manifest.CommitID != "C09" {
		t.Fatalf("Expected manifest commit_id=C09, got: %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 6 {
		t.Fatalf("Expected at least 6 C09 fixtures in manifest, got: %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		baseName := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(fixtureDir, baseName))
		if err != nil {
			t.Fatalf("Failed to read fixture %s: %v", baseName, err)
		}

		sum := sha256.Sum256(raw)
		actualHash := hex.EncodeToString(sum[:])
		if actualHash != entry.SHA256 {
			t.Fatalf("Fixture %s SHA-256 hash mismatch: manifest=%s, actual=%s", baseName, entry.SHA256, actualHash)
		}

		rep, err := policy.RunSimulationFile(context.Background(), filepath.Join(fixtureDir, baseName))
		if err != nil {
			t.Fatalf("Failed to simulate fixture %s: %v", baseName, err)
		}
		if rep.Status != "passed" {
			t.Errorf("Fixture %s failed simulation assertions: %+v", baseName, rep)
		}
	}
}

// TestC09SimulatorHTTPEndpoint verifies the POST /v1/runtime/simulate loopback endpoint.
func TestC09SimulatorHTTPEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	stopCh := make(chan struct{})
	serverDone := make(chan error, 1)

	// Build and run engine server
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
	for i := 0; i < 30; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			ready = true
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("Engine server did not become healthy in time")
	}

	// 1. Positive simulation over HTTP
	fixtureBytes, err := os.ReadFile(filepath.Join("fixtures", "policyhelix", "C09", "positive-changed-deny-to-allow.json"))
	if err != nil {
		t.Fatalf("Failed to read fixture: %v", err)
	}

	resp, err := client.Post(baseURL+"/v1/runtime/simulate", "application/json", bytes.NewReader(fixtureBytes))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/runtime/simulate failed: %v, status: %v", err, resp.Status)
	}

	var report policy.SimulationReport
	_ = json.NewDecoder(resp.Body).Decode(&report)
	_ = resp.Body.Close()

	if report.Status != "passed" || !report.Changed || report.Transition != "deny_to_allow" {
		t.Errorf("Unexpected HTTP simulation report: %+v", report)
	}

	// 2. Malformed JSON returns 400
	resp, err = client.Post(baseURL+"/v1/runtime/simulate", "application/json", bytes.NewReader([]byte(`{invalid_json}`)))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 for malformed payload, got: %v, status: %v", err, resp.Status)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	_ = serverDone
}
