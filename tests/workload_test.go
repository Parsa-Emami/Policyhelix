package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/gateway"
)

type c28ManifestEntry struct {
	FixtureID string `json:"fixture_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Type      string `json:"type"`
	License   string `json:"license"`
}

type c28Manifest struct {
	SchemaVersion string             `json:"schema_version"`
	CommitID      string             `json:"commit_id"`
	Description   string             `json:"description"`
	License       string             `json:"license"`
	Fixtures      []c28ManifestEntry `json:"fixtures"`
}

func TestC28_ManifestIntegrityAndFixtureEvaluation(t *testing.T) {
	manifestPath := filepath.Join("fixtures", "policyhelix", "C28", "manifest.json")
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C28 manifest: %v", err)
	}

	var manifest c28Manifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C28 manifest: %v", err)
	}

	if manifest.CommitID != "C28" || manifest.License != "Apache-2.0" {
		t.Fatalf("expected commit_id C28 and Apache-2.0, got commit_id=%q license=%q", manifest.CommitID, manifest.License)
	}
	if len(manifest.Fixtures) < 10 {
		t.Fatalf("expected at least 10 fixtures in C28 manifest, got %d", len(manifest.Fixtures))
	}

	rootDir := filepath.Clean("..")
	for _, entry := range manifest.Fixtures {
		if entry.License != "Apache-2.0" {
			t.Fatalf("fixture %s must have Apache-2.0 license, got %q", entry.FixtureID, entry.License)
		}

		fullPath := filepath.Join(rootDir, filepath.FromSlash(entry.Path))
		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("failed to read fixture %s at %s: %v", entry.FixtureID, fullPath, err)
		}

		sum := sha256.Sum256(rawBytes)
		expectedDigest := hex.EncodeToString(sum[:])
		if entry.SHA256 != expectedDigest {
			t.Fatalf("digest mismatch for %s: manifest=%s actual=%s", entry.FixtureID, entry.SHA256, expectedDigest)
		}

		var fx gateway.BenchmarkWorkloadFixture
		if err := json.Unmarshal(rawBytes, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", entry.FixtureID, err)
		}

		rep, evalErr := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), fx)
		if evalErr != nil {
			t.Fatalf("fixture %s (%s) failed evaluation: %v (report=%+v)", entry.FixtureID, fx.WorkloadType, evalErr, rep)
		}
		if !rep.Passed {
			t.Fatalf("fixture %s (%s) passed=false, violations: %v", entry.FixtureID, fx.WorkloadType, rep.Violations)
		}
	}
}

func TestC28_BoundedTargetWorkloadAndLatencySLO(t *testing.T) {
	fixturePath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C28", "positive-target-bounded-workload.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read target bounded fixture: %v", err)
	}

	var fx gateway.BenchmarkWorkloadFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("failed to unmarshal target fixture: %v", err)
	}

	rep, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), fx)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}

	if !rep.Passed {
		t.Fatalf("expected workload to pass, got violations: %v", rep.Violations)
	}
	if rep.TotalRequests != 10 {
		t.Fatalf("expected 10 total requests, got %d", rep.TotalRequests)
	}
	if rep.AllowCount != 10 || rep.DenyCount != 0 {
		t.Fatalf("expected 10 allowed and 0 denied, got allow=%d deny=%d", rep.AllowCount, rep.DenyCount)
	}
	if rep.LatencySummary.P95Ms > 200.0 {
		t.Fatalf("p95 latency %.2fms exceeds 200ms SLO deadline", rep.LatencySummary.P95Ms)
	}
}

func TestC28_OverloadCancellationSaturationAndFailClosed(t *testing.T) {
	cases := []struct {
		file           string
		expectedStatus int
		expectedAllow  bool
		expectedError  string
	}{
		{
			file:           "negative-oversized-payload-exceeds-64k.json",
			expectedStatus: 413,
			expectedAllow:  false,
			expectedError:  gateway.ErrCodePayloadTooLarge,
		},
		{
			file:           "negative-deadline-exceeded-timeout.json",
			expectedStatus: 504,
			expectedAllow:  false,
			expectedError:  gateway.ErrCodeDecisionTimeout,
		},
		{
			file:           "negative-client-cancellation.json",
			expectedStatus: 499,
			expectedAllow:  false,
			expectedError:  gateway.ErrCodeRequestCancelled,
		},
		{
			file:           "negative-private-resource-fail-closed.json",
			expectedStatus: 200,
			expectedAllow:  false,
			expectedError:  gateway.ErrCodeWidenedPermission,
		},
		{
			file:           "negative-provider-unavailable-workload.json",
			expectedStatus: 200,
			expectedAllow:  false,
			expectedError:  gateway.ErrCodeProviderUnavailable,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			fixturePath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C28", tc.file)
			raw, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", tc.file, err)
			}

			var fx gateway.BenchmarkWorkloadFixture
			if err := json.Unmarshal(raw, &fx); err != nil {
				t.Fatalf("failed to parse fixture %s: %v", tc.file, err)
			}

			rep, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), fx)
			if err != nil {
				t.Fatalf("fixture %s execution failed: %v", tc.file, err)
			}
			if !rep.Passed {
				t.Fatalf("expected fixture %s to pass, got violations: %v", tc.file, rep.Violations)
			}
			if len(rep.StepResults) > 0 {
				step := rep.StepResults[0]
				if step.StatusCode != tc.expectedStatus {
					t.Fatalf("expected status %d, got %d", tc.expectedStatus, step.StatusCode)
				}
				if step.Allow != tc.expectedAllow {
					t.Fatalf("expected allow %v, got %v", tc.expectedAllow, step.Allow)
				}
				if step.ErrorCode != tc.expectedError {
					t.Fatalf("expected error %q, got %q", tc.expectedError, step.ErrorCode)
				}
			}
		})
	}

	// Test saturation overload
	satFixturePath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C28", "negative-saturation-limit-fail-closed.json")
	satRaw, err := os.ReadFile(satFixturePath)
	if err != nil {
		t.Fatalf("failed to read saturation fixture: %v", err)
	}

	var satFx gateway.BenchmarkWorkloadFixture
	if err := json.Unmarshal(satRaw, &satFx); err != nil {
		t.Fatalf("failed to unmarshal saturation fixture: %v", err)
	}

	satRep, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), satFx)
	if err != nil {
		t.Fatalf("saturation evaluation failed: %v", err)
	}
	if !satRep.Passed {
		t.Fatalf("expected saturation fixture to pass, got violations: %v", satRep.Violations)
	}
	if satRep.SaturationCount == 0 {
		t.Fatalf("expected at least 1 saturation failure, got %d", satRep.SaturationCount)
	}
}

func TestC28_RestartInvariantAndResourceTracking(t *testing.T) {
	fixturePath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C28", "negative-restart-recovery-workload.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read restart fixture: %v", err)
	}

	var fx gateway.BenchmarkWorkloadFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("failed to unmarshal restart fixture: %v", err)
	}

	rep, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), fx)
	if err != nil {
		t.Fatalf("restart evaluation failed: %v", err)
	}

	if !rep.Passed {
		t.Fatalf("expected restart workload to pass, got violations: %v", rep.Violations)
	}
	if rep.ResourceUsage.RSSPeakBytes == 0 {
		t.Fatalf("expected non-zero RSS peak bytes tracking")
	}
	if val, ok := rep.ObservedLimits["restart_recovery_verified"].(bool); !ok || !val {
		t.Fatalf("expected restart_recovery_verified to be true")
	}
}

func TestC28_CLIAndHTTPBenchmarkVerify(t *testing.T) {
	fixturePath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C28", "positive-target-bounded-workload.json")
	rawBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	// 1. Test HTTP handler directly via httptest
	req := httptest.NewRequest(http.MethodPost, "/api/v1/benchmark/run", bytes.NewReader(rawBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	var fx gateway.BenchmarkWorkloadFixture
	if err := json.Unmarshal(rawBytes, &fx); err != nil {
		t.Fatalf("failed to unmarshal fixture: %v", err)
	}

	rep, runErr := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), fx)
	if runErr != nil || !rep.Passed {
		t.Fatalf("direct evaluation failed: %v", runErr)
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rep)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", w.Code)
	}

	// 2. Test CLI execution with -benchmark-workload
	engineBin := filepath.Join("..", "dist", "engine", "policyhelix")
	if _, err := os.Stat(engineBin); err == nil {
		cmd := exec.Command(engineBin, "-benchmark-workload", fixturePath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI benchmark failed: %v (output=%s)", err, string(output))
		}
		var cliRep gateway.BenchmarkExecutionReport
		if err := json.Unmarshal(output, &cliRep); err != nil {
			t.Fatalf("failed to parse CLI output JSON: %v (raw=%s)", err, string(output))
		}
		if !cliRep.Passed {
			t.Fatalf("expected CLI benchmark to pass, got violations: %v", cliRep.Violations)
		}
	}
}

func TestC28_ExtremeWorkerSaturationBurst(t *testing.T) {
	const totalSteps = 50
	const maxWorkers = 5
	steps := make([]gateway.BenchmarkStep, totalSteps)
	for i := 0; i < totalSteps; i++ {
		steps[i] = gateway.BenchmarkStep{
			StepID:          filepath.Join("extreme-sat-step", string(rune('0'+i))),
			Method:          "POST",
			Path:            "/api/v1/analytics/reports",
			Role:            "operator",
			PayloadSize:     512,
			SimulateDelayMs: 25,
		}
	}

	fx := gateway.BenchmarkWorkloadFixture{
		FixtureID:          "extreme-saturation-test",
		SchemaVersion:      "1",
		WorkloadType:       "saturation_overload",
		Concurrency:        totalSteps,
		MaxWorkers:         maxWorkers,
		DecisionDeadlineMs: 200,
		MaxPayloadBytes:    65536,
		Steps:              steps,
		Expected: gateway.BenchmarkExpectations{
			TotalRequests:           totalSteps,
			ExpectedAllowCount:      maxWorkers,
			ExpectedDenyCount:       totalSteps - maxWorkers,
			ExpectedSaturationCount: totalSteps - maxWorkers,
		},
	}

	rep, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), fx)
	if err != nil {
		t.Fatalf("extreme saturation burst evaluation failed: %v", err)
	}

	if !rep.Passed {
		t.Fatalf("expected extreme saturation to pass, got violations: %v", rep.Violations)
	}
	if rep.AllowCount != maxWorkers {
		t.Fatalf("expected exactly %d allows, got %d", maxWorkers, rep.AllowCount)
	}
	if rep.SaturationCount != totalSteps-maxWorkers {
		t.Fatalf("expected %d saturation errors, got %d", totalSteps-maxWorkers, rep.SaturationCount)
	}
}

func TestC28_MalformedFixtureAndEdgeCases(t *testing.T) {
	// 1. Fixture with invalid schema_version and no declared ExpectedErrorCode must fail validation
	badSchemaFx := gateway.BenchmarkWorkloadFixture{
		FixtureID:     "fx-bad-schema",
		SchemaVersion: "bad_v9",
		WorkloadType:  "target_bounded",
	}
	rep, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), badSchemaFx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Passed {
		t.Fatalf("expected malformed schema fixture without expectation to fail verification")
	}
	if rep.ErrorCode != gateway.ErrCodeMalformedBenchmark {
		t.Fatalf("expected error code %q, got %q", gateway.ErrCodeMalformedBenchmark, rep.ErrorCode)
	}

	// 2. Empty fixture_id must fail validation
	emptyIDFx := gateway.BenchmarkWorkloadFixture{
		FixtureID:     "",
		SchemaVersion: "1",
		WorkloadType:  "target_bounded",
	}
	repEmpty, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), emptyIDFx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repEmpty.Passed {
		t.Fatalf("expected empty fixture ID to fail verification")
	}
	if repEmpty.ErrorCode != gateway.ErrCodeMalformedBenchmark {
		t.Fatalf("expected error code %q, got %q", gateway.ErrCodeMalformedBenchmark, repEmpty.ErrorCode)
	}

	// 3. Negative fixture declaring MALFORMED_BENCHMARK_FIXTURE must pass
	declaredMalformedFx := gateway.BenchmarkWorkloadFixture{
		FixtureID:     "fx-declared-malformed",
		SchemaVersion: "unsupported",
		WorkloadType:  "malformed_fixture",
		Expected: gateway.BenchmarkExpectations{
			ExpectedErrorCode: gateway.ErrCodeMalformedBenchmark,
		},
	}
	repDecl, err := gateway.EvaluateBenchmarkFixture(context.Background(), t.TempDir(), declaredMalformedFx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !repDecl.Passed {
		t.Fatalf("expected declared malformed fixture to pass verification")
	}
}
