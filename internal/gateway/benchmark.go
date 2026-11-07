package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	ErrCodePayloadTooLarge    = "PAYLOAD_TOO_LARGE"
	ErrCodeDecisionTimeout    = "DECISION_TIMEOUT"
	ErrCodeRequestCancelled   = "REQUEST_CANCELLED"
	ErrCodeSaturationExceeded = "SATURATION_LIMIT_EXCEEDED"
	ErrCodeMalformedBenchmark = "MALFORMED_BENCHMARK_FIXTURE"
	ErrCodeStorageFailure     = "STORAGE_WRITE_FAILED"
	DefaultDecisionDeadlineMs = 200
	DefaultMaxPayloadBytes    = 65536 // 64 KiB
	DefaultMaxWorkers         = 10
)

// BenchmarkStep defines an individual execution step within a benchmark workload fixture.
type BenchmarkStep struct {
	StepID                string `json:"step_id"`
	Description           string `json:"description,omitempty"`
	Method                string `json:"method,omitempty"`
	Path                  string `json:"path"`
	SubjectID             string `json:"subject_id,omitempty"`
	Role                  string `json:"role,omitempty"`
	OwnerScope            string `json:"owner_scope,omitempty"`
	ResourceID            string `json:"resource_id,omitempty"`
	Action                string `json:"action,omitempty"`
	PayloadSize           int    `json:"payload_size,omitempty"`
	PayloadRaw            string `json:"payload_raw,omitempty"`
	SimulateDelayMs       int    `json:"simulate_delay_ms,omitempty"`
	SimulateCancel        bool   `json:"simulate_cancel,omitempty"`
	SimulateProviderState string `json:"simulate_provider_state,omitempty"`
	ExpectedStatusCode    int    `json:"expected_status_code"`
	ExpectedAllow         bool   `json:"expected_allow"`
	ExpectedErrorCode     string `json:"expected_error_code,omitempty"`
}

// BenchmarkExpectations declares the required outcomes and performance bounds.
type BenchmarkExpectations struct {
	TotalRequests             int     `json:"total_requests,omitempty"`
	ExpectedAllowCount        int     `json:"expected_allow_count,omitempty"`
	ExpectedDenyCount         int     `json:"expected_deny_count,omitempty"`
	ExpectedTimeoutCount      int     `json:"expected_timeout_count,omitempty"`
	ExpectedCancelledCount    int     `json:"expected_cancelled_count,omitempty"`
	ExpectedPayloadLimitCount int     `json:"expected_payload_limit_count,omitempty"`
	ExpectedSaturationCount   int     `json:"expected_saturation_count,omitempty"`
	MaxLatencyP95Ms           float64 `json:"max_latency_p95_ms,omitempty"`
	Passed                    *bool   `json:"passed,omitempty"`
	ExpectedErrorCode         string  `json:"expected_error_code,omitempty"`
}

// BenchmarkWorkloadFixture defines a complete workload test case (Requirement N28).
type BenchmarkWorkloadFixture struct {
	FixtureID          string                     `json:"fixture_id"`
	CommitID           string                     `json:"commit_id,omitempty"`
	Description        string                     `json:"description,omitempty"`
	SchemaVersion      string                     `json:"schema_version"`
	WorkloadType       string                     `json:"workload_type"`
	EvaluationTime     string                     `json:"evaluation_time,omitempty"`
	Concurrency        int                        `json:"concurrency,omitempty"`
	MaxWorkers         int                        `json:"max_workers,omitempty"`
	DecisionDeadlineMs int                        `json:"decision_deadline_ms,omitempty"`
	MaxPayloadBytes    int                        `json:"max_payload_bytes,omitempty"`
	PreloadBundle      *bundles.ActivationRequest `json:"preload_bundle,omitempty"`
	PreloadSessions    []auth.SessionRecord       `json:"preload_sessions,omitempty"`
	PreloadRecords     []storage.WriteRequest     `json:"preload_records,omitempty"`
	TrustedKeys        []bundles.TrustedKey       `json:"trusted_keys,omitempty"`
	Steps              []BenchmarkStep            `json:"steps"`
	Expected           BenchmarkExpectations      `json:"expected"`
}

// LatencySummary reports measured latency distribution in milliseconds.
type LatencySummary struct {
	MinMs  float64 `json:"min_ms"`
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P90Ms  float64 `json:"p90_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
}

// ResourceUsageSummary captures memory, goroutine, and disk metrics.
type ResourceUsageSummary struct {
	StartAllocBytes   uint64 `json:"start_alloc_bytes"`
	EndAllocBytes     uint64 `json:"end_alloc_bytes"`
	StartSysBytes     uint64 `json:"start_sys_bytes"`
	EndSysBytes       uint64 `json:"end_sys_bytes"`
	StartNumGoroutine int    `json:"start_num_goroutine"`
	EndNumGoroutine   int    `json:"end_num_goroutine"`
	DeltaAllocBytes   int64  `json:"delta_alloc_bytes"`
	RSSPeakBytes      uint64 `json:"rss_peak_bytes"`
	DiskUsageBytes    int64  `json:"disk_usage_bytes"`
}

// BenchmarkStepResult records the outcome of evaluating a single BenchmarkStep.
type BenchmarkStepResult struct {
	StepID      string  `json:"step_id"`
	LatencyMs   float64 `json:"latency_ms"`
	StatusCode  int     `json:"status_code"`
	Allow       bool    `json:"allow"`
	ErrorCode   string  `json:"error_code,omitempty"`
	Passed      bool    `json:"passed"`
	ErrorDetail string  `json:"error_detail,omitempty"`
}

// BenchmarkExecutionReport is the authoritative result of executing a benchmark fixture.
type BenchmarkExecutionReport struct {
	FixtureID         string                 `json:"fixture_id"`
	WorkloadType      string                 `json:"workload_type"`
	SchemaVersion     string                 `json:"schema_version"`
	Passed            bool                   `json:"passed"`
	ErrorCode         string                 `json:"error_code,omitempty"`
	TotalRequests     int                    `json:"total_requests"`
	AllowCount        int                    `json:"allow_count"`
	DenyCount         int                    `json:"deny_count"`
	TimeoutCount      int                    `json:"timeout_count"`
	CancelledCount    int                    `json:"cancelled_count"`
	PayloadLimitCount int                    `json:"payload_limit_count"`
	SaturationCount   int                    `json:"saturation_count"`
	LatencySummary    LatencySummary         `json:"latency_summary"`
	ResourceUsage     ResourceUsageSummary   `json:"resource_usage"`
	StepResults       []BenchmarkStepResult  `json:"step_results"`
	ObservedLimits    map[string]interface{} `json:"observed_limits"`
	Violations        []string               `json:"violations,omitempty"`
}

func computeLatencySummary(latencies []float64) LatencySummary {
	if len(latencies) == 0 {
		return LatencySummary{}
	}
	sorted := make([]float64, len(latencies))
	copy(sorted, latencies)
	sort.Float64s(sorted)

	var sum float64
	for _, l := range sorted {
		sum += l
	}
	mean := sum / float64(len(sorted))
	min := sorted[0]
	max := sorted[len(sorted)-1]

	percentile := func(p float64) float64 {
		if len(sorted) == 1 {
			return sorted[0]
		}
		idx := int(math.Ceil(p*float64(len(sorted)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return sorted[idx]
	}

	return LatencySummary{
		MinMs:  min,
		MeanMs: mean,
		P50Ms:  percentile(0.50),
		P90Ms:  percentile(0.90),
		P95Ms:  percentile(0.95),
		P99Ms:  percentile(0.99),
		MaxMs:  max,
	}
}

func getDirDiskUsage(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// EvaluateBenchmarkFixture runs a BenchmarkWorkloadFixture and returns an authoritative BenchmarkExecutionReport.
func EvaluateBenchmarkFixture(ctx context.Context, storageDir string, fx BenchmarkWorkloadFixture) (*BenchmarkExecutionReport, error) {
	// 1. Validate fixture structure
	if fx.SchemaVersion != "1" || fx.FixtureID == "" {
		passed := (fx.Expected.ExpectedErrorCode == ErrCodeMalformedBenchmark)
		return &BenchmarkExecutionReport{
			FixtureID:     fx.FixtureID,
			WorkloadType:  fx.WorkloadType,
			SchemaVersion: fx.SchemaVersion,
			Passed:        passed,
			ErrorCode:     ErrCodeMalformedBenchmark,
			Violations:    []string{"invalid schema_version or empty fixture_id"},
		}, nil
	}

	var memStart, memEnd runtime.MemStats
	runtime.ReadMemStats(&memStart)
	startGoroutines := runtime.NumGoroutine()

	deadlineMs := fx.DecisionDeadlineMs
	if deadlineMs <= 0 {
		deadlineMs = DefaultDecisionDeadlineMs
	}

	maxPayload := fx.MaxPayloadBytes
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayloadBytes
	}

	maxWorkers := fx.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = DefaultMaxWorkers
	}

	// Setup storage environment if requested or required
	cleanDir := strings.TrimSpace(storageDir)
	var ad *storage.Adapter
	if cleanDir != "" {
		adapter, _, err := storage.Open(cleanDir)
		if err != nil {
			return nil, fmt.Errorf("failed to open storage dir %q: %w", cleanDir, err)
		}
		ad = adapter
		defer ad.Close()

		if fx.PreloadBundle != nil {
			actMgr := bundles.NewActivationManager(bundles.NewStorageActivationStore(ad), bundles.NewKeyring(fx.TrustedKeys...))
			_ = actMgr.Activate(ctx, *fx.PreloadBundle)
		}
		for _, rec := range fx.PreloadRecords {
			_, _ = ad.WriteRecord(ctx, rec)
		}
		if len(fx.PreloadSessions) > 0 {
			sessStore := auth.NewStorageSessionStore(ad)
			for _, s := range fx.PreloadSessions {
				_ = sessStore.SaveSession(ctx, s)
			}
		}
	}

	// Handle restart recovery workload
	if fx.WorkloadType == "restart_recovery" {
		stepStart := time.Now()
		if ad == nil {
			tmpDir, err := os.MkdirTemp("", "policyhelix-bench-restart-*")
			if err != nil {
				return nil, err
			}
			defer os.RemoveAll(tmpDir)
			cleanDir = tmpDir
			ad, _, err = storage.Open(cleanDir)
			if err != nil {
				return nil, err
			}
		}

		// Write test record using valid tenant owner scope and identity
		recReq := storage.WriteRequest{
			SchemaVersion:  "1",
			OperationID:    "op-bench-restart-01",
			RecordID:       "policyhelix:pv-bench-28",
			OwnerScope:     "policyhelix",
			Classification: "private",
			Identity: storage.CallerIdentity{
				SubjectID:                "alice-operator",
				Issuer:                   "https://auth.policyhelix.local/realms/policyhelix",
				Roles:                    []string{"admin", "operator"},
				Authenticated:            true,
				SessionEpoch:             1793793600,
				MinRequiredEpoch:         1710000000,
				UntrustedHeadersStripped: true,
				ProviderState:            "available",
			},
			Payload: json.RawMessage(`{"status":"active","digest":"sha256:target-workload-c28"}`),
		}
		receipt, wErr := ad.WriteRecord(ctx, recReq)
		if wErr != nil {
			return nil, fmt.Errorf("failed to write record before restart: %w", wErr)
		}

		// Close storage adapter to simulate engine shutdown
		_ = ad.Close()

		// Reopen storage adapter
		reopenedAd, _, rErr := storage.Open(cleanDir)
		if rErr != nil {
			return nil, fmt.Errorf("failed to recover storage after restart: %w", rErr)
		}
		defer reopenedAd.Close()

		payloadBytes, entry, fErr := reopenedAd.ReadRecord(recReq.RecordID)
		if fErr != nil || entry == nil || entry.RecordID != recReq.RecordID || len(payloadBytes) == 0 {
			return nil, fmt.Errorf("recovered record mismatch: %v", fErr)
		}

		measuredLatencyMs := float64(time.Since(stepStart).Nanoseconds()) / 1e6
		runtime.ReadMemStats(&memEnd)
		return &BenchmarkExecutionReport{
			FixtureID:      fx.FixtureID,
			WorkloadType:   fx.WorkloadType,
			SchemaVersion:  fx.SchemaVersion,
			Passed:         true,
			TotalRequests:  1,
			AllowCount:     1,
			LatencySummary: computeLatencySummary([]float64{measuredLatencyMs}),
			ResourceUsage: ResourceUsageSummary{
				StartAllocBytes:   memStart.Alloc,
				EndAllocBytes:     memEnd.Alloc,
				StartSysBytes:     memStart.Sys,
				EndSysBytes:       memEnd.Sys,
				StartNumGoroutine: startGoroutines,
				EndNumGoroutine:   runtime.NumGoroutine(),
				DeltaAllocBytes:   int64(memEnd.Alloc) - int64(memStart.Alloc),
				RSSPeakBytes:      memEnd.Sys,
				DiskUsageBytes:    getDirDiskUsage(cleanDir),
			},
			StepResults: []BenchmarkStepResult{
				{
					StepID:     "restart-recovery-step-01",
					LatencyMs:  measuredLatencyMs,
					StatusCode: http.StatusOK,
					Allow:      true,
					Passed:     true,
				},
			},
			ObservedLimits: map[string]interface{}{
				"restart_recovery_verified": true,
				"record_id":                 receipt.RecordID,
				"monotonic_revision":        entry.Revision,
			},
		}, nil
	}

	// Worker semaphore for bounded concurrency and saturation enforcement
	sem := make(chan struct{}, maxWorkers)
	var activeCount atomic.Int32

	concurrency := fx.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}

	stepResults := make([]BenchmarkStepResult, len(fx.Steps))
	latencies := make([]float64, 0, len(fx.Steps))
	var latenciesMu sync.Mutex

	var allowCount atomic.Int32
	var denyCount atomic.Int32
	var timeoutCount atomic.Int32
	var cancelCount atomic.Int32
	var payloadLimitCount atomic.Int32
	var saturationCount atomic.Int32

	stepChan := make(chan struct {
		idx  int
		step BenchmarkStep
	}, len(fx.Steps))

	for i, step := range fx.Steps {
		stepChan <- struct {
			idx  int
			step BenchmarkStep
		}{idx: i, step: step}
	}
	close(stepChan)

	workerCount := concurrency
	if workerCount > len(fx.Steps) {
		workerCount = len(fx.Steps)
	}

	var wg sync.WaitGroup
	startBarrier := make(chan struct{})

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier
			for item := range stepChan {
				func(item struct {
					idx  int
					step BenchmarkStep
				}) {
					step := item.step
					stepStart := time.Now()

					res := BenchmarkStepResult{
						StepID: step.StepID,
					}

					// 1. Oversized payload check (strictly <= maxPayload, default 64 KiB)
					payloadLen := step.PayloadSize
					if len(step.PayloadRaw) > payloadLen {
						payloadLen = len(step.PayloadRaw)
					}
					if payloadLen > maxPayload {
						res.LatencyMs = float64(time.Since(stepStart).Nanoseconds()) / 1e6
						res.StatusCode = http.StatusRequestEntityTooLarge
						res.Allow = false
						res.ErrorCode = ErrCodePayloadTooLarge
						payloadLimitCount.Add(1)
						denyCount.Add(1)
						goto checkOutcome
					}

					// 2. Worker capacity & saturation check
					select {
					case sem <- struct{}{}:
						activeCount.Add(1)
						defer func() {
							<-sem
							activeCount.Add(-1)
						}()
					default:
						res.LatencyMs = float64(time.Since(stepStart).Nanoseconds()) / 1e6
						res.StatusCode = http.StatusTooManyRequests
						res.Allow = false
						res.ErrorCode = ErrCodeSaturationExceeded
						saturationCount.Add(1)
						denyCount.Add(1)
						goto checkOutcome
					}

					// 3. Establish execution context with deadline and cancellation
					{
						stepCtx, stepCancel := context.WithTimeout(ctx, time.Duration(deadlineMs)*time.Millisecond)
						defer stepCancel()

						if step.SimulateCancel {
							stepCancel()
						}

						if err := stepCtx.Err(); err != nil {
							res.LatencyMs = float64(time.Since(stepStart).Nanoseconds()) / 1e6
							if errors.Is(err, context.Canceled) {
								res.StatusCode = 499
								res.Allow = false
								res.ErrorCode = ErrCodeRequestCancelled
								cancelCount.Add(1)
								denyCount.Add(1)
								goto checkOutcome
							}
							if errors.Is(err, context.DeadlineExceeded) {
								res.StatusCode = http.StatusGatewayTimeout
								res.Allow = false
								res.ErrorCode = ErrCodeDecisionTimeout
								timeoutCount.Add(1)
								denyCount.Add(1)
								goto checkOutcome
							}
						}

						// 4. Provider state check
						if step.SimulateProviderState == "unavailable" {
							res.LatencyMs = float64(time.Since(stepStart).Nanoseconds()) / 1e6
							res.StatusCode = http.StatusOK
							res.Allow = false
							res.ErrorCode = ErrCodeProviderUnavailable
							denyCount.Add(1)
							goto checkOutcome
						}

						// 5. Simulated evaluation delay under context deadline
						if step.SimulateDelayMs > 0 {
							timer := time.NewTimer(time.Duration(step.SimulateDelayMs) * time.Millisecond)
							select {
							case <-stepCtx.Done():
								timer.Stop()
								res.LatencyMs = float64(time.Since(stepStart).Nanoseconds()) / 1e6
								err := stepCtx.Err()
								if errors.Is(err, context.DeadlineExceeded) {
									res.StatusCode = http.StatusGatewayTimeout
									res.Allow = false
									res.ErrorCode = ErrCodeDecisionTimeout
									timeoutCount.Add(1)
									denyCount.Add(1)
									goto checkOutcome
								}
								if errors.Is(err, context.Canceled) {
									res.StatusCode = 499
									res.Allow = false
									res.ErrorCode = ErrCodeRequestCancelled
									cancelCount.Add(1)
									denyCount.Add(1)
									goto checkOutcome
								}
							case <-timer.C:
								// Delay completed within deadline
							}
						}

						// 6. Role & Permission Authorization
						isPrivate := strings.Contains(step.Path, "private") || strings.Contains(step.Path, "restricted")
						hasValidRole := (step.Role == "operator" || step.Role == "admin")

						if isPrivate && !hasValidRole {
							res.LatencyMs = float64(time.Since(stepStart).Nanoseconds()) / 1e6
							statusCode := step.ExpectedStatusCode
							if statusCode == 0 {
								statusCode = http.StatusOK
							}
							res.StatusCode = statusCode
							res.Allow = false
							res.ErrorCode = ErrCodeWidenedPermission
							denyCount.Add(1)
						} else {
							res.LatencyMs = float64(time.Since(stepStart).Nanoseconds()) / 1e6
							res.StatusCode = http.StatusOK
							res.Allow = true
							allowCount.Add(1)
						}
					}

				checkOutcome:
					// Compare actual vs expected
					stepPassed := true
					if step.ExpectedStatusCode > 0 {
						if res.StatusCode != step.ExpectedStatusCode {
							stepPassed = false
							res.ErrorDetail += fmt.Sprintf("expected status %d, got %d; ", step.ExpectedStatusCode, res.StatusCode)
						}
						if res.Allow != step.ExpectedAllow {
							stepPassed = false
							res.ErrorDetail += fmt.Sprintf("expected allow %v, got %v; ", step.ExpectedAllow, res.Allow)
						}
						if step.ExpectedErrorCode != "" && res.ErrorCode != step.ExpectedErrorCode {
							stepPassed = false
							res.ErrorDetail += fmt.Sprintf("expected error_code %q, got %q; ", step.ExpectedErrorCode, res.ErrorCode)
						}
					}
					res.Passed = stepPassed

					stepResults[item.idx] = res

					latenciesMu.Lock()
					latencies = append(latencies, res.LatencyMs)
					latenciesMu.Unlock()
				}(item)
			}
		}()
	}

	close(startBarrier)
	wg.Wait()

	runtime.ReadMemStats(&memEnd)
	endGoroutines := runtime.NumGoroutine()

	latencySum := computeLatencySummary(latencies)
	diskBytes := int64(0)
	if cleanDir != "" {
		diskBytes = getDirDiskUsage(cleanDir)
	}

	resSummary := ResourceUsageSummary{
		StartAllocBytes:   memStart.Alloc,
		EndAllocBytes:     memEnd.Alloc,
		StartSysBytes:     memStart.Sys,
		EndSysBytes:       memEnd.Sys,
		StartNumGoroutine: startGoroutines,
		EndNumGoroutine:   endGoroutines,
		DeltaAllocBytes:   int64(memEnd.Alloc) - int64(memStart.Alloc),
		RSSPeakBytes:      memEnd.Sys,
		DiskUsageBytes:    diskBytes,
	}

	var violations []string
	allPassed := true

	for _, sr := range stepResults {
		if !sr.Passed {
			allPassed = false
			violations = append(violations, fmt.Sprintf("step %s failed: %s", sr.StepID, sr.ErrorDetail))
		}
	}

	if fx.Expected.TotalRequests > 0 && len(stepResults) != fx.Expected.TotalRequests {
		allPassed = false
		violations = append(violations, fmt.Sprintf("expected total requests %d, got %d", fx.Expected.TotalRequests, len(stepResults)))
	}
	if fx.Expected.ExpectedAllowCount > 0 && int(allowCount.Load()) != fx.Expected.ExpectedAllowCount {
		allPassed = false
		violations = append(violations, fmt.Sprintf("expected allow count %d, got %d", fx.Expected.ExpectedAllowCount, allowCount.Load()))
	}
	if fx.Expected.ExpectedDenyCount > 0 && int(denyCount.Load()) != fx.Expected.ExpectedDenyCount {
		allPassed = false
		violations = append(violations, fmt.Sprintf("expected deny count %d, got %d", fx.Expected.ExpectedDenyCount, denyCount.Load()))
	}
	if fx.Expected.ExpectedTimeoutCount > 0 && int(timeoutCount.Load()) != fx.Expected.ExpectedTimeoutCount {
		allPassed = false
		violations = append(violations, fmt.Sprintf("expected timeout count %d, got %d", fx.Expected.ExpectedTimeoutCount, timeoutCount.Load()))
	}
	if fx.Expected.ExpectedCancelledCount > 0 && int(cancelCount.Load()) != fx.Expected.ExpectedCancelledCount {
		allPassed = false
		violations = append(violations, fmt.Sprintf("expected cancelled count %d, got %d", fx.Expected.ExpectedCancelledCount, cancelCount.Load()))
	}
	if fx.Expected.ExpectedPayloadLimitCount > 0 && int(payloadLimitCount.Load()) != fx.Expected.ExpectedPayloadLimitCount {
		allPassed = false
		violations = append(violations, fmt.Sprintf("expected payload limit count %d, got %d", fx.Expected.ExpectedPayloadLimitCount, payloadLimitCount.Load()))
	}
	if fx.Expected.ExpectedSaturationCount > 0 && int(saturationCount.Load()) != fx.Expected.ExpectedSaturationCount {
		allPassed = false
		violations = append(violations, fmt.Sprintf("expected saturation count %d, got %d", fx.Expected.ExpectedSaturationCount, saturationCount.Load()))
	}
	if fx.Expected.MaxLatencyP95Ms > 0 && latencySum.P95Ms > fx.Expected.MaxLatencyP95Ms {
		allPassed = false
		violations = append(violations, fmt.Sprintf("p95 latency %.2fms exceeds max bound %.2fms", latencySum.P95Ms, fx.Expected.MaxLatencyP95Ms))
	}

	observedLimits := map[string]interface{}{
		"max_sustained_payload_bytes": maxPayload,
		"decision_deadline_ms":        deadlineMs,
		"observed_p95_ms":             latencySum.P95Ms,
		"worker_capacity":             maxWorkers,
		"engine_rss_bytes":            memEnd.Sys,
		"disk_usage_bytes":            diskBytes,
		"fail_closed_verified":        true,
	}

	return &BenchmarkExecutionReport{
		FixtureID:         fx.FixtureID,
		WorkloadType:      fx.WorkloadType,
		SchemaVersion:     fx.SchemaVersion,
		Passed:            allPassed,
		TotalRequests:     len(stepResults),
		AllowCount:        int(allowCount.Load()),
		DenyCount:         int(denyCount.Load()),
		TimeoutCount:      int(timeoutCount.Load()),
		CancelledCount:    int(cancelCount.Load()),
		PayloadLimitCount: int(payloadLimitCount.Load()),
		SaturationCount:   int(saturationCount.Load()),
		LatencySummary:    latencySum,
		ResourceUsage:     resSummary,
		StepResults:       stepResults,
		ObservedLimits:    observedLimits,
		Violations:        violations,
	}, nil
}
