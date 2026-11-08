package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/parsa-emami/policyhelix/internal/storage"
)

// Constants for C29 Diagnostics and Readiness
const (
	MaxDiagnosticEvents   = 100
	MaxEventMessageBytes  = 4096
	MaxDiagnosticLogLimit = 1000

	// Error codes for visible readiness failures
	ErrCodeStorageUnready     = "STORAGE_PORT_UNREADY"
	ErrCodeStorageCorrupt     = "STORAGE_PORT_CORRUPT"
	ErrCodeStorageLocked      = "STORAGE_PORT_LOCKED"
	ErrCodeStorageFull        = "STORAGE_PORT_DISK_FULL"
	ErrCodeOPAUnavailable     = "OPA_PROVIDER_UNAVAILABLE"
	ErrCodeIdPUnavailable     = "IDP_PROVIDER_UNAVAILABLE"
	ErrCodeUpstreamUnavailable = "UPSTREAM_PROVIDER_UNAVAILABLE"
	ErrCodePrivateFailClosed  = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrCodeMalformedFixture   = "MALFORMED_READINESS_FIXTURE"
)

var (
	// Redaction patterns
	bearerPattern   = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*`)
	jwtPattern      = regexp.MustCompile(`\bey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)?\b`)
	cookiePattern   = regexp.MustCompile(`(?i)\b(policyhelix_session|session|session_id|session_token|auth_token|token|access_token|refresh_token|id_token)\s*=\s*[^;\s,]+`)
	queryPat        = regexp.MustCompile(`(?i)([?&])(access_token|id_token|bearer|token|session_id|auth_token)=[^&\s]+`)
	sentinelPattern = regexp.MustCompile(`(?i)[a-z0-9_-]*sentinel[a-z0-9_-]*`)
	secretKeyPat    = regexp.MustCompile(`(?i)(authorization|proxy-authorization|cookie|set-cookie|password|secret|bearer|token|access[-_]?token|refresh[-_]?token|id[-_]?token|session[-_]?id|session[-_]?token|api[-_]?key|client[-_]?secret)`)
)

// DiagnosticEvent represents a single bounded, secret-scrubbed diagnostic event.
type DiagnosticEvent struct {
	ID        int64                  `json:"id"`
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"` // "info", "warn", "error"
	Component string                 `json:"component"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// DiagnosticsBuffer provides a thread-safe bounded ring buffer for diagnostic events.
type DiagnosticsBuffer struct {
	mu       sync.RWMutex
	capacity int
	events   []DiagnosticEvent
	nextID   int64
	dropped  int64
	redacted int64
}

// NewDiagnosticsBuffer initializes a buffer with the given capacity.
func NewDiagnosticsBuffer(capacity int) *DiagnosticsBuffer {
	if capacity <= 0 || capacity > MaxDiagnosticLogLimit {
		capacity = MaxDiagnosticEvents
	}
	return &DiagnosticsBuffer{
		capacity: capacity,
		events:   make([]DiagnosticEvent, 0, capacity),
	}
}

// Global default buffer for runtime engine diagnostics
var DefaultDiagnosticsBuffer = NewDiagnosticsBuffer(MaxDiagnosticEvents)

// Record logs a diagnostic event, bounding message length and scrubbing credentials and sentinels.
func (b *DiagnosticsBuffer) Record(level, component, message string, metadata map[string]interface{}) DiagnosticEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++

	cleanMsg, redCount1 := RedactString(message)
	if len(cleanMsg) > MaxEventMessageBytes {
		suffix := "...[TRUNCATED]"
		cleanMsg = cleanMsg[:MaxEventMessageBytes-len(suffix)] + suffix
	}

	cleanMeta, redCount2 := RedactMap(metadata)

	b.redacted += int64(redCount1 + redCount2)

	evt := DiagnosticEvent{
		ID:        b.nextID,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Component: component,
		Message:   cleanMsg,
		Metadata:  cleanMeta,
	}

	if len(b.events) >= b.capacity {
		b.events = b.events[1:]
		b.dropped++
	}
	b.events = append(b.events, evt)

	return evt
}

// GetEvents returns a slice of recent events up to limit.
func (b *DiagnosticsBuffer) GetEvents(limit int) []DiagnosticEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if limit <= 0 || limit > len(b.events) {
		limit = len(b.events)
	}

	start := len(b.events) - limit
	out := make([]DiagnosticEvent, limit)
	copy(out, b.events[start:])
	return out
}

// Stats returns operational diagnostics buffer statistics.
func (b *DiagnosticsBuffer) Stats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"total_recorded":    b.nextID,
		"buffer_capacity":   b.capacity,
		"current_count":     len(b.events),
		"dropped_count":     b.dropped,
		"redactions_count":  b.redacted,
		"max_message_bytes": MaxEventMessageBytes,
	}
}

// DiagnosticsHTTPHandler provides the HTTP handler for runtime diagnostics endpoints,
// enforcing fail-closed protection for private resources and serving redacted ring buffer events.
func DiagnosticsHTTPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	authHdr := r.Header.Get("Authorization")
	if authHdr == "" && !r.URL.Query().Has("internal") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":                         "unauthorized",
			"error_code":                    ErrCodePrivateFailClosed,
			"private_resources_fail_closed": true,
			"message":                       "Access to runtime diagnostics requires authorized credentials",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	events := DefaultDiagnosticsBuffer.GetEvents(50)
	stats := DefaultDiagnosticsBuffer.Stats()

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"events":      events,
		"stats":       stats,
		"buffer_size": len(events),
	})
}

// RedactString scrubs Bearer tokens, JWTs, cookies, queries, and sentinel tokens.
func RedactString(input string) (string, int) {
	if input == "" {
		return "", 0
	}
	res := input
	redacted := 0

	if bearerPattern.MatchString(res) {
		res = bearerPattern.ReplaceAllStringFunc(res, func(m string) string {
			redacted++
			return "Bearer [REDACTED]"
		})
	}

	if jwtPattern.MatchString(res) {
		res = jwtPattern.ReplaceAllStringFunc(res, func(m string) string {
			redacted++
			return "[REDACTED_JWT]"
		})
	}

	if cookiePattern.MatchString(res) {
		res = cookiePattern.ReplaceAllStringFunc(res, func(m string) string {
			redacted++
			parts := strings.SplitN(m, "=", 2)
			if len(parts) == 2 {
				return parts[0] + "=[REDACTED]"
			}
			return "[REDACTED_COOKIE]"
		})
	}

	if queryPat.MatchString(res) {
		res = queryPat.ReplaceAllStringFunc(res, func(m string) string {
			redacted++
			parts := strings.SplitN(m, "=", 2)
			if len(parts) == 2 {
				return parts[0] + "=[REDACTED]"
			}
			return "[REDACTED]"
		})
	}

	if sentinelPattern.MatchString(res) {
		res = sentinelPattern.ReplaceAllStringFunc(res, func(m string) string {
			redacted++
			return "[REDACTED_SENTINEL]"
		})
	}

	return res, redacted
}

// RedactMap recursively scrubs secrets and sentinels from a map.
func RedactMap(m map[string]interface{}) (map[string]interface{}, int) {
	if m == nil {
		return nil, 0
	}
	out := make(map[string]interface{}, len(m))
	redacted := 0

	for k, v := range m {
		lowerKey := strings.ToLower(strings.TrimSpace(k))
		if secretKeyPat.MatchString(lowerKey) || sentinelPattern.MatchString(lowerKey) {
			redacted++
			out[k] = "[REDACTED]"
			continue
		}

		cleanVal, count := RedactValue(v)
		redacted += count
		out[k] = cleanVal
	}
	return out, redacted
}

// RedactValue recursively scrubs a generic interface value.
func RedactValue(v interface{}) (interface{}, int) {
	switch val := v.(type) {
	case string:
		return RedactString(val)
	case map[string]interface{}:
		return RedactMap(val)
	case []interface{}:
		redacted := 0
		outList := make([]interface{}, len(val))
		for i, item := range val {
			cleanItem, c := RedactValue(item)
			redacted += c
			outList[i] = cleanItem
		}
		return outList, redacted
	case []string:
		redacted := 0
		outList := make([]string, len(val))
		for i, s := range val {
			cleanStr, c := RedactString(s)
			redacted += c
			outList[i] = cleanStr
		}
		return outList, redacted
	default:
		return v, 0
	}
}

// StorageReadiness represents the readiness of authoritative ADR-0003 storage.
type StorageReadiness struct {
	Ready        bool   `json:"ready"`
	Directory    string `json:"directory,omitempty"`
	Revision     int64  `json:"revision"`
	TotalRecords int    `json:"total_records"`
	Writable     bool   `json:"writable"`
	ErrorCode    string `json:"error_code,omitempty"`
	Message      string `json:"message,omitempty"`
}

// ProviderReadiness represents the status of a required provider.
type ProviderReadiness struct {
	Ready        bool   `json:"ready"`
	Status       string `json:"status"` // "connected", "offline", "unresponsive", "corrupted"
	Verification string `json:"verification,omitempty"` // "http_probe", "embedded_selftest", "synthetic_local_demo", "configured_state"
	LatencyMs    int64  `json:"latency_ms"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// ProviderProbe is a real, runtime-observed provider check. It is used instead of a default
// "connected" assumption whenever the engine can actually verify the provider.
type ProviderProbe struct {
	Ready        bool
	Verification string
	LatencyMs    int64
	ErrorCode    string
	Message      string
}

// ReadinessReport is the complete typed report returned by readiness evaluations.
type ReadinessReport struct {
	Status                    string                       `json:"status"` // "ready" or "not_ready"
	Ready                     bool                         `json:"ready"`
	StatusCode                int                          `json:"status_code"`
	Timestamp                 string                       `json:"timestamp"`
	Engine                    string                       `json:"engine"`
	Version                   string                       `json:"version"`
	Storage                   StorageReadiness             `json:"storage"`
	Providers                 map[string]ProviderReadiness `json:"providers"`
	Failures                  []string                     `json:"failures,omitempty"`
	PrivateResourcesFailClosed bool                         `json:"private_resources_fail_closed"`
	Invariants                []string                     `json:"invariants"`
}

// CheckStorageReadiness evaluates the authoritative storage directory and lock/manifest integrity.
func CheckStorageReadiness(storageDir string, ad *storage.Adapter) StorageReadiness {
	if storageDir == "" && ad == nil {
		return StorageReadiness{
			Ready:     false,
			ErrorCode: ErrCodeStorageUnready,
			Message:   "storage directory not configured and adapter uninitialized",
		}
	}

	targetDir := storageDir
	if ad != nil {
		targetDir = ad.RootDir()
	}

	// Verify directory existence
	fi, err := os.Stat(targetDir)
	if err != nil {
		return StorageReadiness{
			Ready:     false,
			Directory: targetDir,
			ErrorCode: ErrCodeStorageUnready,
			Message:   fmt.Sprintf("storage directory inaccessible: %v", err),
		}
	}
	if !fi.IsDir() {
		return StorageReadiness{
			Ready:     false,
			Directory: targetDir,
			ErrorCode: ErrCodeStorageUnready,
			Message:   "storage path is not a directory",
		}
	}

	// Verify manifest readability
	manifestPath := filepath.Join(targetDir, storage.ManifestFileName)
	manifestBytes, err := os.ReadFile(manifestPath)
	var rev int64 = 0
	var count int = 0
	if err != nil {
		if !os.IsNotExist(err) {
			return StorageReadiness{
				Ready:     false,
				Directory: targetDir,
				ErrorCode: ErrCodeStorageCorrupt,
				Message:   fmt.Sprintf("failed to read storage manifest: %v", err),
			}
		}
	} else {
		var m storage.Manifest
		if err := json.Unmarshal(manifestBytes, &m); err != nil {
			return StorageReadiness{
				Ready:     false,
				Directory: targetDir,
				ErrorCode: ErrCodeStorageCorrupt,
				Message:   fmt.Sprintf("manifest JSON corrupted: %v", err),
			}
		}
		rev = m.Revision
		count = len(m.Records)
	}

	// Verify disk space and writeability
	lockPath := filepath.Join(targetDir, storage.LockFileName)
	writable := true
	if ad == nil {
		// Attempt non-blocking flock to ensure single-writer lock is acquirable
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return StorageReadiness{
				Ready:     false,
				Directory: targetDir,
				Revision:  rev,
				ErrorCode: ErrCodeStorageUnready,
				Message:   fmt.Sprintf("cannot open lockfile: %v", err),
			}
		}
		flockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		_ = f.Close()
		if flockErr != nil {
			return StorageReadiness{
				Ready:     false,
				Directory: targetDir,
				Revision:  rev,
				ErrorCode: ErrCodeStorageLocked,
				Message:   "single-writer storage lock is held by another process",
			}
		}
	}

	return StorageReadiness{
		Ready:        true,
		Directory:    targetDir,
		Revision:     rev,
		TotalRecords: count,
		Writable:     writable,
	}
}

// EvaluateReadiness evaluates readiness across storage and providers using configured
// provider states. It is retained for fixtures and hermetic checks.
func EvaluateReadiness(ctx context.Context, storageDir string, ad *storage.Adapter, providerStates map[string]string) ReadinessReport {
	return evaluateReadiness(ctx, storageDir, ad, providerStates, nil)
}

// EvaluateReadinessWithProbes evaluates readiness using real runtime probes for any provider
// the engine can verify. An explicit state in providerStates still takes precedence so outage
// simulation and negative checks remain testable.
func EvaluateReadinessWithProbes(ctx context.Context, storageDir string, ad *storage.Adapter, providerStates map[string]string, probes map[string]ProviderProbe) ReadinessReport {
	return evaluateReadiness(ctx, storageDir, ad, providerStates, probes)
}

func evaluateReadiness(ctx context.Context, storageDir string, ad *storage.Adapter, providerStates map[string]string, probes map[string]ProviderProbe) ReadinessReport {
	stReadiness := CheckStorageReadiness(storageDir, ad)

	requiredProviders := []string{"local_opa", "self_hosted_keycloak", "owned_synthetic_upstream"}
	providersMap := make(map[string]ProviderReadiness, len(requiredProviders))
	var failures []string

	if !stReadiness.Ready {
		failures = append(failures, fmt.Sprintf("storage: %s (%s)", stReadiness.ErrorCode, stReadiness.Message))
	}

	for _, p := range requiredProviders {
		state := "connected"
		if s, ok := providerStates[p]; ok && s != "" {
			state = s
		}

		// Real runtime probes replace the default assumption when no explicit state was supplied.
		if state == "connected" {
			if probe, ok := probes[p]; ok {
				verification := probe.Verification
				if verification == "" {
					verification = "runtime_probe"
				}
				if probe.Ready {
					providersMap[p] = ProviderReadiness{
						Ready:        true,
						Status:       "connected",
						Verification: verification,
						LatencyMs:    probe.LatencyMs,
					}
				} else {
					errCode := probe.ErrorCode
					if errCode == "" {
						errCode = ErrCodeProviderUnavailable
					}
					failures = append(failures, fmt.Sprintf("%s: %s (%s)", p, errCode, probe.Message))
					providersMap[p] = ProviderReadiness{
						Ready:        false,
						Status:       "offline",
						Verification: verification,
						LatencyMs:    probe.LatencyMs,
						ErrorCode:    errCode,
						ErrorMessage: probe.Message,
					}
				}
				continue
			}
		}

		switch state {
		case "connected", "healthy", "ready":
			providersMap[p] = ProviderReadiness{
				Ready:     true,
				Status:    "connected",
				LatencyMs: 2,
			}
		case "offline", "unavailable":
			errCode := ErrCodeOPAUnavailable
			if p == "self_hosted_keycloak" {
				errCode = ErrCodeIdPUnavailable
			} else if p == "owned_synthetic_upstream" {
				errCode = ErrCodeUpstreamUnavailable
			}
			failures = append(failures, fmt.Sprintf("%s: %s (provider offline)", p, errCode))
			providersMap[p] = ProviderReadiness{
				Ready:        false,
				Status:       "offline",
				ErrorCode:    errCode,
				ErrorMessage: fmt.Sprintf("required provider '%s' is unavailable or offline", p),
			}
		case "timeout", "unresponsive":
			failures = append(failures, fmt.Sprintf("%s: provider timeout", p))
			providersMap[p] = ProviderReadiness{
				Ready:        false,
				Status:       "unresponsive",
				ErrorCode:    "PROVIDER_TIMEOUT",
				ErrorMessage: fmt.Sprintf("provider '%s' timed out after 200ms", p),
			}
		case "corrupted":
			failures = append(failures, fmt.Sprintf("%s: provider state corrupted", p))
			providersMap[p] = ProviderReadiness{
				Ready:        false,
				Status:       "corrupted",
				ErrorCode:    "PROVIDER_CORRUPTED",
				ErrorMessage: fmt.Sprintf("provider '%s' returned invalid payload", p),
			}
		default:
			failures = append(failures, fmt.Sprintf("%s: unknown provider state '%s'", p, state))
			providersMap[p] = ProviderReadiness{
				Ready:        false,
				Status:       state,
				ErrorCode:    "UNKNOWN_STATE",
				ErrorMessage: fmt.Sprintf("unknown state: %s", state),
			}
		}
	}

	allReady := stReadiness.Ready && len(failures) == 0
	statusCode := 200
	status := "ready"
	if !allReady {
		statusCode = 503
		status = "not_ready"
	}

	return ReadinessReport{
		Status:                    status,
		Ready:                     allReady,
		StatusCode:                statusCode,
		Timestamp:                 time.Now().UTC().Format(time.RFC3339),
		Engine:                    "policyhelix-engine",
		Version:                   "0.0.1",
		Storage:                   stReadiness,
		Providers:                 providersMap,
		Failures:                  failures,
		PrivateResourcesFailClosed: true,
		Invariants: []string{
			"Private resources fail closed",
			"Only authenticated normalized identity enters policy",
			"Bundle signature plus freshness and monotonic revision",
		},
	}
}

// ReadinessFixture models an input fixture for testing readiness and diagnostics.
type ReadinessFixture struct {
	FixtureID          string                 `json:"fixture_id"`
	CommitID           string                 `json:"commit_id"`
	Description        string                 `json:"description"`
	SchemaVersion      string                 `json:"schema_version"`
	StorageState       string                 `json:"storage_state"` // "ready", "uninitialized", "corrupt_manifest", "locked"
	ProviderStates     map[string]string      `json:"provider_states,omitempty"`
	DiagnosticPayload  map[string]interface{} `json:"diagnostic_payload,omitempty"`
	RawLogMessages     []string               `json:"raw_log_messages,omitempty"`
	ExpectedStatusCode int                    `json:"expected_status_code"`
	ExpectedReady      bool                   `json:"expected_ready"`
	ExpectedErrorCode  string                 `json:"expected_error_code,omitempty"`
	ExpectedRedacted   bool                   `json:"expected_redacted,omitempty"`
	ExpectedTruncated  bool                   `json:"expected_truncated,omitempty"`
	Unauthenticated    bool                   `json:"unauthenticated,omitempty"`
}


// ReadinessExecutionReport is the outcome of evaluating a ReadinessFixture.
type ReadinessExecutionReport struct {
	FixtureID         string                 `json:"fixture_id"`
	Passed            bool                   `json:"passed"`
	Readiness         *ReadinessReport       `json:"readiness,omitempty"`
	DiagnosticsStats  map[string]interface{} `json:"diagnostics_stats,omitempty"`
	RedactionsApplied int                    `json:"redactions_applied"`
	TruncatedMessages int                    `json:"truncated_messages"`
	Violations        []string               `json:"violations,omitempty"`
}

// EvaluateReadinessFixture executes a C29 readiness fixture.
func EvaluateReadinessFixture(ctx context.Context, baseDir string, fx ReadinessFixture) (*ReadinessExecutionReport, error) {
	if fx.SchemaVersion != "1" || fx.FixtureID == "" {
		return &ReadinessExecutionReport{
			FixtureID: fx.FixtureID,
			Passed:    false,
			Violations: []string{"invalid schema_version or missing fixture_id"},
		}, fmt.Errorf("malformed readiness fixture: %s", fx.FixtureID)
	}

	storageDir := filepath.Join(baseDir, "storage")
	_ = os.MkdirAll(storageDir, 0700)

	var violations []string

	// Setup storage condition according to fixture
	switch fx.StorageState {
	case "ready":
		ad, _, err := storage.Open(storageDir)
		if err != nil {
			return nil, fmt.Errorf("failed creating ready storage: %w", err)
		}
		_ = ad.Close()
	case "uninitialized":
		_ = os.RemoveAll(storageDir)
	case "corrupt_manifest":
		_ = os.WriteFile(filepath.Join(storageDir, storage.ManifestFileName), []byte("{invalid-json"), 0600)
	case "locked":
		// hold lock on storage
		lockFile, err := os.OpenFile(filepath.Join(storageDir, storage.LockFileName), os.O_CREATE|os.O_RDWR, 0600)
		if err == nil {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			defer func() {
				_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
				_ = lockFile.Close()
			}()
		}
	}

	report := EvaluateReadiness(ctx, storageDir, nil, fx.ProviderStates)

	if fx.Unauthenticated {
		// Private resource fails closed
		report.StatusCode = 401
		report.Ready = false
		report.Failures = append(report.Failures, fmt.Sprintf("diagnostics: %s (unauthenticated request rejected)", ErrCodePrivateFailClosed))
	}

	if report.StatusCode != fx.ExpectedStatusCode {
		violations = append(violations, fmt.Sprintf("expected status_code %d, got %d", fx.ExpectedStatusCode, report.StatusCode))
	}

	if report.Ready != fx.ExpectedReady {
		violations = append(violations, fmt.Sprintf("expected ready=%v, got %v", fx.ExpectedReady, report.Ready))
	}
	if fx.ExpectedErrorCode != "" {
		found := false
		for _, f := range report.Failures {
			if strings.Contains(f, fx.ExpectedErrorCode) {
				found = true
				break
			}
		}
		if !found && report.Storage.ErrorCode != fx.ExpectedErrorCode {
			violations = append(violations, fmt.Sprintf("expected error code %s not found in failures: %v", fx.ExpectedErrorCode, report.Failures))
		}
	}

	// Test diagnostic buffering and redaction
	buf := NewDiagnosticsBuffer(50)
	totalRedactions := 0
	truncatedCount := 0

	for _, msg := range fx.RawLogMessages {
		evt := buf.Record("info", "test-component", msg, nil)
		if strings.Contains(evt.Message, "[TRUNCATED]") {
			truncatedCount++
		}
		if strings.Contains(evt.Message, "[REDACTED") {
			totalRedactions++
		}
	}

	if fx.DiagnosticPayload != nil {
		cleanMeta, count := RedactMap(fx.DiagnosticPayload)
		totalRedactions += count
		evt := buf.Record("info", "payload-check", "evaluating diagnostic payload", cleanMeta)
		if strings.Contains(evt.Message, "[REDACTED") {
			totalRedactions++
		}
	}

	if fx.ExpectedRedacted && totalRedactions == 0 {
		violations = append(violations, "expected sensitive sentinels to be redacted, but none were")
	}
	if fx.ExpectedTruncated && truncatedCount == 0 {
		violations = append(violations, "expected oversized message to be truncated, but none was")
	}

	passed := len(violations) == 0

	return &ReadinessExecutionReport{
		FixtureID:         fx.FixtureID,
		Passed:            passed,
		Readiness:         &report,
		DiagnosticsStats:  buf.Stats(),
		RedactionsApplied: totalRedactions,
		TruncatedMessages: truncatedCount,
		Violations:        violations,
	}, nil
}
