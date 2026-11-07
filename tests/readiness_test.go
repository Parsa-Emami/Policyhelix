package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/gateway"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

type c29ManifestEntry struct {
	FixtureID string `json:"fixture_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Type      string `json:"type"`
	License   string `json:"license"`
}

type c29Manifest struct {
	SchemaVersion string             `json:"schema_version"`
	CommitID      string             `json:"commit_id"`
	Description   string             `json:"description"`
	License       string             `json:"license"`
	Fixtures      []c29ManifestEntry `json:"fixtures"`
}

func TestC29_ManifestIntegrityAndFixtureEvaluation(t *testing.T) {
	manifestPath := filepath.Join("fixtures", "policyhelix", "C29", "manifest.json")
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C29 manifest: %v", err)
	}

	var manifest c29Manifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C29 manifest: %v", err)
	}

	if manifest.CommitID != "C29" || manifest.License != "Apache-2.0" {
		t.Fatalf("expected commit_id C29 and Apache-2.0, got commit_id=%q license=%q", manifest.CommitID, manifest.License)
	}
	if len(manifest.Fixtures) < 10 {
		t.Fatalf("expected at least 10 fixtures in C29 manifest, got %d", len(manifest.Fixtures))
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

		var fx gateway.ReadinessFixture
		if err := json.Unmarshal(rawBytes, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", entry.FixtureID, err)
		}

		rep, evalErr := gateway.EvaluateReadinessFixture(context.Background(), t.TempDir(), fx)
		if fx.FixtureID == "negative-malformed-readiness-fixture" {
			if evalErr == nil {
				t.Fatalf("expected malformed fixture to produce error, got nil")
			}
			continue
		}

		if evalErr != nil {
			t.Fatalf("fixture %s failed evaluation: %v (report=%+v)", entry.FixtureID, evalErr, rep)
		}
		if !rep.Passed {
			t.Fatalf("fixture %s passed=false, violations: %v", entry.FixtureID, rep.Violations)
		}
	}
}

func TestC29_RealEngineAndStorageReadinessSeparation(t *testing.T) {
	tempDir := t.TempDir()
	ad, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer ad.Close()

	// Initial check: storage ready, all providers connected
	rep := gateway.EvaluateReadiness(context.Background(), tempDir, ad, nil)
	if !rep.Ready {
		t.Fatalf("expected engine to be ready with healthy storage, got ready=%v failures=%v", rep.Ready, rep.Failures)
	}
	if rep.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", rep.StatusCode)
	}
	if !rep.Storage.Ready || !rep.Storage.Writable {
		t.Fatalf("expected storage to be ready and writable: %+v", rep.Storage)
	}

	// Verify liveness vs readiness separation:
	// A missing/corrupt storage port causes readiness to return 503 while healthz remains 200
	corruptDir := filepath.Join(t.TempDir(), "non-existent")
	unreadyRep := gateway.EvaluateReadiness(context.Background(), corruptDir, nil, nil)
	if unreadyRep.Ready {
		t.Fatalf("expected unready storage to fail readiness")
	}
	if unreadyRep.StatusCode != 503 {
		t.Fatalf("expected status 503 on unready storage, got %d", unreadyRep.StatusCode)
	}
	if unreadyRep.Storage.ErrorCode != gateway.ErrCodeStorageUnready {
		t.Fatalf("expected STORAGE_PORT_UNREADY, got %s", unreadyRep.Storage.ErrorCode)
	}
}

func TestC29_ProviderOutageVisibleFailClosed(t *testing.T) {
	tempDir := t.TempDir()
	ad, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("failed opening storage: %v", err)
	}
	defer ad.Close()

	// 1. OPA provider outage
	repOPA := gateway.EvaluateReadiness(context.Background(), tempDir, ad, map[string]string{
		"local_opa": "offline",
	})
	if repOPA.Ready || repOPA.StatusCode != 503 {
		t.Fatalf("expected OPA outage to fail readiness with 503, got %d (ready=%v)", repOPA.StatusCode, repOPA.Ready)
	}
	if repOPA.Providers["local_opa"].ErrorCode != gateway.ErrCodeOPAUnavailable {
		t.Fatalf("expected OPA_PROVIDER_UNAVAILABLE, got %s", repOPA.Providers["local_opa"].ErrorCode)
	}

	// 2. Keycloak IdP outage
	repIdP := gateway.EvaluateReadiness(context.Background(), tempDir, ad, map[string]string{
		"self_hosted_keycloak": "offline",
	})
	if repIdP.Ready || repIdP.StatusCode != 503 {
		t.Fatalf("expected IdP outage to fail readiness with 503, got %d", repIdP.StatusCode)
	}
	if repIdP.Providers["self_hosted_keycloak"].ErrorCode != gateway.ErrCodeIdPUnavailable {
		t.Fatalf("expected IDP_PROVIDER_UNAVAILABLE, got %s", repIdP.Providers["self_hosted_keycloak"].ErrorCode)
	}

	// 3. Upstream outage
	repUpstream := gateway.EvaluateReadiness(context.Background(), tempDir, ad, map[string]string{
		"owned_synthetic_upstream": "offline",
	})
	if repUpstream.Ready || repUpstream.StatusCode != 503 {
		t.Fatalf("expected upstream outage to fail readiness with 503, got %d", repUpstream.StatusCode)
	}
	if repUpstream.Providers["owned_synthetic_upstream"].ErrorCode != gateway.ErrCodeUpstreamUnavailable {
		t.Fatalf("expected UPSTREAM_PROVIDER_UNAVAILABLE, got %s", repUpstream.Providers["owned_synthetic_upstream"].ErrorCode)
	}
}

func TestC29_BoundedLogsAndSecretSentinelRedaction(t *testing.T) {
	buf := gateway.NewDiagnosticsBuffer(10)

	// Test secret sentinel scrubbing
	rawSecretMsg := "Incoming req with Authorization: Bearer SECRET_BEARER_SENTINEL and policyhelix_session=SECRET_COOKIE_SENTINEL and sentinel_token_999"
	evt := buf.Record("info", "test-auth", rawSecretMsg, map[string]interface{}{
		"api_key": "SECRET_KEY_SENTINEL_ABCD",
		"normal":  "safe_value",
	})

	if strings.Contains(evt.Message, "SECRET_BEARER_SENTINEL") || strings.Contains(evt.Message, "SECRET_COOKIE_SENTINEL") || strings.Contains(evt.Message, "sentinel_token_999") {
		t.Fatalf("secret sentinels leaked in message: %s", evt.Message)
	}
	if !strings.Contains(evt.Message, "Bearer [REDACTED]") || !strings.Contains(evt.Message, "[REDACTED_SENTINEL]") {
		t.Fatalf("expected redaction placeholders in message: %s", evt.Message)
	}

	if metaVal, ok := evt.Metadata["api_key"].(string); !ok || metaVal != "[REDACTED]" {
		t.Fatalf("expected api_key in metadata to be redacted, got %v", evt.Metadata["api_key"])
	}

	// Test message length bounding (max 4096 bytes)
	longMsg := "START_" + strings.Repeat("A", 6000) + "_END"
	evtTrunc := buf.Record("warn", "test-size", longMsg, nil)
	if len(evtTrunc.Message) > 4096 {
		t.Fatalf("message exceeds 4096 bytes: len=%d", len(evtTrunc.Message))
	}
	if !strings.HasSuffix(evtTrunc.Message, "...[TRUNCATED]") {
		t.Fatalf("expected truncation suffix, got %s", evtTrunc.Message[len(evtTrunc.Message)-20:])
	}

	// Test ring buffer bounded capacity
	for i := 0; i < 20; i++ {
		buf.Record("info", "filler", "entry", nil)
	}
	events := buf.GetEvents(100)
	if len(events) != 10 {
		t.Fatalf("expected ring buffer bounded to 10 entries, got %d", len(events))
	}
	stats := buf.Stats()
	if stats["dropped_count"].(int64) < 10 {
		t.Fatalf("expected dropped events count >= 10, got %v", stats["dropped_count"])
	}
}

func TestC29_DiagnosticsHTTPAndPrivateFailClosed(t *testing.T) {
	tempDir := t.TempDir()
	ad, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("storage open failed: %v", err)
	}
	defer ad.Close()

	// 1. In absence of auth header or loopback internal param, returns 401
	recUnauth := httptest.NewRecorder()
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/diagnostics", nil)

	gateway.DiagnosticsHTTPHandler(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated diagnostics request to fail closed with 401, got %d", recUnauth.Code)
	}

	// 2. Authenticated request succeeds
	recAuth := httptest.NewRecorder()
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/diagnostics", nil)
	reqAuth.Header.Set("Authorization", "Bearer valid-test-token")
	gateway.DiagnosticsHTTPHandler(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected authorized diagnostics request to succeed with 200, got %d", recAuth.Code)
	}

	// 3. Loopback internal access query param succeeds
	recInternal := httptest.NewRecorder()
	reqInternal := httptest.NewRequest(http.MethodGet, "/api/v1/runtime/diagnostics?internal=1", nil)
	gateway.DiagnosticsHTTPHandler(recInternal, reqInternal)
	if recInternal.Code != http.StatusOK {
		t.Fatalf("expected internal diagnostics request to succeed with 200, got %d", recInternal.Code)
	}

	// 4. Test method not allowed
	recPost := httptest.NewRecorder()
	reqPost := httptest.NewRequest(http.MethodPost, "/api/v1/runtime/diagnostics", nil)
	gateway.DiagnosticsHTTPHandler(recPost, reqPost)
	if recPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected POST diagnostics to return 405 Method Not Allowed, got %d", recPost.Code)
	}
}
