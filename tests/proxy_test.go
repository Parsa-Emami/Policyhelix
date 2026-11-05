package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/gateway"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	c17FixtureDir = "fixtures/policyhelix/C17"
)

type c17FixtureEnvelope struct {
	FixtureID          string                  `json:"fixture_id"`
	CommitID           string                  `json:"commit_id"`
	Description        string                  `json:"description"`
	SchemaVersion      string                  `json:"schema_version"`
	Config             *gateway.UpstreamConfig `json:"config,omitempty"`
	PreloadSessions    []auth.SessionRecord    `json:"preload_sessions,omitempty"`
	PreloadRevocations []auth.RevocationRecord `json:"preload_revocations,omitempty"`
	Request            gateway.ProxyRequest    `json:"request"`
	Expected           struct {
		Valid               bool   `json:"valid"`
		Allow               bool   `json:"allow"`
		ForwardedToUpstream bool   `json:"forwarded_to_upstream"`
		SideEffectsExecuted bool   `json:"side_effects_executed"`
		StatusCode          int    `json:"status_code"`
		ErrorCode           string `json:"error_code,omitempty"`
		UpstreamID          string `json:"upstream_id,omitempty"`
		ResolvedOriginURL   string `json:"resolved_origin_url,omitempty"`
	} `json:"expected"`
}

func TestC17_ManifestIntegrity(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c17FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C17 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C17 manifest: %v", err)
	}
	if manifest.CommitID != "C17" {
		t.Fatalf("expected commit_id C17, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 12 {
		t.Fatalf("expected at least 12 C17 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c17FixtureDir, base))
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

func TestC17_FixturesSuite(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c17FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C17 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C17 manifest: %v", err)
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c17FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		// CLI fixtures are tested in TestC17_EngineCLIProxy
		if base == "cli-proxy-clean.json" || base == "cli-proxy-rejected.json" {
			continue
		}

		var fixture c17FixtureEnvelope
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", entry.Path, err)
		}

		t.Run(fixture.FixtureID, func(t *testing.T) {
			ctx := context.Background()
			sessStore := auth.NewMemorySessionStore()
			revStore := auth.NewMemoryRevocationStore()

			for _, s := range fixture.PreloadSessions {
				if err := sessStore.SaveSession(ctx, s); err != nil {
					t.Fatalf("failed to preload session %s: %v", s.SessionID, err)
				}
			}
			for _, r := range fixture.PreloadRevocations {
				if r.SessionID != "" {
					if err := revStore.SaveSessionRevocation(ctx, r); err != nil {
						t.Fatalf("failed to preload session revocation %s: %v", r.SessionID, err)
					}
				}
				if r.SubjectID != "" && r.MinRequiredEpoch > 0 {
					if err := revStore.SaveSubjectRevocation(ctx, r); err != nil {
						t.Fatalf("failed to preload subject revocation %s: %v", r.SubjectID, err)
					}
				}
				if r.OwnerScope != "" {
					if err := revStore.SaveScopeRevocation(ctx, r); err != nil {
						t.Fatalf("failed to preload scope revocation %s: %v", r.OwnerScope, err)
					}
				}
			}

			cfg := gateway.DefaultUpstreamConfig()
			if fixture.Config != nil {
				cfg = *fixture.Config
			}

			proxy := gateway.NewAllowlistedGatewayProxy(cfg, sessStore, revStore)
			res, err := proxy.EvaluateProxyRequest(ctx, fixture.Request)
			if err != nil {
				t.Fatalf("unexpected proxy evaluation error: %v", err)
			}
			if res == nil {
				t.Fatalf("proxy evaluation returned nil result")
			}

			if res.Allow != fixture.Expected.Allow {
				t.Errorf("allow mismatch: expected %v, got %v (err_code=%s, msg=%s)",
					fixture.Expected.Allow, res.Allow, res.ErrorCode, res.ErrorMessage)
			}
			if res.Valid != fixture.Expected.Valid {
				t.Errorf("valid mismatch: expected %v, got %v", fixture.Expected.Valid, res.Valid)
			}
			if res.ForwardedToUpstream != fixture.Expected.ForwardedToUpstream {
				t.Errorf("forwarded_to_upstream mismatch: expected %v, got %v",
					fixture.Expected.ForwardedToUpstream, res.ForwardedToUpstream)
			}
			if res.SideEffectsExecuted != fixture.Expected.SideEffectsExecuted {
				t.Errorf("side_effects_executed mismatch: expected %v, got %v",
					fixture.Expected.SideEffectsExecuted, res.SideEffectsExecuted)
			}
			if fixture.Expected.StatusCode != 0 && res.StatusCode != fixture.Expected.StatusCode {
				t.Errorf("status_code mismatch: expected %d, got %d",
					fixture.Expected.StatusCode, res.StatusCode)
			}
			if fixture.Expected.ErrorCode != "" && res.ErrorCode != fixture.Expected.ErrorCode {
				t.Errorf("error_code mismatch: expected %s, got %s",
					fixture.Expected.ErrorCode, res.ErrorCode)
			}
			if fixture.Expected.UpstreamID != "" && res.UpstreamID != fixture.Expected.UpstreamID {
				t.Errorf("upstream_id mismatch: expected %s, got %s",
					fixture.Expected.UpstreamID, res.UpstreamID)
			}
			if fixture.Expected.ResolvedOriginURL != "" && res.ResolvedOriginURL != fixture.Expected.ResolvedOriginURL {
				t.Errorf("resolved_origin_url mismatch: expected %s, got %s",
					fixture.Expected.ResolvedOriginURL, res.ResolvedOriginURL)
			}
		})
	}
}

func TestC17_RealLoopbackHTTPReverseProxy(t *testing.T) {
	ctx := context.Background()
	secret := "test_secret_for_c17_proof_123"

	// 1. Upstream synthetic service (protected origin)
	var lastReceivedProof string
	var lastReceivedSubject string
	var lastReceivedRoles string

	upstreamMux := http.NewServeMux()
	upstreamMux.HandleFunc("/api/v1/analytics", func(w http.ResponseWriter, r *http.Request) {
		lastReceivedProof = r.Header.Get(gateway.HeaderGatewayProof)
		lastReceivedSubject = r.Header.Get(gateway.HeaderPolicyHelixSubject)
		lastReceivedRoles = r.Header.Get(gateway.HeaderPolicyHelixRoles)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"service":"analytics","status":"ok","records":42}`))
	})
	upstreamMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	})

	// Wrap upstream with ProtectedOriginMiddleware
	protectedUpstream := gateway.ProtectedOriginMiddleware(secret)(upstreamMux)
	upstreamServer := httptest.NewServer(protectedUpstream)
	defer upstreamServer.Close()

	// 2. Gateway setup
	sessStore := auth.NewMemorySessionStore()
	revStore := auth.NewMemoryRevocationStore()

	// Seed valid session
	validSessionID := "sess-c17-live-01"
	_ = sessStore.SaveSession(ctx, auth.SessionRecord{
		SessionID: validSessionID,
		SubjectID: "alice-analyst",
		Issuer:    "https://auth.policyhelix.local",
		Roles:     []string{"operator", "analyst"},
		Status:    "ACTIVE",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	// Seed revoked session
	revokedSessionID := "sess-c17-live-revoked"
	_ = sessStore.SaveSession(ctx, auth.SessionRecord{
		SessionID: revokedSessionID,
		SubjectID: "bob-compromised",
		Issuer:    "https://auth.policyhelix.local",
		Roles:     []string{"operator"},
		Status:    "ACTIVE",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	_ = revStore.SaveSessionRevocation(ctx, auth.RevocationRecord{
		SessionID: revokedSessionID,
		Reason:    "token compromised",
		RevokedAt: time.Now().Add(-10 * time.Minute),
	})

	cfg := gateway.UpstreamConfig{
		ID:                     "service:analytics",
		OriginURL:              upstreamServer.URL,
		AllowedPathPrefixes:    []string{"/api/v1/analytics", "/health"},
		RequiredOwnerScope:     "",
		ResourceClassification: "private",
		GatewayProofSecret:     secret,
		ProofMaxAge:            60 * time.Second,
	}

	proxyCore := gateway.NewAllowlistedGatewayProxy(cfg, sessStore, revStore)
	proxyCore.Transport = http.DefaultTransport
	gatewayHandler := gateway.NewAllowlistedReverseProxy(proxyCore)
	gatewayServer := httptest.NewServer(gatewayHandler)
	defer gatewayServer.Close()

	client := gatewayServer.Client()

	// Scenario A: Direct Origin Access Bypass Attempt (Origin reachability invariant)
	t.Run("DirectOriginAccessBypassAttemptDenied", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, upstreamServer.URL+"/api/v1/analytics", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected direct origin bypass to return 403 Forbidden, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), gateway.ErrCodeDirectOriginBypass) {
			t.Fatalf("expected error body to contain %s, got: %s", gateway.ErrCodeDirectOriginBypass, string(body))
		}
	})

	// Scenario B: Authorized Request Through Gateway
	t.Run("AuthorizedRequestThroughGatewaySuccess", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, gatewayServer.URL+"/api/v1/analytics", nil)
		req.AddCookie(&http.Cookie{Name: "policyhelix_session", Value: validSessionID})
		req.Header.Set("X-Request-Id", "req-test-live-01")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200 OK, got %d (body: %s)", resp.StatusCode, string(body))
		}

		if lastReceivedSubject != "alice-analyst" {
			t.Errorf("upstream did not receive injected subject: got %s", lastReceivedSubject)
		}
		if !strings.Contains(lastReceivedRoles, "operator") {
			t.Errorf("upstream did not receive injected roles: got %s", lastReceivedRoles)
		}
		if lastReceivedProof == "" {
			t.Errorf("upstream did not receive gateway origin proof token")
		}
	})

	// Scenario C: Forged Client Identity Header Stripped at Gateway
	t.Run("ForgedClientHeaderStrippedAndReplaced", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, gatewayServer.URL+"/api/v1/analytics", nil)
		req.AddCookie(&http.Cookie{Name: "policyhelix_session", Value: validSessionID})
		req.Header.Set("X-User-Id", "attacker-impersonating-root")
		req.Header.Set("X-Roles", "superadmin")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
		}

		// Verified that forged client header was purged and replaced with authoritative session subject
		if lastReceivedSubject == "attacker-impersonating-root" {
			t.Fatalf("SECURITY VIOLATION: upstream received forged X-User-Id value")
		}
		if lastReceivedSubject != "alice-analyst" {
			t.Errorf("expected authoritative subject 'alice-analyst', got '%s'", lastReceivedSubject)
		}
	})

	// Scenario D: Revoked Session Access Denied
	t.Run("RevokedSessionAccessDenied", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, gatewayServer.URL+"/api/v1/analytics", nil)
		req.AddCookie(&http.Cookie{Name: "policyhelix_session", Value: revokedSessionID})

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for revoked session, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), gateway.ErrCodeRevokedSessionDenied) {
			t.Errorf("expected body to contain %s, got: %s", gateway.ErrCodeRevokedSessionDenied, string(body))
		}
	})

	// Scenario E: Unauthenticated Private Resource Fails Closed
	t.Run("UnauthenticatedPrivateResourceFailsClosed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, gatewayServer.URL+"/api/v1/analytics", nil)
		// No cookie or identity header

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for unauthenticated private resource, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), gateway.ErrCodePrivateResource) {
			t.Errorf("expected body to contain %s, got: %s", gateway.ErrCodePrivateResource, string(body))
		}
	})

	// Scenario F: Unallowlisted Path Denied
	t.Run("UnallowlistedPathDenied", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, gatewayServer.URL+"/admin/secret_keys", nil)
		req.AddCookie(&http.Cookie{Name: "policyhelix_session", Value: validSessionID})

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for unallowlisted path, got %d", resp.StatusCode)
		}
	})
}

func TestC17_EngineCLIProxy(t *testing.T) {
	engineBin := filepath.Join("..", "dist", "engine", "policyhelix")
	if _, err := os.Stat(engineBin); err != nil {
		buildCmd := exec.Command("go", "build", "-o", filepath.Join("dist", "engine", "policyhelix"), "./cmd/policyhelix")
		buildCmd.Dir = ".."
		if out, bErr := buildCmd.CombinedOutput(); bErr != nil {
			t.Skipf("cannot build policyhelix binary for CLI tests: %v: %s", bErr, string(out))
		}
		engineBin = filepath.Join("..", "dist", "engine", "policyhelix")
	}

	cleanPath := filepath.Join(c17FixtureDir, "cli-proxy-clean.json")
	cmdClean := exec.Command(engineBin, "-proxy-upstream", cleanPath)
	outClean, err := cmdClean.CombinedOutput()
	if err != nil {
		t.Fatalf("clean CLI proxy command failed: %v\nOutput: %s", err, string(outClean))
	}

	var resClean gateway.ProxyResult
	if err := json.Unmarshal(outClean, &resClean); err != nil {
		t.Fatalf("failed to parse CLI JSON output: %v\nOutput: %s", err, string(outClean))
	}
	if !resClean.Valid || !resClean.Allow || !resClean.ForwardedToUpstream {
		t.Fatalf("expected valid and allowed proxy outcome, got: %+v", resClean)
	}

	// Test negative CLI
	rejectedPath := filepath.Join(c17FixtureDir, "cli-proxy-rejected.json")
	cmdRejected := exec.Command(engineBin, "-proxy-upstream", rejectedPath)
	outRejected, err := cmdRejected.CombinedOutput()
	if err == nil {
		t.Fatalf("expected rejected CLI proxy command to fail with non-zero exit code, got success\nOutput: %s", string(outRejected))
	}

	var resRejected gateway.ProxyResult
	if err := json.Unmarshal(outRejected, &resRejected); err != nil {
		if !strings.Contains(string(outRejected), gateway.ErrCodeUpstreamNotAllowlisted) {
			t.Fatalf("expected output to contain %s, got: %s", gateway.ErrCodeUpstreamNotAllowlisted, string(outRejected))
		}
	} else {
		if resRejected.Allow || resRejected.ForwardedToUpstream {
			t.Fatalf("expected rejected CLI outcome, got: %+v", resRejected)
		}
	}
}

func TestC17_DurableStorageIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policyhelix-c17-store-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	ad, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("storage open failed: %v", err)
	}

	sessStore := auth.NewStorageSessionStore(ad)

	sessionID := "sess-durable-c17-01"
	err = sessStore.SaveSession(ctx, auth.SessionRecord{
		SessionID:    sessionID,
		SubjectID:    "operator-durable",
		Issuer:       "https://auth.policyhelix.local",
		Roles:        []string{"operator"},
		Status:       "ACTIVE",
		SessionEpoch: 1793793600,
		ExpiresAt:    time.Now().Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to save durable session: %v", err)
	}

	// Close and reopen to prove restart recovery
	_ = ad.Close()

	ad2, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("storage reopen failed: %v", err)
	}
	defer ad2.Close()

	sessStore2 := auth.NewStorageSessionStore(ad2)
	revStore2 := auth.NewStorageRevocationStore(ad2)

	cfg := gateway.DefaultUpstreamConfig()
	proxy := gateway.NewAllowlistedGatewayProxy(cfg, sessStore2, revStore2)

	// Positive test after restore
	req := gateway.ProxyRequest{
		RequestID:                "req-durable-01",
		TargetUpstreamID:         "service:analytics",
		Method:                   http.MethodGet,
		Path:                     "/api/v1/analytics",
		SessionID:                sessionID,
		UntrustedHeadersStripped: true,
	}

	res, err := proxy.EvaluateProxyRequest(ctx, req)
	if err != nil {
		t.Fatalf("proxy eval error: %v", err)
	}
	if !res.Valid || !res.Allow || !res.ForwardedToUpstream {
		t.Fatalf("expected allowed proxy forward after restart, got: %+v", res)
	}

	// Now revoke and verify restart durability of revocation
	_ = revStore2.SaveSessionRevocation(ctx, auth.RevocationRecord{
		SessionID: sessionID,
		Reason:    "durable revoke test",
		RevokedAt: time.Now(),
	})

	_ = ad2.Close()

	ad3, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("storage reopen 3 failed: %v", err)
	}
	defer ad3.Close()

	proxy3 := gateway.NewAllowlistedGatewayProxy(cfg, auth.NewStorageSessionStore(ad3), auth.NewStorageRevocationStore(ad3))
	resRevoked, err := proxy3.EvaluateProxyRequest(ctx, req)
	if err != nil {
		t.Fatalf("proxy eval error: %v", err)
	}
	if resRevoked.Allow || resRevoked.ForwardedToUpstream {
		t.Fatalf("expected revoked session to be denied after restart, got: %+v", resRevoked)
	}
	if resRevoked.ErrorCode != gateway.ErrCodeRevokedSessionDenied {
		t.Errorf("expected %s, got %s", gateway.ErrCodeRevokedSessionDenied, resRevoked.ErrorCode)
	}
}
