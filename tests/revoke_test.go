package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	c15FixtureDir = "fixtures/policyhelix/C15"
)

func TestC15_FixturesSuite(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c15FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C15 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C15 manifest: %v", err)
	}
	if manifest.CommitID != "C15" {
		t.Fatalf("expected commit_id C15, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) != 13 {
		t.Fatalf("expected 13 C15 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c15FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		// Verify SHA-256 integrity
		sum := sha256.Sum256(raw)
		if actual := hex.EncodeToString(sum[:]); actual != entry.SHA256 {
			t.Fatalf("SHA-256 mismatch on %s: manifest=%s computed=%s", entry.Path, entry.SHA256, actual)
		}
		if entry.License != "Apache-2.0" {
			t.Fatalf("unexpected license %s on %s", entry.License, entry.Path)
		}

		var spec auth.WorkloadRevocationSpec
		if err := json.Unmarshal(raw, &spec); err != nil {
			t.Fatalf("failed to parse fixture %s: %v", entry.Path, err)
		}
		if spec.CommitID != "C15" || spec.FixtureID != entry.FixtureID {
			t.Fatalf("fixture identity mismatch in %s: %+v", entry.Path, spec)
		}

		t.Run(spec.FixtureID, func(t *testing.T) {
			ctx := context.Background()
			report, err := auth.EvaluateWorkloadSpec(ctx, spec, nil, nil)
			if err != nil {
				t.Fatalf("EvaluateWorkloadSpec unexpected error: %v", err)
			}

			if report.Allow != spec.Expected.Allow {
				t.Errorf("expected allow=%v, got %v (code=%s msg=%s)", spec.Expected.Allow, report.Allow, report.ErrorCode, report.ErrorMessage)
			}
			if report.Valid != spec.Expected.Valid {
				t.Errorf("expected valid=%v, got %v", spec.Expected.Valid, report.Valid)
			}
			if spec.Expected.ErrorCode != "" && report.ErrorCode != spec.Expected.ErrorCode {
				t.Errorf("expected error_code=%s, got %s (%s)", spec.Expected.ErrorCode, report.ErrorCode, report.ErrorMessage)
			}
			if report.SideEffectsExecuted != spec.Expected.SideEffectsExecuted {
				t.Errorf("expected side_effects_executed=%v, got %v", spec.Expected.SideEffectsExecuted, report.SideEffectsExecuted)
			}
			if report.StoppedWithinBound != spec.Expected.StoppedWithinBound {
				t.Errorf("expected stopped_within_bound=%v, got %v", spec.Expected.StoppedWithinBound, report.StoppedWithinBound)
			}
			if spec.Expected.TotalChecks > 0 && report.TotalChecks != spec.Expected.TotalChecks {
				t.Errorf("expected total_checks=%d, got %d", spec.Expected.TotalChecks, report.TotalChecks)
			}
			if spec.Expected.AllowedBeforeRevokeCount > 0 && report.AllowedBeforeRevokeCount != spec.Expected.AllowedBeforeRevokeCount {
				t.Errorf("expected allowed_before_revoke_count=%d, got %d", spec.Expected.AllowedBeforeRevokeCount, report.AllowedBeforeRevokeCount)
			}
			if spec.Expected.DeniedAfterRevokeCount > 0 && report.DeniedAfterRevokeCount != spec.Expected.DeniedAfterRevokeCount {
				t.Errorf("expected denied_after_revoke_count=%d, got %d", spec.Expected.DeniedAfterRevokeCount, report.DeniedAfterRevokeCount)
			}
		})
	}
}

// TestC15_Bounded30SecondTargetWorkload validates Requirement F09:
// "Revoked session stops within configured 30-second bound under target workload."
func TestC15_Bounded30SecondTargetWorkload(t *testing.T) {
	ctx := context.Background()
	sessStore := auth.NewMemorySessionStore()
	revStore := auth.NewMemoryRevocationStore()
	mgr := auth.NewSessionManager(sessStore, auth.SessionConfig{})

	// 1. Reject configuration exceeding 30-second bound
	_, err := auth.NewRevocationEnforcer(mgr, revStore, auth.RevocationConfig{
		StaleWindowSeconds: 45,
	})
	if err == nil {
		t.Fatalf("expected stale_window_seconds > 30 to be rejected")
	}

	// 2. Initialize enforcer with 30s bound
	enforcer, err := auth.NewRevocationEnforcer(mgr, revStore, auth.RevocationConfig{
		StaleWindowSeconds: 30,
		AllowedPaths:       []string{"/api/v1/analytics"},
		AllowedProviders:   []string{"owned_synthetic_upstream"},
	})
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	if enforcer.StaleWindow() != 30*time.Second {
		t.Fatalf("expected 30s stale window, got %v", enforcer.StaleWindow())
	}

	baseTime := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	clientIP := "192.168.10.25"
	userAgent := "PolicyHelix-Workload/1.0"

	// Create 8 sessions for concurrent target workload
	sessionIDs := make([]string, 8)
	for i := 0; i < 8; i++ {
		res, err := mgr.CreateSession(ctx, auth.CreateSessionRequest{
			SubjectID:  fmt.Sprintf("user-worker-%d", i),
			Issuer:     "https://auth.policyhelix.local/realms/policyhelix",
			Roles:      []string{"operator"},
			OwnerScope: "tenant-alpha",
			ClientIP:   clientIP,
			UserAgent:  userAgent,
			ServerCredentials: auth.ServerCredentials{
				Custom: map[string]string{
					"allowed_path_prefix": "/api/v1/analytics",
					"allowed_provider":    "owned_synthetic_upstream",
				},
			},
			TTL:            2 * time.Hour,
			EvaluationTime: baseTime.Add(-10 * time.Minute),
		})
		if err != nil || !res.Valid {
			t.Fatalf("failed to create workload session %d: %v", i, err)
		}
		sessionIDs[i] = res.Session.SessionID
		enforcer.PrimeWorkerLease(*res.Session, baseTime.Add(-5*time.Second))
	}

	// Target session 0 and session 1 for explicit revocation at baseTime
	revokedSessionA := sessionIDs[0]
	revokedSessionB := sessionIDs[1]
	if _, err := enforcer.RevokeSession(ctx, revokedSessionA, "compromised_token", "sec-ops", baseTime); err != nil {
		t.Fatalf("RevokeSession A failed: %v", err)
	}
	if _, err := enforcer.RevokeSession(ctx, revokedSessionB, "operator_logout", "sec-ops", baseTime); err != nil {
		t.Fatalf("RevokeSession B failed: %v", err)
	}

	// Run concurrent target workload across all 8 sessions at multiple offsets (0s..30s)
	var wg sync.WaitGroup
	var revokedPermits int64
	var revokedDenials int64
	var activePermits int64

	offsets := []time.Duration{
		0 * time.Second,
		1 * time.Second,
		10 * time.Second,
		29 * time.Second,
		30 * time.Second,
		35 * time.Second,
	}

	for _, sID := range sessionIDs {
		for _, offset := range offsets {
			wg.Add(1)
			go func(sessionID string, delta time.Duration) {
				defer wg.Done()
				res, err := enforcer.CheckAccess(ctx, auth.AccessCheckRequest{
					SessionID:                sessionID,
					ClientIP:                 clientIP,
					UserAgent:                userAgent,
					UntrustedHeadersStripped: true,
					TargetOwnerScope:         "tenant-alpha",
					RequestedPath:            "/api/v1/analytics/reports",
					RequestedProvider:        "owned_synthetic_upstream",
					ResourceClassification:   "private",
					EvaluationTime:           baseTime.Add(delta),
				})
				if err != nil {
					t.Errorf("CheckAccess unexpected error: %v", err)
					return
				}

				isRevokedTarget := sessionID == revokedSessionA || sessionID == revokedSessionB
				if isRevokedTarget {
					if res.Allow || res.SideEffectsExecuted {
						atomic.AddInt64(&revokedPermits, 1)
					} else if res.ErrorCode == auth.ErrCodeRevokedSession && res.StoppedWithinBound {
						atomic.AddInt64(&revokedDenials, 1)
					}
				} else {
					if res.Allow && res.Valid && res.SideEffectsExecuted {
						atomic.AddInt64(&activePermits, 1)
					}
				}
			}(sID, offset)
		}
	}
	wg.Wait()

	if revokedPermits != 0 {
		t.Fatalf("expected 0 permits for revoked sessions under target workload, got %d", revokedPermits)
	}
	if revokedDenials != int64(2*len(offsets)) {
		t.Fatalf("expected %d revoked denials, got %d", 2*len(offsets), revokedDenials)
	}
	if activePermits != int64(6*len(offsets)) {
		t.Fatalf("expected %d active session permits, got %d", 6*len(offsets), activePermits)
	}
}

// TestC15_DurableStoragePersistence verifies revocation state and monotonic epochs survive storage close/reopen.
func TestC15_DurableStoragePersistence(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	clientIP := "127.0.0.1"
	userAgent := "PolicyHelix-DurableTest/1.0"

	// 1. Open storage adapter, create sessions, and persist revocations
	adapter1, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}

	sessStore1 := auth.NewStorageSessionStore(adapter1)
	revStore1 := auth.NewStorageRevocationStore(adapter1)
	mgr1 := auth.NewSessionManager(sessStore1, auth.SessionConfig{})
	enforcer1, err := auth.NewRevocationEnforcer(mgr1, revStore1, auth.RevocationConfig{
		StaleWindowSeconds: 30,
	})
	if err != nil {
		t.Fatalf("NewRevocationEnforcer failed: %v", err)
	}

	sessA, err := mgr1.CreateSession(ctx, auth.CreateSessionRequest{
		SessionID:      "sess-durable-revoke-a",
		SubjectID:      "user-durable-1",
		Issuer:         "https://auth.policyhelix.local",
		Roles:          []string{"operator"},
		OwnerScope:     "tenant-durable",
		ClientIP:       clientIP,
		UserAgent:      userAgent,
		EvaluationTime: now.Add(-15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateSession A failed: %v", err)
	}

	sessB, err := mgr1.CreateSession(ctx, auth.CreateSessionRequest{
		SessionID:      "sess-durable-epoch-b",
		SubjectID:      "user-durable-2",
		Issuer:         "https://auth.policyhelix.local",
		Roles:          []string{"operator"},
		OwnerScope:     "tenant-durable",
		ClientIP:       clientIP,
		UserAgent:      userAgent,
		EvaluationTime: now.Add(-15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateSession B failed: %v", err)
	}

	// Revoke sessA explicitly and user-durable-2 by subject epoch
	if _, err := enforcer1.RevokeSession(ctx, sessA.Session.SessionID, "durable_session_revoke", "admin-1", now); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
	if _, err := enforcer1.RevokeSubject(ctx, "user-durable-2", now.Unix()+100, "durable_subject_epoch_revoke", "admin-1", now); err != nil {
		t.Fatalf("RevokeSubject failed: %v", err)
	}

	if err := adapter1.Close(); err != nil {
		t.Fatalf("adapter1.Close failed: %v", err)
	}

	// 2. Reopen storage adapter and verify both revocations are enforced
	adapter2, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("reopen storage.Open failed: %v", err)
	}
	defer adapter2.Close()

	sessStore2 := auth.NewStorageSessionStore(adapter2)
	revStore2 := auth.NewStorageRevocationStore(adapter2)
	mgr2 := auth.NewSessionManager(sessStore2, auth.SessionConfig{})
	enforcer2, err := auth.NewRevocationEnforcer(mgr2, revStore2, auth.RevocationConfig{
		StaleWindowSeconds: 30,
	})
	if err != nil {
		t.Fatalf("reopen NewRevocationEnforcer failed: %v", err)
	}

	resA, err := enforcer2.CheckAccess(ctx, auth.AccessCheckRequest{
		SessionID:                sessA.Session.SessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		TargetOwnerScope:         "tenant-durable",
		ResourceClassification:   "private",
		EvaluationTime:           now.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("CheckAccess A failed: %v", err)
	}
	if resA.Allow || resA.ErrorCode != auth.ErrCodeRevokedSession || resA.SideEffectsExecuted {
		t.Fatalf("expected durable revoked session A to be denied, got %+v", resA)
	}

	resB, err := enforcer2.CheckAccess(ctx, auth.AccessCheckRequest{
		SessionID:                sessB.Session.SessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		TargetOwnerScope:         "tenant-durable",
		ResourceClassification:   "private",
		EvaluationTime:           now.Add(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("CheckAccess B failed: %v", err)
	}
	if resB.Allow || resB.ErrorCode != auth.ErrCodeRevokedSession || resB.SideEffectsExecuted {
		t.Fatalf("expected durable subject-epoch revoked session B to be denied, got %+v", resB)
	}
}

// TestC15_NegativeSecurityInvariants verifies all required C15 negative cases fail before side effects.
func TestC15_NegativeSecurityInvariants(t *testing.T) {
	ctx := context.Background()
	sessStore := auth.NewMemorySessionStore()
	revStore := auth.NewMemoryRevocationStore()
	mgr := auth.NewSessionManager(sessStore, auth.SessionConfig{})
	enforcer, err := auth.NewRevocationEnforcer(mgr, revStore, auth.RevocationConfig{
		StaleWindowSeconds: 30,
		AllowedPaths:       []string{"/api/v1/analytics"},
		AllowedProviders:   []string{"owned_synthetic_upstream"},
	})
	if err != nil {
		t.Fatalf("NewRevocationEnforcer failed: %v", err)
	}

	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	clientIP := "10.10.1.5"
	userAgent := "PolicyHelix-SecTest/1.0"

	created, err := mgr.CreateSession(ctx, auth.CreateSessionRequest{
		SessionID:  "sess-neg-active",
		SubjectID:  "user-operator",
		Issuer:     "https://auth.policyhelix.local",
		Roles:      []string{"operator"},
		OwnerScope: "tenant-alpha",
		ClientIP:   clientIP,
		UserAgent:  userAgent,
		ServerCredentials: auth.ServerCredentials{
			Custom: map[string]string{
				"allowed_path_prefix": "/api/v1/analytics",
				"allowed_provider":    "owned_synthetic_upstream",
			},
		},
		TTL:            1 * time.Hour,
		EvaluationTime: now,
	})
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	sid := created.Session.SessionID

	// 1. Single-use request ID replay fails before side effects
	firstReq := auth.AccessCheckRequest{
		RequestID:                "req-once-001",
		SingleUseRequest:         true,
		SessionID:                sid,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		TargetOwnerScope:         "tenant-alpha",
		RequestedPath:            "/api/v1/analytics/reports",
		RequestedProvider:        "owned_synthetic_upstream",
		EvaluationTime:           now.Add(1 * time.Minute),
	}
	res1, _ := enforcer.CheckAccess(ctx, firstReq)
	if !res1.Allow {
		t.Fatalf("expected first single-use request to succeed, got %+v", res1)
	}
	resReplay, _ := enforcer.CheckAccess(ctx, firstReq)
	if resReplay.Allow || resReplay.ErrorCode != auth.ErrCodeReplayedIdentity || resReplay.SideEffectsExecuted {
		t.Errorf("expected REPLAYED_IDENTITY_REJECTED with no side effects, got %+v", resReplay)
	}

	// 2. Path traversal / widened path fails closed
	resTraversal, _ := enforcer.CheckAccess(ctx, auth.AccessCheckRequest{
		SessionID:                sid,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		TargetOwnerScope:         "tenant-alpha",
		RequestedPath:            "/api/v1/analytics/../../admin/secrets",
		RequestedProvider:        "owned_synthetic_upstream",
		EvaluationTime:           now.Add(2 * time.Minute),
	})
	if resTraversal.Allow || resTraversal.ErrorCode != auth.ErrCodeWidenedPermissionDenied || resTraversal.SideEffectsExecuted {
		t.Errorf("expected WIDENED_PERMISSION_DENIED on path traversal, got %+v", resTraversal)
	}

	// 3. Widened provider permission fails closed
	resProv, _ := enforcer.CheckAccess(ctx, auth.AccessCheckRequest{
		SessionID:                sid,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		TargetOwnerScope:         "tenant-alpha",
		RequestedPath:            "/api/v1/analytics/reports",
		RequestedProvider:        "unapproved_cloud_provider",
		EvaluationTime:           now.Add(2 * time.Minute),
	})
	if resProv.Allow || resProv.ErrorCode != auth.ErrCodeWidenedPermissionDenied || resProv.SideEffectsExecuted {
		t.Errorf("expected WIDENED_PERMISSION_DENIED on widened provider, got %+v", resProv)
	}

	// 4. Scope revocation stops all sessions in that owner_scope
	if _, err := enforcer.RevokeScope(ctx, "tenant-alpha", now.Unix()+500, "tenant_emergency_lockdown", "sec-admin", now.Add(3*time.Minute)); err != nil {
		t.Fatalf("RevokeScope failed: %v", err)
	}
	resScopeRev, _ := enforcer.CheckAccess(ctx, auth.AccessCheckRequest{
		SessionID:                sid,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		TargetOwnerScope:         "tenant-alpha",
		RequestedPath:            "/api/v1/analytics/reports",
		RequestedProvider:        "owned_synthetic_upstream",
		EvaluationTime:           now.Add(3*time.Minute + 5*time.Second),
	})
	if resScopeRev.Allow || resScopeRev.ErrorCode != auth.ErrCodeRevokedSession || resScopeRev.SideEffectsExecuted {
		t.Errorf("expected REVOKED_SESSION after scope revocation, got %+v", resScopeRev)
	}
}

// TestC15_CLIValidation verifies engine CLI invocations with -enforce-revocation.
func TestC15_CLIValidation(t *testing.T) {
	cmdPath := filepath.Join("..", "cmd", "policyhelix")

	// 1. Positive CLI workload fixture exits 0
	posPath := filepath.Join(c15FixtureDir, "cli-revoke-workload.json")
	cmdPos := exec.Command("go", "run", cmdPath, "-enforce-revocation", posPath)
	var stdoutPos, stderrPos bytes.Buffer
	cmdPos.Stdout = &stdoutPos
	cmdPos.Stderr = &stderrPos
	if err := cmdPos.Run(); err != nil {
		t.Fatalf("CLI positive workload failed: %v, stderr: %s", err, stderrPos.String())
	}

	var posReport auth.WorkloadEvaluationReport
	if err := json.Unmarshal(stdoutPos.Bytes(), &posReport); err != nil {
		t.Fatalf("failed to unmarshal CLI workload report: %v\nstdout: %s", err, stdoutPos.String())
	}
	if !posReport.StoppedWithinBound || posReport.DeniedAfterRevokeCount != 1 || posReport.AllowedBeforeRevokeCount != 1 {
		t.Errorf("unexpected positive CLI workload report: %+v", posReport)
	}

	// 2. Negative CLI fixture exits non-zero
	negPath := filepath.Join(c15FixtureDir, "cli-revoke-rejected.json")
	cmdNeg := exec.Command("go", "run", cmdPath, "-enforce-revocation", negPath)
	var stdoutNeg, stderrNeg bytes.Buffer
	cmdNeg.Stdout = &stdoutNeg
	cmdNeg.Stderr = &stderrNeg
	if err := cmdNeg.Run(); err == nil {
		t.Fatalf("expected non-zero exit code for rejected CLI fixture, but succeeded")
	}

	var negReport auth.WorkloadEvaluationReport
	if err := json.Unmarshal(stdoutNeg.Bytes(), &negReport); err != nil {
		t.Fatalf("failed to unmarshal CLI negative report: %v\nstdout: %s", err, stdoutNeg.String())
	}
	if negReport.Allow || negReport.ErrorCode != auth.ErrCodeRevokedSession || negReport.SideEffectsExecuted {
		t.Errorf("expected REVOKED_SESSION with no side effects in CLI output, got %+v", negReport)
	}
}
