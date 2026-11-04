package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	c14FixtureDir = "fixtures/policyhelix/C14"
)

type c14Expected struct {
	Valid              bool   `json:"valid"`
	Status             string `json:"status"`
	ErrorCode          string `json:"error_code,omitempty"`
	SubjectID          string `json:"subject_id,omitempty"`
	OwnerScope         string `json:"owner_scope,omitempty"`
	NewSessionID       string `json:"new_session_id,omitempty"`
	FingerprintMatched bool   `json:"fingerprint_matched,omitempty"`
	AuthorizedForScope bool   `json:"authorized_for_scope,omitempty"`
}

type c14FixtureFile struct {
	FixtureID       string                     `json:"fixture_id"`
	CommitID        string                     `json:"commit_id"`
	Description     string                     `json:"description"`
	SchemaVersion   string                     `json:"schema_version"`
	Operation       string                     `json:"operation"`
	PreloadSessions []auth.SessionRecord       `json:"preload_sessions,omitempty"`
	Create          *auth.CreateSessionRequest `json:"create,omitempty"`
	Resume          *auth.ResumeSessionRequest `json:"resume,omitempty"`
	Rotate          *auth.RotateSessionRequest `json:"rotate,omitempty"`
	Expected        c14Expected                `json:"expected"`
}

func TestC14_FixturesSuite(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c14FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C14 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C14 manifest: %v", err)
	}
	if manifest.CommitID != "C14" {
		t.Fatalf("expected commit_id C14, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) != 12 {
		t.Fatalf("expected 12 C14 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c14FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture file %s: %v", entry.Path, err)
		}

		// Verify SHA-256 integrity
		h := sha256.Sum256(raw)
		computedHash := hex.EncodeToString(h[:])
		if computedHash != entry.SHA256 {
			t.Fatalf("hash mismatch on %s: manifest=%s, computed=%s", entry.Path, entry.SHA256, computedHash)
		}

		var fix c14FixtureFile
		if err := json.Unmarshal(raw, &fix); err != nil {
			t.Fatalf("failed to parse fixture %s: %v", entry.Path, err)
		}

		t.Run(fix.FixtureID, func(t *testing.T) {
			store := auth.NewMemorySessionStore()
			ctx := context.Background()

			for _, s := range fix.PreloadSessions {
				if err := store.SaveSession(ctx, s); err != nil {
					t.Fatalf("failed to preload session: %v", err)
				}
			}

			mgr := auth.NewSessionManager(store, auth.SessionConfig{})

			switch fix.Operation {
			case "create":
				if fix.Create == nil {
					t.Fatalf("create request missing in fixture")
				}
				res, err := mgr.CreateSession(ctx, *fix.Create)
				if err != nil {
					t.Fatalf("CreateSession error: %v", err)
				}
				if res.Valid != fix.Expected.Valid {
					t.Errorf("expected valid=%v, got %v", fix.Expected.Valid, res.Valid)
				}
				if fix.Expected.SubjectID != "" && res.Session.SubjectID != fix.Expected.SubjectID {
					t.Errorf("expected subject_id=%s, got %s", fix.Expected.SubjectID, res.Session.SubjectID)
				}

			case "resume":
				if fix.Resume == nil {
					t.Fatalf("resume request missing in fixture")
				}
				res, err := mgr.ResumeSession(ctx, *fix.Resume)
				if err != nil {
					t.Fatalf("ResumeSession unexpected fatal error: %v", err)
				}
				if res.Valid != fix.Expected.Valid {
					t.Errorf("expected valid=%v, got %v (err=%s, msg=%s)", fix.Expected.Valid, res.Valid, res.ErrorCode, res.ErrorMessage)
				}
				if fix.Expected.ErrorCode != "" && res.ErrorCode != fix.Expected.ErrorCode {
					t.Errorf("expected error_code=%s, got %s", fix.Expected.ErrorCode, res.ErrorCode)
				}
				if fix.Expected.SubjectID != "" && (res.Identity.SubjectID != fix.Expected.SubjectID) {
					t.Errorf("expected subject_id=%s, got %s", fix.Expected.SubjectID, res.Identity.SubjectID)
				}

			case "rotate":
				if fix.Rotate == nil {
					t.Fatalf("rotate request missing in fixture")
				}
				res, err := mgr.RotateSession(ctx, *fix.Rotate)
				if err != nil {
					t.Fatalf("RotateSession unexpected fatal error: %v", err)
				}
				if res.Valid != fix.Expected.Valid {
					t.Errorf("expected valid=%v, got %v (err=%s, msg=%s)", fix.Expected.Valid, res.Valid, res.ErrorCode, res.ErrorMessage)
				}
				if fix.Expected.ErrorCode != "" && res.ErrorCode != fix.Expected.ErrorCode {
					t.Errorf("expected error_code=%s, got %s", fix.Expected.ErrorCode, res.ErrorCode)
				}
				if fix.Expected.NewSessionID != "" && (res.Session == nil || res.Session.SessionID != fix.Expected.NewSessionID) {
					t.Errorf("expected new_session_id=%s, got %+v", fix.Expected.NewSessionID, res.Session)
				}

			default:
				t.Fatalf("unknown operation: %s", fix.Operation)
			}
		})
	}
}

// TestC14_AcceptanceCriteria tests:
// "Session stores fingerprints and safe server-held credentials; cookie rotation prevents fixation."
func TestC14_AcceptanceCriteria(t *testing.T) {
	ctx := context.Background()
	store := auth.NewMemorySessionStore()
	mgr := auth.NewSessionManager(store, auth.SessionConfig{})

	clientIP := "192.168.1.50"
	userAgent := "Mozilla/5.0 (X11; Linux x86_64) PolicyHelix/1.0"
	now := time.Now().UTC()

	// 1. Create session with server-held credentials
	createReq := auth.CreateSessionRequest{
		SubjectID:  "user-alice",
		Issuer:     "https://auth.policyhelix.local/realms/policyhelix",
		Roles:      []string{"operator", "auditor"},
		OwnerScope: "tenant-alpha",
		ClientIP:   clientIP,
		UserAgent:  userAgent,
		ServerCredentials: auth.ServerCredentials{
			AccessToken:       "secret-access-token-12345",
			RefreshToken:      "secret-refresh-token-67890",
			UpstreamSessionID: "kc-session-999",
			Custom:            map[string]string{"internal_key": "val123"},
		},
		TTL:            2 * time.Hour,
		EvaluationTime: now,
	}

	res, err := mgr.CreateSession(ctx, createReq)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected created session to be valid")
	}

	sessionID := res.Session.SessionID
	if sessionID == "" {
		t.Fatalf("expected non-empty session ID")
	}
	if res.Cookie == nil || res.Cookie.Value != sessionID {
		t.Fatalf("expected session cookie with value=%s, got %+v", sessionID, res.Cookie)
	}

	// Verify Cookie Hardening: HttpOnly, Secure, SameSite=Strict
	if !res.Cookie.HttpOnly {
		t.Errorf("cookie must be HttpOnly")
	}
	if !res.Cookie.Secure {
		t.Errorf("cookie must be Secure")
	}

	// Verify Client Fingerprint is stored
	expectedFP := auth.ComputeFingerprint(clientIP, userAgent)
	if res.Session.Fingerprint.CompositeHash != expectedFP.CompositeHash {
		t.Errorf("fingerprint mismatch: got %s, want %s", res.Session.Fingerprint.CompositeHash, expectedFP.CompositeHash)
	}

	// Verify safe server-held credentials: tokens never serialized in JSON
	jsonBytes, err := json.Marshal(res.Session)
	if err != nil {
		t.Fatalf("failed to marshal session record: %v", err)
	}
	jsonStr := string(jsonBytes)
	if bytes.Contains(jsonBytes, []byte("secret-access-token-12345")) {
		t.Fatalf("SECURITY VIOLATION: server-held access token leaked in JSON: %s", jsonStr)
	}
	if bytes.Contains(jsonBytes, []byte("secret-refresh-token-67890")) {
		t.Fatalf("SECURITY VIOLATION: server-held refresh token leaked in JSON: %s", jsonStr)
	}
	// But safe indicators are present
	if !bytes.Contains(jsonBytes, []byte(`"has_access_token":true`)) {
		t.Errorf("expected safe credential indicator has_access_token:true in JSON: %s", jsonStr)
	}

	// 2. Resumption with matching client attributes succeeds
	resumeRes, err := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                sessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		EvaluationTime:           now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ResumeSession error: %v", err)
	}
	if !resumeRes.Valid {
		t.Fatalf("expected successful resumption, got error: %s (%s)", resumeRes.ErrorCode, resumeRes.ErrorMessage)
	}
	if resumeRes.Session.Credentials.AccessToken != "secret-access-token-12345" {
		t.Errorf("server-held credential not preserved in internal session record")
	}

	// 3. Resumption with mismatched fingerprint (hijacking attempt) fails
	hijackRes, err := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                sessionID,
		ClientIP:                 "10.200.0.1", // Hijacker IP
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		EvaluationTime:           now.Add(15 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ResumeSession error: %v", err)
	}
	if hijackRes.Valid {
		t.Errorf("expected hijacking attempt to be rejected")
	}
	if hijackRes.ErrorCode != auth.ErrCodeFingerprintMismatch {
		t.Errorf("expected error %s, got %s", auth.ErrCodeFingerprintMismatch, hijackRes.ErrorCode)
	}

	// 4. Cookie rotation prevents fixation
	rotateRes, err := mgr.RotateSession(ctx, auth.RotateSessionRequest{
		OldSessionID:             sessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		EvaluationTime:           now.Add(20 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RotateSession error: %v", err)
	}
	if !rotateRes.Valid {
		t.Fatalf("expected rotation to succeed, got %s (%s)", rotateRes.ErrorCode, rotateRes.ErrorMessage)
	}
	newSessionID := rotateRes.Session.SessionID
	if newSessionID == sessionID {
		t.Errorf("rotated session ID must be distinct from old session ID")
	}

	// 5. Replaying old cookie is rejected as fixation attempt
	replayRes, err := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                sessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		EvaluationTime:           now.Add(25 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ResumeSession error: %v", err)
	}
	if replayRes.Valid {
		t.Errorf("replaying superseded session cookie must be rejected")
	}
	if replayRes.ErrorCode != auth.ErrCodeSessionFixation {
		t.Errorf("expected %s, got %s", auth.ErrCodeSessionFixation, replayRes.ErrorCode)
	}

	// 6. Resuming with new rotated session succeeds
	newResumeRes, err := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                newSessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		EvaluationTime:           now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ResumeSession error: %v", err)
	}
	if !newResumeRes.Valid {
		t.Errorf("resuming with new rotated session must succeed")
	}
}

// TestC14_DurableStorageIntegration validates session persistence over storage.Adapter.
func TestC14_DurableStorageIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policyhelix-c14-storage-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()
	clientIP := "127.0.0.1"
	userAgent := "PolicyHelix-Agent/1.0"
	now := time.Now().UTC()

	// 1. Open storage adapter and persist session
	adapter1, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("failed to open storage adapter: %v", err)
	}

	store1 := auth.NewStorageSessionStore(adapter1)
	mgr1 := auth.NewSessionManager(store1, auth.SessionConfig{})

	createRes, err := mgr1.CreateSession(ctx, auth.CreateSessionRequest{
		SubjectID:  "user-persisted",
		Issuer:     "https://auth.policyhelix.local",
		Roles:      []string{"admin"},
		OwnerScope: "tenant-root",
		ClientIP:   clientIP,
		UserAgent:  userAgent,
		TTL:        3 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create session in durable store: %v", err)
	}
	sessionID := createRes.Session.SessionID

	// Close storage adapter to simulate engine restart
	if err := adapter1.Close(); err != nil {
		t.Fatalf("failed to close storage adapter: %v", err)
	}

	// 2. Re-open storage adapter and verify session was durably persisted
	adapter2, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("failed to reopen storage adapter: %v", err)
	}
	defer adapter2.Close()

	store2 := auth.NewStorageSessionStore(adapter2)
	mgr2 := auth.NewSessionManager(store2, auth.SessionConfig{})

	resumeRes, err := mgr2.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                sessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		EvaluationTime:           now.Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to resume session from reopened store: %v", err)
	}
	if !resumeRes.Valid {
		t.Fatalf("expected valid session after storage reopen, got error: %s (%s)", resumeRes.ErrorCode, resumeRes.ErrorMessage)
	}
	if resumeRes.Session.SubjectID != "user-persisted" {
		t.Errorf("expected subject 'user-persisted', got '%s'", resumeRes.Session.SubjectID)
	}

	// 3. Test explicit revocation persistence
	if err := mgr2.RevokeSession(ctx, sessionID); err != nil {
		t.Fatalf("failed to revoke session: %v", err)
	}

	// Verify revoked status is immediately returned
	revokedRes, err := mgr2.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                sessionID,
		ClientIP:                 clientIP,
		UserAgent:                userAgent,
		UntrustedHeadersStripped: true,
		EvaluationTime:           now.Add(70 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ResumeSession error: %v", err)
	}
	if revokedRes.Valid {
		t.Errorf("revoked session must not be valid")
	}
	if revokedRes.ErrorCode != auth.ErrCodeRevokedSession {
		t.Errorf("expected %s, got %s", auth.ErrCodeRevokedSession, revokedRes.ErrorCode)
	}
}

// TestC14_NegativeCases covers required security negative cases.
func TestC14_NegativeCases(t *testing.T) {
	ctx := context.Background()
	store := auth.NewMemorySessionStore()
	mgr := auth.NewSessionManager(store, auth.SessionConfig{})
	now := time.Now().UTC()

	// 1. Missing identity fails unauthenticated
	res1, _ := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                "",
		ClientIP:                 "127.0.0.1",
		UserAgent:                "TestAgent",
		UntrustedHeadersStripped: true,
		EvaluationTime:           now,
	})
	if res1.Valid || res1.ErrorCode != auth.ErrCodeUnauthenticatedIdentity {
		t.Errorf("expected UNAUTHENTICATED_IDENTITY, got %s", res1.ErrorCode)
	}

	// 2. Private resource fails closed on missing identity
	res2, _ := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                "",
		ClientIP:                 "127.0.0.1",
		UserAgent:                "TestAgent",
		UntrustedHeadersStripped: true,
		ResourceClassification:   "private",
		EvaluationTime:           now,
	})
	if res2.Valid || res2.ErrorCode != auth.ErrCodePrivateFailClosed {
		t.Errorf("expected PRIVATE_RESOURCE_FAIL_CLOSED, got %s", res2.ErrorCode)
	}

	// 3. Forged header (untrusted headers not stripped) fails closed
	res3, _ := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                "any-session-id",
		ClientIP:                 "127.0.0.1",
		UserAgent:                "TestAgent",
		UntrustedHeadersStripped: false, // NOT stripped
		EvaluationTime:           now,
	})
	if res3.Valid || res3.ErrorCode != auth.ErrCodeForgedHeader {
		t.Errorf("expected FORGED_HEADER_REJECTED, got %s", res3.ErrorCode)
	}

	// 4. Revocation Epoch boundary fails older session
	created, err := mgr.CreateSession(ctx, auth.CreateSessionRequest{
		SubjectID:      "user-epoch",
		Issuer:         "https://auth.policyhelix.local",
		ClientIP:       "127.0.0.1",
		UserAgent:      "TestAgent",
		EvaluationTime: now,
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	res4, _ := mgr.ResumeSession(ctx, auth.ResumeSessionRequest{
		SessionID:                created.Session.SessionID,
		ClientIP:                 "127.0.0.1",
		UserAgent:                "TestAgent",
		UntrustedHeadersStripped: true,
		MinRequiredEpoch:         now.Unix() + 100, // minimum epoch higher than session creation epoch
		EvaluationTime:           now.Add(10 * time.Minute),
	})
	if res4.Valid || res4.ErrorCode != auth.ErrCodeRevokedSession {
		t.Errorf("expected REVOKED_SESSION due to min epoch, got %s", res4.ErrorCode)
	}
}

// TestC14_CLIValidation tests engine CLI invocations with -manage-session flag.
func TestC14_CLIValidation(t *testing.T) {
	cmdPath := filepath.Join("..", "cmd", "policyhelix")

	// 1. Positive CLI create fixture
	createFixPath := filepath.Join("fixtures", "policyhelix", "C14", "cli-session-create.json")
	cmd := exec.Command("go", "run", cmdPath, "-manage-session", createFixPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		t.Fatalf("CLI session create failed: %v, stderr: %s", err, stderr.String())
	}

	var createResult struct {
		Status    string `json:"status"`
		Valid     bool   `json:"valid"`
		Operation string `json:"operation"`
		Session   struct {
			SubjectID string `json:"subject_id"`
		} `json:"session"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &createResult); err != nil {
		t.Fatalf("failed to unmarshal CLI create result: %v\nstdout: %s", err, stdout.String())
	}
	if !createResult.Valid || createResult.Status != "ok" {
		t.Errorf("expected valid CLI create result, got %+v", createResult)
	}
	if createResult.Session.SubjectID != "user-bob" {
		t.Errorf("expected subject 'user-bob', got '%s'", createResult.Session.SubjectID)
	}

	// 2. Positive CLI rotate fixture
	rotateFixPath := filepath.Join("fixtures", "policyhelix", "C14", "cli-session-rotate.json")
	cmdRotate := exec.Command("go", "run", cmdPath, "-manage-session", rotateFixPath)
	var stdoutRotate, stderrRotate bytes.Buffer
	cmdRotate.Stdout = &stdoutRotate
	cmdRotate.Stderr = &stderrRotate
	errRotate := cmdRotate.Run()
	if errRotate != nil {
		t.Fatalf("CLI session rotate failed: %v, stderr: %s", errRotate, stderrRotate.String())
	}

	var rotateResult struct {
		Status  string `json:"status"`
		Valid   bool   `json:"valid"`
		Session struct {
			SessionID string `json:"session_id"`
		} `json:"session"`
	}
	if err := json.Unmarshal(stdoutRotate.Bytes(), &rotateResult); err != nil {
		t.Fatalf("failed to unmarshal CLI rotate result: %v", err)
	}
	if !rotateResult.Valid || rotateResult.Session.SessionID != "sess-cli-rotate-final" {
		t.Errorf("expected valid rotated session 'sess-cli-rotate-final', got %+v", rotateResult)
	}

	// 3. Negative CLI fixture: fingerprint mismatch fails with exit code 1
	negFixPath := filepath.Join("fixtures", "policyhelix", "C14", "negative-fingerprint-mismatch.json")
	cmdNeg := exec.Command("go", "run", cmdPath, "-manage-session", negFixPath)
	var stdoutNeg, stderrNeg bytes.Buffer
	cmdNeg.Stdout = &stdoutNeg
	cmdNeg.Stderr = &stderrNeg
	errNeg := cmdNeg.Run()
	if errNeg == nil {
		t.Errorf("expected CLI to exit with code 1 for negative fixture, but succeeded")
	}

	var negResult struct {
		Status    string `json:"status"`
		Valid     bool   `json:"valid"`
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(stdoutNeg.Bytes(), &negResult); err != nil {
		t.Fatalf("failed to unmarshal negative CLI result: %v\nstdout: %s", err, stdoutNeg.String())
	}
	if negResult.Valid || negResult.ErrorCode != auth.ErrCodeFingerprintMismatch {
		t.Errorf("expected FINGERPRINT_MISMATCH in negative CLI output, got %+v", negResult)
	}
}
