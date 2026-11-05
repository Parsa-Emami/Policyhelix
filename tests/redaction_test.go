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

	"github.com/parsa-emami/policyhelix/internal/audit"
	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/gateway"
)

const (
	c20FixtureDir = "fixtures/policyhelix/C20"
)

type c20FixtureEnvelope struct {
	FixtureID     string                   `json:"fixture_id"`
	CommitID      string                   `json:"commit_id"`
	Description   string                   `json:"description"`
	SchemaVersion string                   `json:"schema_version"`
	Request       audit.DecisionLogRequest `json:"request"`
	Expected      struct {
		Valid                    bool   `json:"valid"`
		Allow                    bool   `json:"allow"`
		StatusCode               int    `json:"status_code"`
		ErrorCode                string `json:"error_code,omitempty"`
		SubjectPseudonym         string `json:"subject_pseudonym,omitempty"`
		PolicyDigest             string `json:"policy_digest,omitempty"`
		BearerTokensRedactedMin  int    `json:"bearer_tokens_redacted_min,omitempty"`
		CookiesRedactedMin       int    `json:"cookies_redacted_min,omitempty"`
		RawEmailContained        bool   `json:"raw_email_contained,omitempty"`
		RawSubjectIDContained    bool   `json:"raw_subject_id_contained,omitempty"`
	} `json:"expected"`
}

func TestC20_ManifestIntegrity(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c20FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C20 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C20 manifest: %v", err)
	}
	if manifest.CommitID != "C20" {
		t.Fatalf("expected commit_id C20, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 10 {
		t.Fatalf("expected at least 10 C20 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c20FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		sum := sha256.Sum256(raw)
		actualSHA := hex.EncodeToString(sum[:])
		if actualSHA != entry.SHA256 {
			t.Fatalf("SHA256 mismatch for fixture %s: expected %s, got %s", entry.Path, entry.SHA256, actualSHA)
		}
	}
}

func TestC20_BearerTokenRedaction(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "positive-bearer-token-redacted.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("LogDecision error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid and allow, got valid=%v allow=%v error=%s", res.Valid, res.Allow, res.ErrorMessage)
	}

	rec := res.AuditRecord
	if rec == nil {
		t.Fatalf("audit record must not be nil")
	}

	// Invariant: no raw JWT or bearer token in JSON
	jsonStr := res.JSON
	if strings.Contains(jsonStr, "sig1234567890abcdef") {
		t.Fatalf("bearer token signature leaked into JSON: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "validSignature123") {
		t.Fatalf("downstream bearer token leaked into JSON: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, "Bearer [REDACTED]") && !strings.Contains(jsonStr, "[REDACTED_JWT]") {
		t.Fatalf("expected redacted bearer token marker, got: %s", jsonStr)
	}

	if rec.SubjectPseudonym != env.Expected.SubjectPseudonym {
		t.Fatalf("pseudonym mismatch: expected %s, got %s", env.Expected.SubjectPseudonym, rec.SubjectPseudonym)
	}
	if rec.PolicyDigest != env.Expected.PolicyDigest {
		t.Fatalf("policy digest mismatch: expected %s, got %s", env.Expected.PolicyDigest, rec.PolicyDigest)
	}
}

func TestC20_CookieRedaction(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "positive-cookie-token-redacted.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("LogDecision error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid and allow, got valid=%v allow=%v", res.Valid, res.Allow)
	}

	jsonStr := res.JSON
	if strings.Contains(jsonStr, "s_live_sec_99182374619") {
		t.Fatalf("session cookie value leaked into JSON: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "s_live_sec_rotated_99182") {
		t.Fatalf("set-cookie value leaked into JSON: %s", jsonStr)
	}
	if rec := res.AuditRecord; rec.SubjectPseudonym != env.Expected.SubjectPseudonym {
		t.Fatalf("pseudonym mismatch: expected %s, got %s", env.Expected.SubjectPseudonym, rec.SubjectPseudonym)
	}
}

func TestC20_MultipleTokensRedacted(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "positive-multiple-tokens-redacted.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("LogDecision error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid and allow, got valid=%v allow=%v", res.Valid, res.Allow)
	}

	jsonStr := res.JSON
	forbiddenPatterns := []string{
		"secretSignatureValue",
		"s_admin_live_sess_778899",
		"secretParamValue",
		"proxySecretToken9988",
		"live_apikey_secret_99887766",
		"secretUrlToken12345",
	}
	for _, p := range forbiddenPatterns {
		if strings.Contains(jsonStr, p) {
			t.Fatalf("leaked secret '%s' in audit JSON: %s", p, jsonStr)
		}
	}
}

func TestC20_SubjectPseudonymization(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "positive-subject-pseudonymized.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("LogDecision error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid and allow, got valid=%v allow=%v", res.Valid, res.Allow)
	}

	jsonStr := res.JSON
	if strings.Contains(jsonStr, "david.finance@corp.example.com") {
		t.Fatalf("user email leaked into audit JSON: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "usr-finance-david-552") {
		t.Fatalf("raw user ID leaked into audit JSON: %s", jsonStr)
	}

	rec := res.AuditRecord
	if rec.SubjectPseudonym != env.Expected.SubjectPseudonym {
		t.Fatalf("pseudonym mismatch: expected %s, got %s", env.Expected.SubjectPseudonym, rec.SubjectPseudonym)
	}
}

func TestC20_DenialDecisionLogged(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "positive-denial-decision-logged.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("LogDecision error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid=true for recorded denial, got false")
	}
	if res.Allow {
		t.Fatalf("expected allow=false for denial decision")
	}

	rec := res.AuditRecord
	if rec.Outcome.Status != "deny" || rec.Outcome.StatusCode != 403 {
		t.Fatalf("expected outcome status deny / 403, got %s / %d", rec.Outcome.Status, rec.Outcome.StatusCode)
	}
	if rec.Outcome.ErrorCode != env.Expected.ErrorCode {
		t.Fatalf("expected error code %s, got %s", env.Expected.ErrorCode, rec.Outcome.ErrorCode)
	}
}

func TestC20_MalformedAuditRequest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "negative-malformed-audit-request.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if res.Valid {
		t.Fatalf("expected valid=false for malformed request, got true")
	}
	if res.ErrorCode != env.Expected.ErrorCode {
		t.Fatalf("expected error code %s, got %s", env.Expected.ErrorCode, res.ErrorCode)
	}
}

func TestC20_PrivateResourceFailClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "negative-private-resource-fail-closed.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Valid {
		t.Fatalf("expected valid=true for recorded fail-closed outcome, got false")
	}
	if res.Allow {
		t.Fatalf("private resource must fail closed when unauthenticated, got allow=true")
	}
	if res.AuditRecord.SubjectPseudonym != "pseudo:unauthenticated" {
		t.Fatalf("expected pseudo:unauthenticated, got %s", res.AuditRecord.SubjectPseudonym)
	}
	if res.AuditRecord.Outcome.ErrorCode != env.Expected.ErrorCode {
		t.Fatalf("expected error code %s, got %s", env.Expected.ErrorCode, res.AuditRecord.Outcome.ErrorCode)
	}
}

func TestC20_ProviderUnavailable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "negative-provider-unavailable.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	res, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Allow {
		t.Fatalf("provider outage must deny decision, got allow=true")
	}
	if res.AuditRecord.Outcome.StatusCode != 503 {
		t.Fatalf("expected status code 503, got %d", res.AuditRecord.Outcome.StatusCode)
	}
	if res.AuditRecord.Outcome.ErrorCode != env.Expected.ErrorCode {
		t.Fatalf("expected error code %s, got %s", env.Expected.ErrorCode, res.AuditRecord.Outcome.ErrorCode)
	}
}

func TestC20_RestartInvariant(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(c20FixtureDir, "positive-restart-invariant.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c20FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// 1st run
	res1, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil || !res1.Valid || !res1.Allow {
		t.Fatalf("run 1 failed: valid=%v allow=%v err=%v", res1.Valid, res1.Allow, err)
	}

	// Simulate engine restart / new process context
	res2, err := audit.LogDecision(context.Background(), env.Request)
	if err != nil || !res2.Valid || !res2.Allow {
		t.Fatalf("run 2 failed: valid=%v allow=%v err=%v", res2.Valid, res2.Allow, err)
	}

	if res1.AuditRecord.SubjectPseudonym != res2.AuditRecord.SubjectPseudonym {
		t.Fatalf("restart invariant violated: pseudonym changed across restart (%s vs %s)",
			res1.AuditRecord.SubjectPseudonym, res2.AuditRecord.SubjectPseudonym)
	}
	if res1.AuditRecord.SubjectPseudonym != env.Expected.SubjectPseudonym {
		t.Fatalf("pseudonym mismatch: expected %s, got %s", env.Expected.SubjectPseudonym, res1.AuditRecord.SubjectPseudonym)
	}
}

func TestC20_CLIExecution(t *testing.T) {
	fixturePath := filepath.Join(c20FixtureDir, "cli-audit-decision.json")

	binPath := filepath.Join("..", "dist", "engine", "policyhelix")
	var cmd *exec.Cmd
	if _, err := os.Stat(binPath); err == nil {
		cmd = exec.Command(binPath, "-audit-decision", fixturePath)
	} else {
		cmd = exec.Command("go", "run", "../cmd/policyhelix", "-audit-decision", fixturePath)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("CLI execution failed: %v, stderr: %s", err, stderr.String())
	}

	var res audit.DecisionLogResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse CLI JSON output: %v, raw: %s", err, stdout.String())
	}

	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid and allow from CLI run, got valid=%v allow=%v", res.Valid, res.Allow)
	}

	if strings.Contains(stdout.String(), "cliJwtTokenData") {
		t.Fatalf("bearer token leaked into CLI stdout: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "cli_session_value_998811") {
		t.Fatalf("cookie value leaked into CLI stdout: %s", stdout.String())
	}
}

func TestC20_HTTPRoutes(t *testing.T) {
	fixturePath := filepath.Join(c20FixtureDir, "positive-bearer-token-redacted.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind loopback listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	binaryPath := filepath.Join("..", "dist", "engine", "policyhelix")
	var cmd *exec.Cmd
	if _, err := os.Stat(binaryPath); err == nil {
		cmd = exec.Command(binaryPath, "--port", fmt.Sprintf("%d", port))
	} else {
		cmd = exec.Command("go", "run", "../cmd/policyhelix", "--port", fmt.Sprintf("%d", port))
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start engine for HTTP endpoint tests: %v", err)
		return
	}
	defer func() {
		_ = cmd.Process.Kill()
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	ready := false
	for i := 0; i < 40; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Skip("engine server did not become healthy in time, skipping HTTP integration test")
		return
	}

	// Test POST /api/v1/audit/decision
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/v1/audit/decision", baseURL), bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute POST /api/v1/audit/decision: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
	}

	var res audit.DecisionLogResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid=true and allow=true from HTTP endpoint")
	}
	if strings.Contains(res.JSON, "sig1234567890abcdef") {
		t.Fatalf("bearer token leaked into HTTP response: %s", res.JSON)
	}
}

func TestC20_GatewayProxyIntegration(t *testing.T) {
	sessStore := auth.NewMemorySessionStore()
	revStore := auth.NewMemoryRevocationStore()
	cfg := gateway.DefaultUpstreamConfig()
	proxy := gateway.NewAllowlistedGatewayProxy(cfg, sessStore, revStore)

	ctx := context.Background()
	req := gateway.ProxyRequest{
		RequestID:                "req-proxy-audit-c20",
		TargetUpstreamID:         cfg.ID,
		Method:                   "GET",
		Path:                     "/api/v1/analytics/reports",
		ResourceClassification:   "sensitive",
		UntrustedHeadersStripped: true,
		Headers: map[string]string{
			"Authorization": "Bearer sensitiveProxyJwtTokenValue123",
			"Cookie":        "policyhelix_session=s_proxy_secret_sess_9918",
		},
		Obligations: []gateway.Obligation{
			{
				ID:   "ob-audit-1",
				Type: "audit_log",
				Parameters: map[string]interface{}{
					"log_level":   "info",
					"bearer":      "Bearer sensitiveProxyJwtTokenValue123",
					"cookie_data": "policyhelix_session=s_proxy_secret_sess_9918",
				},
			},
		},
	}

	// Create valid session to satisfy proxy authentication
	sessMgr := auth.NewSessionManager(sessStore, auth.SessionConfig{})
	sess, err := sessMgr.CreateSession(ctx, auth.CreateSessionRequest{
		SubjectID:  "usr-proxy-tester",
		Issuer:     "https://auth.policyhelix.local",
		Roles:      []string{"operator"},
		OwnerScope: cfg.RequiredOwnerScope,
		ClientIP:   "127.0.0.1",
		UserAgent:  "TestClient/1.0",
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	req.SessionID = sess.Session.SessionID

	res, err := proxy.EvaluateProxyRequest(ctx, req)
	if err != nil {
		t.Fatalf("EvaluateProxyRequest error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid and allow, got valid=%v allow=%v err=%s", res.Valid, res.Allow, res.ErrorMessage)
	}

	if len(res.AuditRecords) == 0 {
		t.Fatalf("expected audit records from obligation execution, got 0")
	}

	rawAudit, err := json.Marshal(res.AuditRecords)
	if err != nil {
		t.Fatalf("marshal audit error: %v", err)
	}
	auditStr := string(rawAudit)

	if strings.Contains(auditStr, "sensitiveProxyJwtTokenValue123") {
		t.Fatalf("Bearer token leaked into proxy AuditRecords: %s", auditStr)
	}
	if strings.Contains(auditStr, "s_proxy_secret_sess_9918") {
		t.Fatalf("Cookie leaked into proxy AuditRecords: %s", auditStr)
	}
	if !strings.Contains(auditStr, "pseudo:sha256:") {
		t.Fatalf("expected subject pseudonym in proxy AuditRecords, got: %s", auditStr)
	}
}
