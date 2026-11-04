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

	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/policy"
)

const (
	c11RogueSeedHex = "9999999999999999999999999999999999999999999999999999999999999999"
	c11EvalTime     = "2026-11-03T12:00:00Z"
)

func c11BuildBundle(t *testing.T, mutate func(*bundles.BundleBuildSpec)) policy.LocalPolicyBundle {
	t.Helper()
	spec := standardBuildSpec()
	if mutate != nil {
		mutate(&spec)
	}
	bundle, err := bundles.BuildDeterministicBundle(spec)
	if err != nil {
		t.Fatalf("BuildDeterministicBundle failed: %v", err)
	}
	return bundle
}

func c11VerificationRequest(t *testing.T, bundle policy.LocalPolicyBundle, evalTime string, minimumRevision int64) bundles.BundleVerificationRequest {
	t.Helper()
	keyring, _ := getTestKeyring(t)
	return bundles.BundleVerificationRequest{
		SchemaVersion:   "1",
		TrustedKeys:     keyring.TrustedKeys(),
		Bundle:          bundle,
		EvaluationTime:  evalTime,
		MinimumRevision: minimumRevision,
	}
}

func c11AssertRejected(t *testing.T, verification bundles.BundleVerification, code string) {
	t.Helper()
	if verification.Verified {
		t.Fatalf("security invariant violated: expected rejection with %s, got verified bundle", code)
	}
	if verification.Status != bundles.VerificationStatusRejected {
		t.Fatalf("expected status %q, got %q", bundles.VerificationStatusRejected, verification.Status)
	}
	if code != "" && verification.ErrorCode != code {
		t.Fatalf("expected error code %s, got %s (%s)", code, verification.ErrorCode, verification.Message)
	}
}

func c11AuthorizedInput(requestID string) policy.BundleEvalInput {
	return policy.BundleEvalInput{
		RequestID:  requestID,
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   c11EvalTime,
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        testIssuer,
			Roles:         []string{"operator"},
			Authenticated: true,
		},
	}
}

// TestC11AcceptanceTrustedFreshBundleVerified proves Requirement F05's positive path: a trusted,
// fresh, monotonically advanced bundle passes verification and reports its evidence.
func TestC11AcceptanceTrustedFreshBundleVerified(t *testing.T) {
	bundle := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) { spec.Revision = 3 })

	verification := bundles.VerifyBundle(c11VerificationRequest(t, bundle, c11EvalTime, 2))
	if !verification.Verified {
		t.Fatalf("expected verified bundle, got %s: %s", verification.ErrorCode, verification.Message)
	}
	if verification.Status != bundles.VerificationStatusVerified {
		t.Errorf("expected status %q, got %q", bundles.VerificationStatusVerified, verification.Status)
	}
	if verification.ErrorCode != "" {
		t.Errorf("expected no error code, got %s", verification.ErrorCode)
	}
	if verification.Revision != 3 || verification.Digest != bundle.Digest {
		t.Errorf("verification evidence mismatch: %+v", verification)
	}
	if verification.IssuedAt != bundle.IssuedAt || verification.ExpiresAt != bundle.ExpiresAt {
		t.Errorf("validity window mismatch: %+v", verification)
	}
	if verification.CheckedAt != c11EvalTime {
		t.Errorf("expected checked_at %s, got %s", c11EvalTime, verification.CheckedAt)
	}

	again := bundles.VerifyBundle(c11VerificationRequest(t, bundle, c11EvalTime, 2))
	if again != verification {
		t.Errorf("verification is not deterministic: first=%+v second=%+v", verification, again)
	}
}

// TestC11RejectsMissingSignatureEvidence covers the missing-signature negative case: empty signature,
// unverified evidence flag, no trust anchors, unknown signer and issuer mismatch never verify.
func TestC11RejectsMissingSignatureEvidence(t *testing.T) {
	bundle := c11BuildBundle(t, nil)

	emptySignature := bundle
	emptySignature.Signature = ""
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, emptySignature, c11EvalTime, 0)), bundles.ErrCodeUntrustedSigner)

	unverifiedEvidence := bundle
	unverifiedEvidence.SignatureVerified = false
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, unverifiedEvidence, c11EvalTime, 0)), bundles.ErrCodeUntrustedSigner)

	noTrustAnchors := bundles.BundleVerificationRequest{SchemaVersion: "1", Bundle: bundle, EvaluationTime: c11EvalTime}
	c11AssertRejected(t, bundles.VerifyBundle(noTrustAnchors), bundles.ErrCodeUntrustedSigner)

	unknownSigner := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) { spec.SignerKeyID = "ed25519-rogue-signer" })
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, unknownSigner, c11EvalTime, 0)), bundles.ErrCodeUntrustedSigner)

	issuerMismatch := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) { spec.Issuer = "https://rogue.policyhelix.example" })
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, issuerMismatch, c11EvalTime, 0)), bundles.ErrCodeUntrustedSigner)
}

// TestC11RejectsWrongKey proves that a bundle claiming a trusted key ID but signed by another key is
// rejected and never becomes accepted authority.
func TestC11RejectsWrongKey(t *testing.T) {
	bundle := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) { spec.Revision = 3 })

	roguePublic, _, err := bundles.DeriveKeyPairFromSeedHex(c11RogueSeedHex)
	if err != nil {
		t.Fatalf("failed to derive rogue public key: %v", err)
	}
	wrongKeyring := bundles.NewKeyring(bundles.TrustedKey{
		SignerKeyID:  testKeyID,
		Issuer:       testIssuer,
		PublicKeyHex: hex.EncodeToString(roguePublic),
	})

	verification := bundles.VerifyBundle(bundles.BundleVerificationRequest{
		SchemaVersion:   "1",
		TrustedKeys:     wrongKeyring.TrustedKeys(),
		Bundle:          bundle,
		EvaluationTime:  c11EvalTime,
		MinimumRevision: 2,
	})
	c11AssertRejected(t, verification, bundles.ErrCodeVerificationFailed)

	authority := bundles.NewBundleAuthorityManager(wrongKeyring)
	if err := authority.IngestBundle(bundle, mustParseC11Time(t, c11EvalTime)); err == nil {
		t.Fatal("security invariant violated: bundle signed by wrong key was ingested")
	} else if !strings.Contains(err.Error(), bundles.ErrCodeVerificationFailed) {
		t.Fatalf("expected %s, got %v", bundles.ErrCodeVerificationFailed, err)
	}
	if authority.HighestRevision() != 0 {
		t.Errorf("wrong-key bundle advanced accepted revision to %d", authority.HighestRevision())
	}
	if _, ok := authority.ActiveBundle(); ok {
		t.Error("wrong-key bundle became active authority")
	}
}

// TestC11RejectsStaleRevisionAndRetainsAuthority proves an expired or replayed revision cannot replace
// the last valid accepted authority, while a genuinely newer valid bundle is still accepted.
func TestC11RejectsStaleRevisionAndRetainsAuthority(t *testing.T) {
	keyring, _ := getTestKeyring(t)
	authority := bundles.NewBundleAuthorityManager(keyring)
	evalTime := mustParseC11Time(t, c11EvalTime)

	revision2 := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) { spec.Revision = 2 })
	if err := authority.IngestBundle(revision2, evalTime); err != nil {
		t.Fatalf("failed to ingest valid revision 2: %v", err)
	}

	replayed := bundles.VerifyBundle(c11VerificationRequest(t, revision2, c11EvalTime, authority.HighestRevision()))
	c11AssertRejected(t, replayed, bundles.ErrCodeStaleOrReplayedRev)

	revision1 := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) { spec.Revision = 1 })
	stale := bundles.VerifyBundle(c11VerificationRequest(t, revision1, c11EvalTime, authority.HighestRevision()))
	c11AssertRejected(t, stale, bundles.ErrCodeStaleOrReplayedRev)

	expiredRevision3 := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) {
		spec.Revision = 3
		spec.IssuedAt = "2026-11-01T10:00:00Z"
		spec.ExpiresAt = "2026-11-02T10:00:00Z"
	})
	expired := bundles.VerifyBundle(c11VerificationRequest(t, expiredRevision3, c11EvalTime, authority.HighestRevision()))
	c11AssertRejected(t, expired, bundles.ErrCodeExpiredBundle)

	if err := authority.IngestBundle(expiredRevision3, evalTime); err == nil || !strings.Contains(err.Error(), bundles.ErrCodeExpiredBundle) {
		t.Fatalf("expected expired revision rejection, got %v", err)
	}
	if err := authority.IngestBundle(revision2, evalTime); err == nil || !strings.Contains(err.Error(), bundles.ErrCodeStaleOrReplayedRev) {
		t.Fatalf("expected replayed revision rejection, got %v", err)
	}

	if authority.HighestRevision() != 2 {
		t.Fatalf("security invariant violated: accepted revision changed to %d", authority.HighestRevision())
	}
	active, ok := authority.ActiveBundle()
	if !ok || active.Revision != 2 || active.Digest != revision2.Digest {
		t.Fatalf("security invariant violated: accepted authority was replaced: %+v", active)
	}

	retainedDecision := authority.Evaluate(context.Background(), c11AuthorizedInput("req-c11-retained"))
	if !retainedDecision.Allow || retainedDecision.PolicyDigest != revision2.Digest {
		t.Errorf("retained authority no longer authorizes the private workflow: %+v", retainedDecision)
	}

	revision3 := c11BuildBundle(t, func(spec *bundles.BundleBuildSpec) { spec.Revision = 3 })
	if err := authority.IngestBundle(revision3, evalTime); err != nil {
		t.Fatalf("valid newer revision 3 should be accepted, got: %v", err)
	}
	if authority.HighestRevision() != 3 {
		t.Errorf("expected accepted revision 3, got %d", authority.HighestRevision())
	}
}

// TestC11RejectsExpiredAndNotYetValidWindow covers validity-window boundaries.
func TestC11RejectsExpiredAndNotYetValidWindow(t *testing.T) {
	bundle := c11BuildBundle(t, nil)

	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, bundle, "2026-11-04T10:00:00Z", 0)), bundles.ErrCodeExpiredBundle)
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, bundle, "2026-11-04T10:00:01Z", 0)), bundles.ErrCodeExpiredBundle)
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, bundle, "2026-11-03T09:59:59Z", 0)), bundles.ErrCodeExpiredBundle)

	atIssuedAt := bundles.VerifyBundle(c11VerificationRequest(t, bundle, bundle.IssuedAt, 0))
	if !atIssuedAt.Verified {
		t.Errorf("bundle should be valid at its issued_at boundary, got %s: %s", atIssuedAt.ErrorCode, atIssuedAt.Message)
	}
}

// TestC11RejectsOneModifiedByte covers the single-byte modification negative case for policy content,
// signature bytes and the declared digest.
func TestC11RejectsOneModifiedByte(t *testing.T) {
	bundle := c11BuildBundle(t, nil)

	modifiedRego := bundle
	modifiedRego.RegoModule += " "
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, modifiedRego, c11EvalTime, 0)), bundles.ErrCodeTamperedBundle)

	modifiedSignature := bundle
	signatureHex := strings.TrimPrefix(modifiedSignature.Signature, "ed25519:")
	replacement := "0"
	if signatureHex[len(signatureHex)-1] == '0' {
		replacement = "1"
	}
	modifiedSignature.Signature = "ed25519:" + signatureHex[:len(signatureHex)-1] + replacement
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, modifiedSignature, c11EvalTime, 0)), bundles.ErrCodeVerificationFailed)

	modifiedDigest := bundle
	modifiedDigest.Digest += "0"
	c11AssertRejected(t, bundles.VerifyBundle(c11VerificationRequest(t, modifiedDigest, c11EvalTime, 0)), bundles.ErrCodeTamperedBundle)
}

// TestC11NegativePrivateResourcesFailClosed proves a rejected bundle never becomes authority and that
// private resources deny when identity is unauthenticated.
func TestC11NegativePrivateResourcesFailClosed(t *testing.T) {
	keyring, _ := getTestKeyring(t)
	authority := bundles.NewBundleAuthorityManager(keyring)

	unsigned := c11BuildBundle(t, nil)
	unsigned.Signature = ""
	if err := authority.IngestBundle(unsigned, mustParseC11Time(t, c11EvalTime)); err == nil {
		t.Fatal("security invariant violated: unsigned bundle was ingested")
	}

	denied := authority.Evaluate(context.Background(), c11AuthorizedInput("req-c11-no-authority"))
	if denied.Allow {
		t.Fatal("security invariant violated: private resource allowed without accepted authority")
	}
	if denied.Error == nil || denied.Error.Code != policy.ErrCodeNoActiveBundle {
		t.Errorf("expected %s, got %+v", policy.ErrCodeNoActiveBundle, denied.Error)
	}

	valid := c11BuildBundle(t, nil)
	if err := authority.IngestBundle(valid, mustParseC11Time(t, c11EvalTime)); err != nil {
		t.Fatalf("failed to ingest valid bundle: %v", err)
	}

	unauthenticated := c11AuthorizedInput("req-c11-unauthenticated")
	unauthenticated.Subject = policy.SubjectIdentity{ID: "guest", Authenticated: false}
	denied = authority.Evaluate(context.Background(), unauthenticated)
	if denied.Allow {
		t.Fatal("security invariant failed: unauthenticated private resource allowed")
	}
	if denied.Error == nil || denied.Error.Code != policy.ErrCodePrivateFailClosed {
		t.Errorf("expected %s, got %+v", policy.ErrCodePrivateFailClosed, denied.Error)
	}
}

type c11FixtureFile struct {
	FixtureID       string                   `json:"fixture_id"`
	CommitID        string                   `json:"commit_id"`
	SchemaVersion   string                   `json:"schema_version"`
	TrustedKeys     []bundles.TrustedKey     `json:"trusted_keys"`
	Bundle          policy.LocalPolicyBundle `json:"bundle"`
	EvaluationTime  string                   `json:"evaluation_time"`
	MinimumRevision int64                    `json:"minimum_revision"`
	EvaluationInput *policy.BundleEvalInput  `json:"evaluation_input,omitempty"`
	Expected        struct {
		Verified         bool   `json:"verified"`
		ErrorCode        string `json:"error_code"`
		Revision         int64  `json:"revision"`
		Digest           string `json:"digest"`
		RetainedRevision int64  `json:"retained_revision"`
		Allow            bool   `json:"allow"`
	} `json:"expected"`
}

// TestC11FixturesAndManifestIntegration verifies every C11 fixture, its SHA-256 manifest hash and the
// declared verification outcome through the public gate and authority manager.
func TestC11FixturesAndManifestIntegration(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "policyhelix", "C11")
	manifestRaw, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C11 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C11 manifest: %v", err)
	}
	if manifest.CommitID != "C11" {
		t.Fatalf("expected commit_id C11, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) != 7 {
		t.Fatalf("expected 7 C11 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(fixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", base, err)
		}
		sum := sha256.Sum256(raw)
		if actual := hex.EncodeToString(sum[:]); actual != entry.SHA256 {
			t.Fatalf("fixture %s SHA-256 mismatch: manifest=%s actual=%s", base, entry.SHA256, actual)
		}
		if entry.License != "Apache-2.0" {
			t.Fatalf("fixture %s has unexpected license %s", base, entry.License)
		}

		var fx c11FixtureFile
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", base, err)
		}
		if fx.CommitID != "C11" || fx.FixtureID != entry.FixtureID {
			t.Fatalf("fixture identity mismatch for %s: %+v", base, fx)
		}

		verification := bundles.VerifyBundle(bundles.BundleVerificationRequest{
			SchemaVersion:   fx.SchemaVersion,
			TrustedKeys:     fx.TrustedKeys,
			Bundle:          fx.Bundle,
			EvaluationTime:  fx.EvaluationTime,
			MinimumRevision: fx.MinimumRevision,
		})
		if verification.Verified != fx.Expected.Verified {
			t.Fatalf("fixture %s: expected verified=%v, got %v (%s: %s)", base, fx.Expected.Verified, verification.Verified, verification.ErrorCode, verification.Message)
		}
		if !fx.Expected.Verified && verification.ErrorCode != fx.Expected.ErrorCode {
			t.Fatalf("fixture %s: expected error %s, got %s", base, fx.Expected.ErrorCode, verification.ErrorCode)
		}
		if verification.Revision != fx.Expected.Revision {
			t.Fatalf("fixture %s: expected revision %d, got %d", base, fx.Expected.Revision, verification.Revision)
		}
		if fx.Expected.Digest != "" && verification.Digest != fx.Expected.Digest {
			t.Fatalf("fixture %s: expected digest %s, got %s", base, fx.Expected.Digest, verification.Digest)
		}
		if fx.Expected.RetainedRevision > 0 && fx.MinimumRevision != fx.Expected.RetainedRevision {
			t.Fatalf("fixture %s: retained_revision %d does not match minimum_revision %d", base, fx.Expected.RetainedRevision, fx.MinimumRevision)
		}

		if fx.EvaluationInput != nil {
			authority := bundles.NewBundleAuthorityManager(bundles.NewKeyring(fx.TrustedKeys...))
			evalTime := mustParseC11Time(t, fx.EvaluationTime)
			if err := authority.IngestBundle(fx.Bundle, evalTime); err == nil {
				t.Fatalf("fixture %s: rejected bundle was ingested as authority", base)
			}
			if _, ok := authority.ActiveBundle(); ok {
				t.Fatalf("fixture %s: rejected bundle became active authority", base)
			}
			decision := authority.Evaluate(context.Background(), *fx.EvaluationInput)
			if decision.Allow != fx.Expected.Allow {
				t.Fatalf("fixture %s: expected allow=%v after rejection, got %v", base, fx.Expected.Allow, decision.Allow)
			}
		}
	}
}

// TestC11CLIVerifyBundle verifies the engine CLI exposes the typed trust/freshness outcome.
func TestC11CLIVerifyBundle(t *testing.T) {
	positivePath, err := filepath.Abs(filepath.Join("fixtures", "policyhelix", "C11", "positive-trusted-fresh-bundle.json"))
	if err != nil {
		t.Fatalf("failed to resolve positive fixture path: %v", err)
	}
	expiredPath, err := filepath.Abs(filepath.Join("fixtures", "policyhelix", "C11", "negative-expired-validity.json"))
	if err != nil {
		t.Fatalf("failed to resolve expired fixture path: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--verify-bundle", positivePath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI --verify-bundle failed on positive fixture: %v, stderr: %s", err, stderr.String())
	}
	var verified bundles.BundleVerification
	if err := json.Unmarshal(stdout.Bytes(), &verified); err != nil {
		t.Fatalf("failed to parse CLI verification output: %v, raw: %s", err, stdout.String())
	}
	if !verified.Verified || verified.Status != bundles.VerificationStatusVerified {
		t.Errorf("expected verified CLI outcome, got %+v", verified)
	}

	stdout.Reset()
	stderr.Reset()
	cmd = exec.Command("go", "run", "../cmd/policyhelix", "--verify-bundle", expiredPath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("expected non-zero exit for expired bundle")
	}
	var rejected bundles.BundleVerification
	if err := json.Unmarshal(stdout.Bytes(), &rejected); err != nil {
		t.Fatalf("failed to parse rejected CLI output: %v, raw: %s", err, stdout.String())
	}
	if rejected.Verified || rejected.ErrorCode != bundles.ErrCodeExpiredBundle {
		t.Errorf("expected %s rejection, got %+v", bundles.ErrCodeExpiredBundle, rejected)
	}
}

// TestC11HTTPEndpointVerifyBundle verifies the loopback verification endpoint maps typed outcomes to
// 200/422/400 without exposing non-loopback listeners.
func TestC11HTTPEndpointVerifyBundle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--port", fmt.Sprintf("%d", port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start engine: %v", err)
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
		t.Fatal("engine server did not become healthy in time")
	}

	postFixture := func(name string) (*http.Response, bundles.BundleVerification) {
		raw, err := os.ReadFile(filepath.Join("fixtures", "policyhelix", "C11", name))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", name, err)
		}
		resp, err := client.Post(baseURL+"/v1/runtime/bundles/verify", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("POST verify for %s failed: %v", name, err)
		}
		var verification bundles.BundleVerification
		if err := json.NewDecoder(resp.Body).Decode(&verification); err != nil {
			_ = resp.Body.Close()
			t.Fatalf("failed to decode verify response for %s: %v", name, err)
		}
		_ = resp.Body.Close()
		return resp, verification
	}

	resp, verification := postFixture("positive-trusted-fresh-bundle.json")
	if resp.StatusCode != http.StatusOK || !verification.Verified {
		t.Errorf("expected 200 verified, got status=%d outcome=%+v", resp.StatusCode, verification)
	}

	resp, verification = postFixture("negative-missing-signature.json")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for missing signature, got %d", resp.StatusCode)
	}
	if verification.Verified || verification.ErrorCode != bundles.ErrCodeUntrustedSigner {
		t.Errorf("expected %s rejection, got %+v", bundles.ErrCodeUntrustedSigner, verification)
	}

	resp, err = client.Post(baseURL+"/v1/runtime/bundles/verify", "application/json", strings.NewReader("{invalid json"))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed JSON, got status=%v err=%v", resp, err)
	}
	var malformed bundles.BundleVerification
	_ = json.NewDecoder(resp.Body).Decode(&malformed)
	_ = resp.Body.Close()
	if malformed.ErrorCode != bundles.ErrCodeInvalidVerificationRequest {
		t.Errorf("expected %s, got %+v", bundles.ErrCodeInvalidVerificationRequest, malformed)
	}

	resp, err = client.Post(baseURL+"/v1/runtime/bundles/verify", "application/json", strings.NewReader(`{"schema_version":"99"}`))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported schema, got status=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()
}

func mustParseC11Time(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("invalid test timestamp %s: %v", value, err)
	}
	return parsed
}
