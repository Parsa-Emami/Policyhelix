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
	testSeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	testKeyID   = "ed25519-primary-2026"
	testIssuer  = "https://issuer.policyhelix.local"
)

func getTestKeyring(t *testing.T) (*bundles.Keyring, string) {
	pub, _, err := bundles.DeriveKeyPairFromSeedHex(testSeedHex)
	if err != nil {
		t.Fatalf("Failed to derive test keypair: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	kr := bundles.NewKeyring(bundles.TrustedKey{
		SignerKeyID:  testKeyID,
		Issuer:       testIssuer,
		PublicKeyHex: pubHex,
	})
	return kr, pubHex
}

func standardBuildSpec() bundles.BundleBuildSpec {
	return bundles.BundleBuildSpec{
		SchemaVersion: "1",
		BundleID:      "bundle-analytics-v1",
		Package:       "policyhelix.authz",
		Issuer:        testIssuer,
		SignerKeyID:   testKeyID,
		SeedHex:       testSeedHex,
		Revision:      1,
		IssuedAt:      "2026-11-03T10:00:00Z",
		ExpiresAt:     "2026-11-04T10:00:00Z",
		RegoModule:    "package policyhelix.authz\ndefault allow = false\nallow { input.subject.authenticated == true }",
		Routes: []policy.RouteRule{
			{
				Pattern:              "/api/v1/analytics/reports",
				Action:               "read",
				Classification:       policy.ResourceClassPrivate,
				AllowUnauthenticated: false,
				RequiredRoles:        []string{"operator", "admin"},
				Description:          "Private analytics reports endpoint",
			},
		},
		Rules: []policy.PolicyRule{
			{
				ID:            "rule-operator-analytics-read",
				Effect:        "allow",
				PathPattern:   "/api/v1/analytics/reports",
				Actions:       []string{"read"},
				Roles:         []string{"operator", "admin"},
				ResourceClass: policy.ResourceClassPrivate,
				ReasonCode:    "policy_allow_role_operator",
				ReasonMessage: "Operator granted read access to analytics reports",
			},
		},
	}
}

// TestC10AcceptanceBundleRecordsIssuerDigestRevisionValidity verifies Requirement F04:
// Bundle records issuer, digest, revision and validity period, and build is strictly deterministic.
func TestC10AcceptanceBundleRecordsIssuerDigestRevisionValidity(t *testing.T) {
	spec1 := standardBuildSpec()
	b1, err := bundles.BuildDeterministicBundle(spec1)
	if err != nil {
		t.Fatalf("BuildDeterministicBundle failed: %v", err)
	}

	// 1. Acceptance Criteria: Bundle records issuer, digest, revision and validity period
	if b1.Issuer != testIssuer {
		t.Errorf("Expected issuer '%s', got '%s'", testIssuer, b1.Issuer)
	}
	if b1.Revision != 1 {
		t.Errorf("Expected revision 1, got %d", b1.Revision)
	}
	if !strings.HasPrefix(b1.Digest, "sha256:") {
		t.Errorf("Expected valid sha256 digest, got: %s", b1.Digest)
	}
	if b1.IssuedAt != "2026-11-03T10:00:00Z" || b1.ExpiresAt != "2026-11-04T10:00:00Z" {
		t.Errorf("Expected validity period 2026-11-03 to 2026-11-04, got: %s to %s", b1.IssuedAt, b1.ExpiresAt)
	}
	if !strings.HasPrefix(b1.Signature, "ed25519:") {
		t.Errorf("Expected ed25519 signature prefix, got: %s", b1.Signature)
	}

	// 2. Determinism check: building again from identical spec produces identical digest and signature bytes
	spec2 := standardBuildSpec()
	b2, err := bundles.BuildDeterministicBundle(spec2)
	if err != nil {
		t.Fatalf("Second BuildDeterministicBundle failed: %v", err)
	}
	if b1.Digest != b2.Digest {
		t.Errorf("Non-deterministic digest: b1=%s, b2=%s", b1.Digest, b2.Digest)
	}
	if b1.Signature != b2.Signature {
		t.Errorf("Non-deterministic signature: b1=%s, b2=%s", b1.Signature, b2.Signature)
	}

	// 3. Verify signature cryptographically against keyring
	kr, _ := getTestKeyring(t)
	if err := bundles.VerifyBundleSignature(b1, kr); err != nil {
		t.Errorf("VerifyBundleSignature failed on valid bundle: %v", err)
	}
}

// TestC10NegativeModifiedByteTamperedRejected verifies required negative case 1:
// One modified byte, missing evidence or a wrong/untrusted signer must not produce trusted success.
func TestC10NegativeModifiedByteTamperedRejected(t *testing.T) {
	kr, _ := getTestKeyring(t)
	spec := standardBuildSpec()
	bundle, err := bundles.BuildDeterministicBundle(spec)
	if err != nil {
		t.Fatalf("BuildDeterministicBundle failed: %v", err)
	}

	// 1. One modified byte in Rego module (content digest mismatch)
	tamperedRego := bundle
	tamperedRego.RegoModule += " "
	if err := bundles.VerifyBundleSignature(tamperedRego, kr); err == nil || !strings.Contains(err.Error(), bundles.ErrCodeTamperedBundle) {
		t.Errorf("Expected %s on 1-byte rego modification, got: %v", bundles.ErrCodeTamperedBundle, err)
	}

	// 2. One modified byte in signature
	tamperedSig := bundle
	sigHex := strings.TrimPrefix(tamperedSig.Signature, "ed25519:")
	flippedChar := "0"
	if sigHex[len(sigHex)-1] == '0' {
		flippedChar = "1"
	}
	tamperedSig.Signature = "ed25519:" + sigHex[:len(sigHex)-1] + flippedChar
	if err := bundles.VerifyBundleSignature(tamperedSig, kr); err == nil || !strings.Contains(err.Error(), bundles.ErrCodeVerificationFailed) {
		t.Errorf("Expected %s on 1-byte signature modification, got: %v", bundles.ErrCodeVerificationFailed, err)
	}

	// 3. Wrong / untrusted signer key ID
	wrongSigner := bundle
	wrongSigner.SignerKeyID = "ed25519-rogue-signer"
	if err := bundles.VerifyBundleSignature(wrongSigner, kr); err == nil || !strings.Contains(err.Error(), bundles.ErrCodeUntrustedSigner) {
		t.Errorf("Expected %s on untrusted signer key, got: %v", bundles.ErrCodeUntrustedSigner, err)
	}
}

// TestC10NegativeStaleOrReplayedRevisionPreservesAuthority verifies required negative case 2:
// An expired/stale/replayed revision cannot replace the last valid accepted authority.
func TestC10NegativeStaleOrReplayedRevisionPreservesAuthority(t *testing.T) {
	kr, _ := getTestKeyring(t)
	bam := bundles.NewBundleAuthorityManager(kr)

	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")

	// Ingest valid revision 2 as initial authoritative state
	specRev2 := standardBuildSpec()
	specRev2.Revision = 2
	bundleRev2, err := bundles.BuildDeterministicBundle(specRev2)
	if err != nil {
		t.Fatalf("Build rev 2 failed: %v", err)
	}
	if err := bam.IngestBundle(bundleRev2, evalTime); err != nil {
		t.Fatalf("Ingest rev 2 failed: %v", err)
	}
	if bam.HighestRevision() != 2 {
		t.Fatalf("Expected highest revision 2, got %d", bam.HighestRevision())
	}

	// 1. Attempt replay of revision 2
	if err := bam.IngestBundle(bundleRev2, evalTime); err == nil || !strings.Contains(err.Error(), bundles.ErrCodeStaleOrReplayedRev) {
		t.Errorf("Expected %s on replayed revision 2, got: %v", bundles.ErrCodeStaleOrReplayedRev, err)
	}

	// 2. Attempt downgrade to stale revision 1
	specRev1 := standardBuildSpec()
	specRev1.Revision = 1
	bundleRev1, err := bundles.BuildDeterministicBundle(specRev1)
	if err != nil {
		t.Fatalf("Build rev 1 failed: %v", err)
	}
	if err := bam.IngestBundle(bundleRev1, evalTime); err == nil || !strings.Contains(err.Error(), bundles.ErrCodeStaleOrReplayedRev) {
		t.Errorf("Expected %s on stale revision 1, got: %v", bundles.ErrCodeStaleOrReplayedRev, err)
	}

	// 3. Attempt expired revision 3
	specRev3 := standardBuildSpec()
	specRev3.Revision = 3
	specRev3.IssuedAt = "2026-11-01T10:00:00Z"
	specRev3.ExpiresAt = "2026-11-02T10:00:00Z"
	bundleRev3, err := bundles.BuildDeterministicBundle(specRev3)
	if err != nil {
		t.Fatalf("Build rev 3 failed: %v", err)
	}
	if err := bam.IngestBundle(bundleRev3, evalTime); err == nil {
		t.Errorf("Expected error on expired revision 3, but succeeded")
	}

	// Invariant check: authority strictly preserved at revision 2
	if bam.HighestRevision() != 2 {
		t.Errorf("Security invariant violated: highest revision altered from 2 to %d", bam.HighestRevision())
	}
	active, ok := bam.ActiveBundle()
	if !ok || active.Revision != 2 || active.Digest != bundleRev2.Digest {
		t.Errorf("Active bundle not preserved at revision 2: %+v", active)
	}
}

// TestC10NegativePrivateResourcesFailClosed verifies required negative case 3:
// Private resources fail closed when unauthenticated or lacking required roles.
func TestC10NegativePrivateResourcesFailClosed(t *testing.T) {
	kr, _ := getTestKeyring(t)
	bam := bundles.NewBundleAuthorityManager(kr)
	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")

	spec := standardBuildSpec()
	bundle, err := bundles.BuildDeterministicBundle(spec)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if err := bam.IngestBundle(bundle, evalTime); err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	// 1. Unauthenticated request to private route fails closed
	dec1 := bam.Evaluate(context.Background(), policy.BundleEvalInput{
		RequestID:  "req-unauth",
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "guest",
			Authenticated: false,
		},
	})
	if dec1.Allow {
		t.Errorf("Security invariant violated: unauthenticated private resource allowed")
	}

	// 2. Authenticated user without required role fails closed
	dec2 := bam.Evaluate(context.Background(), policy.BundleEvalInput{
		RequestID:  "req-wrong-role",
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "user-1",
			Issuer:        testIssuer,
			Roles:         []string{"auditor"},
			Authenticated: true,
		},
	})
	if dec2.Allow {
		t.Errorf("Security invariant violated: unauthorized role allowed")
	}
}

// TestC10FixturesAndManifestIntegration verifies all 5 synthetic C10 fixtures and manifest SHA-256 hashes.
func TestC10FixturesAndManifestIntegration(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "policyhelix", "C10")
	manifestPath := filepath.Join(fixtureDir, "manifest.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read manifest.json: %v", err)
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
		t.Fatalf("Failed to unmarshal manifest.json: %v", err)
	}
	if manifest.CommitID != "C10" {
		t.Fatalf("Expected commit_id=C10, got: %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) != 5 {
		t.Fatalf("Expected 5 fixtures in manifest, got: %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		fxBytes, err := os.ReadFile(filepath.Join(fixtureDir, base))
		if err != nil {
			t.Fatalf("Failed to read fixture %s: %v", base, err)
		}

		sum := sha256.Sum256(fxBytes)
		actualHash := hex.EncodeToString(sum[:])
		if actualHash != entry.SHA256 {
			t.Fatalf("Fixture %s SHA-256 hash mismatch: manifest=%s, actual=%s", base, entry.SHA256, actualHash)
		}

		var fx bundles.BundleFixture
		if err := json.Unmarshal(fxBytes, &fx); err != nil {
			t.Fatalf("Failed to unmarshal fixture %s: %v", base, err)
		}

		passed, _, err := bundles.RunBundleFixture(context.Background(), fx)
		if err != nil || !passed {
			t.Errorf("Fixture %s failed assertion: %v", base, err)
		}
	}
}

// TestC10CLIBundleBuild verifies CLI --build-bundle and --evaluate-bundle functionality.
func TestC10CLIBundleBuild(t *testing.T) {
	// Create temporary build spec file
	tmpSpec, err := os.CreateTemp("", "c10-spec-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp spec: %v", err)
	}
	defer os.Remove(tmpSpec.Name())

	spec := standardBuildSpec()
	specBytes, _ := json.Marshal(spec)
	_, _ = tmpSpec.Write(specBytes)
	_ = tmpSpec.Close()

	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--build-bundle", tmpSpec.Name())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI --build-bundle failed: %v, stderr: %s", err, stderr.String())
	}

	var built policy.LocalPolicyBundle
	if err := json.Unmarshal(stdout.Bytes(), &built); err != nil {
		t.Fatalf("Failed to parse bundle output: %v, raw: %s", err, stdout.String())
	}

	if built.Issuer != testIssuer || built.Revision != 1 || !strings.HasPrefix(built.Digest, "sha256:") {
		t.Errorf("Unexpected bundle built via CLI: %+v", built)
	}
}

// TestC10HTTPEndpointBundleBuild verifies POST /v1/runtime/bundles/build loopback endpoint.
func TestC10HTTPEndpointBundleBuild(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind listener: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	cmd := exec.Command("go", "run", "../cmd/policyhelix", "--port", fmt.Sprintf("%d", port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start engine: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Wait for healthy status
	for i := 0; i < 30; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	spec := standardBuildSpec()
	body, _ := json.Marshal(spec)
	resp, err := client.Post(baseURL+"/v1/runtime/bundles/build", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/runtime/bundles/build failed: %v, status: %v", err, resp.Status)
	}

	var built policy.LocalPolicyBundle
	_ = json.NewDecoder(resp.Body).Decode(&built)
	_ = resp.Body.Close()

	if built.Issuer != testIssuer || built.Revision != 1 || !strings.HasPrefix(built.Digest, "sha256:") {
		t.Errorf("Unexpected bundle built via HTTP: %+v", built)
	}
}
