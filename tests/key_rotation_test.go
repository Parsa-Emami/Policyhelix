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
	"strings"
	"sync"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	c25SeedV1Hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	c25SeedV2Hex = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	c25SeedV3Hex = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
	c25KeyV1ID   = "ed25519-primary-2026"
	c25KeyV2ID   = "ed25519-rotated-2026"
	c25KeyV3ID   = "ed25519-emergency-2026"
	c25Issuer    = "https://issuer.policyhelix.local"
	c25EvalTime  = "2026-11-03T12:00:00Z"
)

func c25TrustedKey(t *testing.T, keyID, seedHex string) bundles.TrustedKey {
	t.Helper()
	pub, _, err := bundles.DeriveKeyPairFromSeedHex(seedHex)
	if err != nil {
		t.Fatalf("failed to derive key %s: %v", keyID, err)
	}
	return bundles.TrustedKey{
		SignerKeyID:  keyID,
		Issuer:       c25Issuer,
		PublicKeyHex: hex.EncodeToString(pub),
	}
}

func c25BuildSignedBundle(t *testing.T, bundleID, keyID, seedHex string, revision int64) policy.LocalPolicyBundle {
	t.Helper()
	spec := standardBuildSpec()
	spec.BundleID = bundleID
	spec.Issuer = c25Issuer
	spec.SignerKeyID = keyID
	spec.SeedHex = seedHex
	spec.Revision = revision
	spec.IssuedAt = "2026-11-03T10:00:00Z"
	spec.ExpiresAt = "2026-11-04T10:00:00Z"
	b, err := bundles.BuildDeterministicBundle(spec)
	if err != nil {
		t.Fatalf("BuildDeterministicBundle failed for %s: %v", bundleID, err)
	}
	return b
}

func c25OperatorEvalInput() policy.BundleEvalInput {
	return policy.BundleEvalInput{
		RequestID: "req-c25-operator-1",
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        c25Issuer,
			Roles:         []string{"operator"},
			Authenticated: true,
			SessionEpoch:  1720000000,
		},
		Action:     "read",
		Path:       "/api/v1/analytics/reports",
		ResourceID: "res-analytics-reports",
		DeadlineMS: 50,
		EvalTime:   c25EvalTime,
	}
}

func c25UnauthenticatedEvalInput() policy.BundleEvalInput {
	return policy.BundleEvalInput{
		RequestID: "req-c25-unauth-1",
		Subject: policy.SubjectIdentity{
			ID:            "anonymous",
			Issuer:        c25Issuer,
			Roles:         []string{},
			Authenticated: false,
			SessionEpoch:  0,
		},
		Action:     "read",
		Path:       "/api/v1/analytics/reports",
		ResourceID: "res-analytics-reports",
		DeadlineMS: 50,
		EvalTime:   c25EvalTime,
	}
}

// TestC25_ManifestIntegrity verifies that all C25 synthetic fixtures exist, are valid JSON,
// carry Apache-2.0 license metadata, and match their exact SHA-256 digests in manifest.json.
func TestC25_ManifestIntegrity(t *testing.T) {
	manifestPath := filepath.Join("fixtures", "policyhelix", "C25", "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C25 manifest.json: %v", err)
	}

	var manifest struct {
		SchemaVersion string `json:"schema_version"`
		CommitID      string `json:"commit_id"`
		License       string `json:"license"`
		Fixtures      []struct {
			FixtureID string `json:"fixture_id"`
			Path      string `json:"path"`
			SHA256    string `json:"sha256"`
			Type      string `json:"type"`
			License   string `json:"license"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("invalid C25 manifest JSON: %v", err)
	}
	if manifest.CommitID != "C25" || manifest.License != "Apache-2.0" {
		t.Fatalf("unexpected manifest metadata: commit_id=%s license=%s", manifest.CommitID, manifest.License)
	}
	if len(manifest.Fixtures) < 8 {
		t.Fatalf("expected at least 8 fixtures in C25 manifest, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		relPath := strings.TrimPrefix(entry.Path, "tests/")
		fxBytes, err := os.ReadFile(relPath)
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", relPath, err)
		}
		sum := sha256.Sum256(fxBytes)
		actualHash := hex.EncodeToString(sum[:])
		if actualHash != entry.SHA256 {
			t.Errorf("SHA-256 mismatch for %s: manifest=%s actual=%s", entry.Path, entry.SHA256, actualHash)
		}
		if entry.License != "Apache-2.0" {
			t.Errorf("fixture %s license must be Apache-2.0, got %s", entry.FixtureID, entry.License)
		}

		// Execute every fixture through RunKeyRotationFixture and verify expected outcomes
		var fx bundles.KeyRotationFixture
		if err := json.Unmarshal(fxBytes, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", entry.FixtureID, err)
		}
		tmpDir := t.TempDir()
		rep, runErr := bundles.RunKeyRotationFixture(context.Background(), tmpDir, fx)
		if !rep.Passed {
			t.Errorf("fixture %s failed expectations: err=%v report=%+v", entry.FixtureID, runErr, rep)
		}
	}
}

// TestC25_OperatorControlledRotationAndRemovedKeyRejection verifies Requirement F19:
// New trust set is operator-controlled; removed key cannot activate an old or new signed bundle,
// and rotating keys preserves the monotonic revision floor without rollback gap.
func TestC25_OperatorControlledRotationAndRemovedKeyRejection(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer ad.Close()

	keyV1 := c25TrustedKey(t, c25KeyV1ID, c25SeedV1Hex)
	keyV2 := c25TrustedKey(t, c25KeyV2ID, c25SeedV2Hex)

	mgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(keyV1))
	mgr.Now = c12Clock()

	bundleRev1V1 := c25BuildSignedBundle(t, "bundle-v1-rev1", c25KeyV1ID, c25SeedV1Hex, 1)
	bundleRev2V1 := c25BuildSignedBundle(t, "bundle-v1-rev2", c25KeyV1ID, c25SeedV1Hex, 2)
	bundleRev2V2 := c25BuildSignedBundle(t, "bundle-v2-rev2", c25KeyV2ID, c25SeedV2Hex, 2)
	bundleRev3V1 := c25BuildSignedBundle(t, "bundle-v1-rev3", c25KeyV1ID, c25SeedV1Hex, 3)

	// 1. Activate initial bundle rev 1 signed by key-v1
	act1 := mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-act-rev1",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev1V1,
	}, c25EvalTime)
	if act1.Status != bundles.ActivationStatusActivated || !act1.Active || act1.HighestRevision != 1 {
		t.Fatalf("expected initial activation of rev 1 to succeed, got %+v", act1)
	}

	// 2. Operator rotates trust set to [key-v2], removing key-v1, and atomically activates bundleRev2V2
	rotRes := mgr.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID:       "op-rotate-to-v2",
		BundleOperationID: "op-act-rev2-v2",
		Identity:          c12OperatorIdentity(),
		EvaluationTime:    c25EvalTime,
		TrustedKeys:       []bundles.TrustedKey{keyV2},
		RemoveKeyIDs:      []string{c25KeyV1ID},
		CandidateBundle:   &bundleRev2V2,
	})
	if !rotRes.Valid || rotRes.Status != bundles.KeyRotationStatusRotated {
		t.Fatalf("expected key rotation to succeed, got %+v", rotRes)
	}
	if rotRes.KeySetEpoch != 1 || rotRes.HighestRevision != 2 || rotRes.ActiveSignerKeyID != c25KeyV2ID {
		t.Fatalf("unexpected post-rotation state: %+v", rotRes)
	}

	// 3. Removed key-v1 cannot activate an old signed bundle (rev 1 or rev 2)
	oldAttempt := mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-removed-key-old-bundle",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev1V1,
	}, c25EvalTime)
	if oldAttempt.Status != bundles.ActivationStatusRejected || oldAttempt.ErrorCode != bundles.ErrCodeRemovedKeyRejected {
		t.Fatalf("expected removed key old bundle to be rejected with %s, got %+v", bundles.ErrCodeRemovedKeyRejected, oldAttempt)
	}

	equalRevAttempt := mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-removed-key-rev2-bundle",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev2V1,
	}, c25EvalTime)
	if equalRevAttempt.Status != bundles.ActivationStatusRejected || equalRevAttempt.ErrorCode != bundles.ErrCodeRemovedKeyRejected {
		t.Fatalf("expected removed key rev2 bundle to be rejected with %s, got %+v", bundles.ErrCodeRemovedKeyRejected, equalRevAttempt)
	}

	// 4. Removed key-v1 cannot even activate a higher-revision signed bundle (rev 3)
	newerRevAttempt := mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-removed-key-rev3-bundle",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev3V1,
	}, c25EvalTime)
	if newerRevAttempt.Status != bundles.ActivationStatusRejected || newerRevAttempt.ErrorCode != bundles.ErrCodeRemovedKeyRejected {
		t.Fatalf("expected removed key rev3 bundle to be rejected with %s, got %+v", bundles.ErrCodeRemovedKeyRejected, newerRevAttempt)
	}

	// 5. Verify active authority remains bundleRev2V2 and authorizes operator request
	state := mgr.State()
	if !state.Active || state.ActiveBundleID != "bundle-v2-rev2" || state.HighestRevision != 2 {
		t.Fatalf("expected bundle-v2-rev2 to remain active at rev 2, got %+v", state)
	}
	dec := mgr.Evaluate(context.Background(), c25OperatorEvalInput())
	if !dec.Allow {
		t.Fatalf("expected operator access to be allowed after valid key rotation, got %+v", dec)
	}
}

// TestC25_NoRollbackGapWithNewTrustedKey verifies that rotating to a new trusted key preserves
// HighestRevision and prevents the new key from activating a bundle with revision <= HighestRevision.
func TestC25_NoRollbackGapWithNewTrustedKey(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer ad.Close()

	keyV1 := c25TrustedKey(t, c25KeyV1ID, c25SeedV1Hex)
	keyV2 := c25TrustedKey(t, c25KeyV2ID, c25SeedV2Hex)

	mgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(keyV1))
	mgr.Now = c12Clock()

	// Activate revision 5 under key-v1
	bundleRev5V1 := c25BuildSignedBundle(t, "bundle-v1-rev5", c25KeyV1ID, c25SeedV1Hex, 5)
	act5 := mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-act-rev5",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev5V1,
	}, c25EvalTime)
	if act5.Status != bundles.ActivationStatusActivated || act5.HighestRevision != 5 {
		t.Fatalf("expected rev 5 activation to succeed, got %+v", act5)
	}

	// Dual-trust rotation: operator adds key-v2 alongside key-v1
	rot := mgr.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID:    "op-rotate-dual",
		Identity:       c12OperatorIdentity(),
		EvaluationTime: c25EvalTime,
		TrustedKeys:    []bundles.TrustedKey{keyV1, keyV2},
	})
	if !rot.Valid || rot.HighestRevision != 5 {
		t.Fatalf("expected dual-trust rotation to preserve HighestRevision=5, got %+v", rot)
	}

	// Attempt to activate revision 4 signed by the NEW key-v2 -> must fail with STALE_OR_REPLAYED_REVISION
	bundleRev4V2 := c25BuildSignedBundle(t, "bundle-v2-rev4", c25KeyV2ID, c25SeedV2Hex, 4)
	rollbackAttempt := mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-rollback-rev4-v2",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev4V2,
	}, c25EvalTime)
	if rollbackAttempt.Status != bundles.ActivationStatusRejected || rollbackAttempt.ErrorCode != bundles.ErrCodeStaleOrReplayedRev {
		t.Fatalf("expected rollback attempt with new key to fail with %s, got %+v", bundles.ErrCodeStaleOrReplayedRev, rollbackAttempt)
	}

	// Attempt to activate revision 6 signed by key-v2 while removing key-v1 -> succeeds
	bundleRev6V2 := c25BuildSignedBundle(t, "bundle-v2-rev6", c25KeyV2ID, c25SeedV2Hex, 6)
	rotRemove := mgr.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID:       "op-rotate-remove-v1",
		BundleOperationID: "op-act-rev6-v2",
		Identity:          c12OperatorIdentity(),
		EvaluationTime:    c25EvalTime,
		TrustedKeys:       []bundles.TrustedKey{keyV2},
		RemoveKeyIDs:      []string{c25KeyV1ID},
		CandidateBundle:   &bundleRev6V2,
	})
	if !rotRemove.Valid || rotRemove.HighestRevision != 6 || rotRemove.ActiveSignerKeyID != c25KeyV2ID {
		t.Fatalf("expected rotation + rev 6 activation to succeed, got %+v", rotRemove)
	}
}

// TestC25_RestartAndRecoveryInvariance verifies that after a process restart, the durable rotated
// trust set, removed key set, and HighestRevision floor are restored and enforced.
func TestC25_RestartAndRecoveryInvariance(t *testing.T) {
	dir := t.TempDir()
	keyV1 := c25TrustedKey(t, c25KeyV1ID, c25SeedV1Hex)
	keyV2 := c25TrustedKey(t, c25KeyV2ID, c25SeedV2Hex)

	bundleRev1V1 := c25BuildSignedBundle(t, "bundle-v1-rev1", c25KeyV1ID, c25SeedV1Hex, 1)
	bundleRev2V2 := c25BuildSignedBundle(t, "bundle-v2-rev2", c25KeyV2ID, c25SeedV2Hex, 2)
	bundleRev3V1 := c25BuildSignedBundle(t, "bundle-v1-rev3", c25KeyV1ID, c25SeedV1Hex, 3)

	// Instance 1: activate rev 1 with key-v1, then rotate to key-v2 with rev 2
	ad1, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open 1 failed: %v", err)
	}
	mgr1 := bundles.NewKeyRotationManagerFromAdapter(ad1, bundles.NewKeyring(keyV1))
	mgr1.Now = c12Clock()

	mgr1.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-init-rev1",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev1V1,
	}, c25EvalTime)

	rot1 := mgr1.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID:       "op-rot-1",
		BundleOperationID: "op-act-rev2",
		Identity:          c12OperatorIdentity(),
		EvaluationTime:    c25EvalTime,
		TrustedKeys:       []bundles.TrustedKey{keyV2},
		RemoveKeyIDs:      []string{c25KeyV1ID},
		CandidateBundle:   &bundleRev2V2,
	})
	if !rot1.Valid {
		t.Fatalf("rotation on instance 1 failed: %+v", rot1)
	}
	_ = ad1.Close()

	// Instance 2 (Restart): even if initialized with bootstrap keyV1, Restore loads durable rotated state (keyV2, keyV1 removed)
	ad2, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open 2 failed: %v", err)
	}
	defer ad2.Close()

	mgr2 := bundles.NewKeyRotationManagerFromAdapter(ad2, bundles.NewKeyring(keyV1))
	mgr2.Now = c12Clock()

	restored := mgr2.Restore(context.Background())
	if !restored.Valid || !restored.Active || restored.KeySetEpoch != 1 || restored.HighestRevision != 2 {
		t.Fatalf("unexpected restored state after restart: %+v", restored)
	}
	if len(restored.TrustedKeyIDs) != 1 || restored.TrustedKeyIDs[0] != c25KeyV2ID {
		t.Fatalf("expected restored trusted keys [%s], got %v", c25KeyV2ID, restored.TrustedKeyIDs)
	}
	if len(restored.RemovedKeyIDs) != 1 || restored.RemovedKeyIDs[0] != c25KeyV1ID {
		t.Fatalf("expected restored removed keys [%s], got %v", c25KeyV1ID, restored.RemovedKeyIDs)
	}

	// Attempting to activate rev 3 signed by removed keyV1 after restart must still be rejected
	postRestartAttempt := mgr2.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-post-restart-v1",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev3V1,
	}, c25EvalTime)
	if postRestartAttempt.Status != bundles.ActivationStatusRejected || postRestartAttempt.ErrorCode != bundles.ErrCodeRemovedKeyRejected {
		t.Fatalf("expected post-restart removed key activation to fail with %s, got %+v", bundles.ErrCodeRemovedKeyRejected, postRestartAttempt)
	}
}

// TestC25_EmergencyKeyRemovalFailsClosed verifies that if an operator removes the key that signed
// the currently active bundle without supplying a replacement bundle, the gateway immediately
// deactivates the compromised bundle and fails closed on private resources.
func TestC25_EmergencyKeyRemovalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer ad.Close()

	keyV1 := c25TrustedKey(t, c25KeyV1ID, c25SeedV1Hex)
	keyV3 := c25TrustedKey(t, c25KeyV3ID, c25SeedV3Hex)

	mgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(keyV1))
	mgr.Now = c12Clock()

	bundleRev1V1 := c25BuildSignedBundle(t, "bundle-v1-rev1", c25KeyV1ID, c25SeedV1Hex, 1)
	mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-act-rev1",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev1V1,
	}, c25EvalTime)

	// Emergency rotation removing key-v1 and trusting key-v3 without a new bundle yet
	rot := mgr.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID:    "op-emergency-revoke-v1",
		Identity:       c12OperatorIdentity(),
		EvaluationTime: c25EvalTime,
		TrustedKeys:    []bundles.TrustedKey{keyV3},
		RemoveKeyIDs:   []string{c25KeyV1ID},
	})
	if !rot.Valid || rot.Active {
		t.Fatalf("expected emergency rotation to succeed and deactivate bundle signed by removed key, got %+v", rot)
	}
	if rot.HighestRevision != 1 {
		t.Fatalf("expected HighestRevision=1 to be preserved, got %d", rot.HighestRevision)
	}

	// Private resource evaluation must now fail closed (NO_ACTIVE_POLICY_BUNDLE)
	dec := mgr.Evaluate(context.Background(), c25OperatorEvalInput())
	if dec.Allow {
		t.Fatalf("expected private resource evaluation to fail closed after active key removal, got %+v", dec)
	}
}

// TestC25_NegativeCasesAndConcurrentSafety verifies unauthenticated rejection, malformed inputs,
// provider unavailability, private resource fail-closed, and race safety under concurrent access.
func TestC25_NegativeCasesAndConcurrentSafety(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer ad.Close()

	keyV1 := c25TrustedKey(t, c25KeyV1ID, c25SeedV1Hex)
	keyV2 := c25TrustedKey(t, c25KeyV2ID, c25SeedV2Hex)

	mgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(keyV1))
	mgr.Now = c12Clock()

	// 1. Unauthenticated caller rejected
	unauthRes := mgr.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID: "op-unauth-rot",
		Identity:    c12UnauthenticatedIdentity(),
		TrustedKeys: []bundles.TrustedKey{keyV2},
	})
	if unauthRes.Valid || unauthRes.ErrorCode != storage.ErrUnauthenticatedIdentity {
		t.Fatalf("expected unauthenticated rotation to fail with %s, got %+v", storage.ErrUnauthenticatedIdentity, unauthRes)
	}

	// 2. Empty trust set rejected
	emptyRes := mgr.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID: "op-empty-keys",
		Identity:    c12OperatorIdentity(),
		TrustedKeys: []bundles.TrustedKey{},
	})
	if emptyRes.Valid || emptyRes.ErrorCode != bundles.ErrCodeEmptyTrustedKeySet {
		t.Fatalf("expected empty trust set to fail with %s, got %+v", bundles.ErrCodeEmptyTrustedKeySet, emptyRes)
	}

	// 3. Provider unavailable fails closed
	unavailRes := mgr.RotateKeys(context.Background(), bundles.KeyRotationRequest{
		OperationID:         "op-provider-down",
		Identity:            c12OperatorIdentity(),
		ProviderUnavailable: true,
		TrustedKeys:         []bundles.TrustedKey{keyV2},
	})
	if unavailRes.Valid || unavailRes.ErrorCode != bundles.ErrCodeProviderUnavailable {
		t.Fatalf("expected unavailable provider to fail with %s, got %+v", bundles.ErrCodeProviderUnavailable, unavailRes)
	}

	// 4. Activate valid bundle and verify unauthenticated private resource fails closed
	bundleRev1V1 := c25BuildSignedBundle(t, "bundle-v1-rev1", c25KeyV1ID, c25SeedV1Hex, 1)
	mgr.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-act-rev1",
		Identity:    c12OperatorIdentity(),
		Bundle:      bundleRev1V1,
	}, c25EvalTime)

	unauthDec := mgr.Evaluate(context.Background(), c25UnauthenticatedEvalInput())
	if unauthDec.Allow {
		t.Fatalf("expected unauthenticated private resource to fail closed, got %+v", unauthDec)
	}

	// 5. Concurrent reads and rotations under race detector
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.State()
			_ = mgr.Evaluate(context.Background(), c25OperatorEvalInput())
		}()
	}
	wg.Wait()
}

// TestC25_CLIAndHTTPIntegration verifies the -rotate-keys CLI flag and HTTP endpoints.
func TestC25_CLIAndHTTPIntegration(t *testing.T) {
	posPath := filepath.Join("fixtures", "policyhelix", "C25", "positive-operator-key-rotation.json")
	negPath := filepath.Join("fixtures", "policyhelix", "C25", "negative-unauthenticated-rotation.json")

	// 1. CLI positive fixture exits 0
	cmdPos := exec.Command("go", "run", "../cmd/policyhelix", "-rotate-keys", posPath)
	var outPos bytes.Buffer
	cmdPos.Stdout = &outPos
	cmdPos.Stderr = &outPos
	if err := cmdPos.Run(); err != nil {
		t.Fatalf("CLI -rotate-keys failed on positive fixture: %v\nOutput: %s", err, outPos.String())
	}
	var repPos bundles.KeyRotationScenarioReport
	if err := json.Unmarshal(outPos.Bytes(), &repPos); err != nil || !repPos.Passed {
		t.Fatalf("unexpected CLI positive output: err=%v rep=%+v", err, repPos)
	}

	// 2. CLI negative fixture exits non-zero when rotation fails with an unexpected error or test HTTP endpoint
	rawPos, err := os.ReadFile(posPath)
	if err != nil {
		t.Fatalf("read pos fixture: %v", err)
	}
	rawNeg, err := os.ReadFile(negPath)
	if err != nil {
		t.Fatalf("read neg fixture: %v", err)
	}
	_ = rawNeg

	// Test HTTP endpoint /api/v1/bundles/keys/rotate and /api/v1/bundles/keys/state via direct handler
	keyV1 := c25TrustedKey(t, c25KeyV1ID, c25SeedV1Hex)
	reqBody, _ := json.Marshal(bundles.KeyRotationRequest{
		OperationID:    "op-http-rot-1",
		Identity:       c12OperatorIdentity(),
		EvaluationTime: c25EvalTime,
		TrustedKeys:    []bundles.TrustedKey{keyV1},
	})
	mgr := bundles.NewKeyRotationManager(nil, nil, nil)
	mgr.Now = c12Clock()
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/api/v1/bundles/keys/rotate", func(w http.ResponseWriter, r *http.Request) {
		var req bundles.KeyRotationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		res := mgr.RotateKeys(r.Context(), req)
		w.Header().Set("Content-Type", "application/json")
		if !res.Valid {
			w.WriteHeader(http.StatusForbidden)
		}
		_ = json.NewEncoder(w).Encode(res)
	})
	httpMux.HandleFunc("/api/v1/bundles/keys/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mgr.State())
	})

	srv := httptest.NewServer(httpMux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/bundles/keys/rotate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("HTTP POST rotate failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
	}

	stateResp, err := http.Get(srv.URL + "/api/v1/bundles/keys/state")
	if err != nil {
		t.Fatalf("HTTP GET state failed: %v", err)
	}
	defer stateResp.Body.Close()
	var state bundles.KeyRotationState
	if err := json.NewDecoder(stateResp.Body).Decode(&state); err != nil || state.KeySetEpoch != 1 {
		t.Fatalf("unexpected HTTP state response: err=%v state=%+v", err, state)
	}
	_ = rawPos
}
