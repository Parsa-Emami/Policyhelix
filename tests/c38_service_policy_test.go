package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/storage"
)

type c38Manifest struct {
	ManifestVersion int    `json:"manifest_version"`
	CommitID        string `json:"commit_id"`
	Requirement     string `json:"requirement"`
	Fixtures        []struct {
		FixtureID   string `json:"fixture_id"`
		Path        string `json:"path"`
		Sha256      string `json:"sha256"`
		Kind        string `json:"kind"`
		Description string `json:"description"`
		License     string `json:"license"`
	} `json:"fixtures"`
}

// TestC38FixturesManifest validates that all C38 synthetic positive and negative
// fixtures exist, match pinned SHA-256 digests in manifest.json, and enforce Apache-2.0 licensing.
func TestC38FixturesManifest(t *testing.T) {
	manifestPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C38", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read C38 manifest: %v", err)
	}

	var m c38Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to parse C38 manifest: %v", err)
	}

	if m.CommitID != "C38" {
		t.Errorf("Expected commit_id C38, got %s", m.CommitID)
	}
	if m.Requirement != "N38" {
		t.Errorf("Expected requirement N38, got %s", m.Requirement)
	}
	if len(m.Fixtures) != 6 {
		t.Errorf("Expected 6 fixtures in manifest, got %d", len(m.Fixtures))
	}

	for _, f := range m.Fixtures {
		filePath := filepath.Join("..", f.Path)
		file, err := os.Open(filePath)
		if err != nil {
			t.Fatalf("Fixture file missing: %s (%v)", f.Path, err)
		}
		h := sha256.New()
		if _, err := io.Copy(h, file); err != nil {
			file.Close()
			t.Fatalf("Failed to read fixture: %s (%v)", f.Path, err)
		}
		file.Close()

		actualSha := hex.EncodeToString(h.Sum(nil))
		if actualSha != f.Sha256 {
			t.Errorf("SHA-256 mismatch for %s: expected %s, got %s", f.Path, f.Sha256, actualSha)
		}
		if f.License != "Apache-2.0" {
			t.Errorf("Fixture %s must be Apache-2.0 licensed, got %s", f.Path, f.License)
		}
	}
}

// TestC38WriterCrashAtStagedByteBoundary verifies Requirement N38:
// Killing the writer at the staged-byte/manifest boundary is cleaned up on restart,
// exposing only the complete prior valid state.
func TestC38WriterCrashAtStagedByteBoundary(t *testing.T) {
	tempDir := t.TempDir()
	ad, orphans, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to open storage adapter: %v", err)
	}
	if orphans != 0 {
		t.Errorf("Expected 0 orphans on clean dir, got %d", orphans)
	}

	ctx := context.Background()
	identity := storage.CallerIdentity{
		SubjectID:                "operator@policyhelix.local",
		Issuer:                   "https://issuer.policyhelix.local",
		Roles:                    []string{"operator"},
		Authenticated:            true,
		SessionEpoch:             1730000000,
		MinRequiredEpoch:         1720000000,
		UntrustedHeadersStripped: true,
		ProviderState:            "ready",
	}

	// 1. Commit initial authoritative state (R1)
	req1 := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c38-init",
		RecordID:       "service:analytics:bundle-active",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity:       identity,
		Payload:        json.RawMessage(`{"bundle_id":"bundle-r1","revision":1,"rules":["allow = true"]}`),
	}

	receipt1, sErr := ad.WriteRecord(ctx, req1)
	if sErr != nil {
		t.Fatalf("Failed to write initial R1: %v", sErr)
	}
	if receipt1.Revision != 1 {
		t.Fatalf("Expected revision 1, got %d", receipt1.Revision)
	}

	// Close cleanly
	if err := ad.Close(); err != nil {
		t.Fatalf("Failed to close adapter: %v", err)
	}

	// 2. Simulate crashed writer: inject stray uncommitted file into .staging/ and stray manifest.json.tmp
	stagingDir := filepath.Join(tempDir, storage.StagingDirName)
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		t.Fatalf("Failed to create staging dir: %v", err)
	}
	orphanStagedFile := filepath.Join(stagingDir, "temp-op-crashed-writer")
	if err := os.WriteFile(orphanStagedFile, []byte(`{"in-flight":"incomplete-write"}`), 0644); err != nil {
		t.Fatalf("Failed to write orphan staged file: %v", err)
	}

	strayManifestTmp := filepath.Join(tempDir, storage.ManifestFileName+".tmp")
	if err := os.WriteFile(strayManifestTmp, []byte(`{"corrupt":"half-written"}`), 0644); err != nil {
		t.Fatalf("Failed to write stray manifest temp file: %v", err)
	}

	// 3. Restart engine: storage.Open must clean the orphaned staging file and manifest.json.tmp
	reopenedAd, orphansCleaned, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to re-open storage adapter after crash: %v", err)
	}
	defer reopenedAd.Close()

	if orphansCleaned != 2 {
		t.Errorf("Expected 2 orphans cleaned on crash recovery, got %d", orphansCleaned)
	}

	// 4. Verify that only prior authoritative R1 state is exposed
	data, entry, readErr := reopenedAd.ReadRecord("service:analytics:bundle-active")
	if readErr != nil {
		t.Fatalf("Failed to read record after crash recovery: %v", readErr)
	}
	if entry == nil || entry.Revision != 1 {
		t.Fatalf("Expected revision 1 to be exposed, got: %+v", entry)
	}
	if !strings.Contains(string(data), "bundle-r1") {
		t.Fatalf("Expected data to contain bundle-r1, got: %s", string(data))
	}

	// Verify orphan files were physically purged
	if _, err := os.Stat(orphanStagedFile); !os.IsNotExist(err) {
		t.Errorf("Orphan staged file was not purged on recovery")
	}
	if _, err := os.Stat(strayManifestTmp); !os.IsNotExist(err) {
		t.Errorf("Stray manifest temp file was not purged on recovery")
	}
}

// TestC38OperationReplayAndLostAck verifies Requirement N38:
// Replaying an operation after a lost ACK returns the cached receipt (idempotent, 0 duplicate side effects),
// and replaying with conflicting payload fails closed with ErrOperationConflict.
func TestC38OperationReplayAndLostAck(t *testing.T) {
	tempDir := t.TempDir()
	ad, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to open storage adapter: %v", err)
	}
	defer ad.Close()

	ctx := context.Background()
	identity := storage.CallerIdentity{
		SubjectID:                "operator@policyhelix.local",
		Issuer:                   "https://issuer.policyhelix.local",
		Roles:                    []string{"operator"},
		Authenticated:            true,
		SessionEpoch:             1730000000,
		MinRequiredEpoch:         1720000000,
		UntrustedHeadersStripped: true,
		ProviderState:            "ready",
	}

	req := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c38-idempotent-test",
		RecordID:       "service:analytics:bundle-test",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity:       identity,
		Payload:        json.RawMessage(`{"bundle":"v1","rules":["allow = true"]}`),
	}

	// 1. Initial write
	receipt1, sErr := ad.WriteRecord(ctx, req)
	if sErr != nil {
		t.Fatalf("Initial WriteRecord failed: %v", sErr)
	}
	if receipt1.Replayed {
		t.Errorf("Initial write should have Replayed=false")
	}

	// 2. Client loses ACK and replays identical request
	receipt2, sErr := ad.WriteRecord(ctx, req)
	if sErr != nil {
		t.Fatalf("Replayed WriteRecord failed: %v", sErr)
	}
	if !receipt2.Replayed {
		t.Errorf("Replayed write should have Replayed=true")
	}
	if receipt2.Revision != receipt1.Revision {
		t.Errorf("Replayed write revision mismatch: got %d, want %d", receipt2.Revision, receipt1.Revision)
	}
	if receipt2.ObjectDigest != receipt1.ObjectDigest {
		t.Errorf("Replayed write digest mismatch: got %s, want %s", receipt2.ObjectDigest, receipt1.ObjectDigest)
	}

	// 3. Replay with conflicting payload fails closed
	conflictReq := req
	conflictReq.Payload = json.RawMessage(`{"bundle":"v1","rules":["allow = false"]}`)
	_, conflictErr := ad.WriteRecord(ctx, conflictReq)
	if conflictErr == nil {
		t.Fatalf("Expected conflict error on modified payload replay, got nil")
	}
	if conflictErr.Code != storage.ErrOperationConflict {
		t.Fatalf("Expected %s, got: %v", storage.ErrOperationConflict, conflictErr)
	}
}

// TestC38ServicePolicyAndMaintenanceDocs validates that SERVICE_POLICY.md and
// MAINTENANCE.md exhaustively document all required sections, local paths, and policies.
func TestC38ServicePolicyAndMaintenanceDocs(t *testing.T) {
	// 1. Validate SERVICE_POLICY.md
	servicePolicyPath := filepath.Join("..", "docs", "release", "SERVICE_POLICY.md")
	spContent, err := os.ReadFile(servicePolicyPath)
	if err != nil {
		t.Fatalf("Failed to read SERVICE_POLICY.md: %v", err)
	}
	spText := string(spContent)
	spRequired := []string{
		"Zero Hosted Subscription",
		"No Unearned Service Level Agreements",
		".local-data/storage/manifest.json",
		".local-data/storage/objects/",
		"local-demo",
		"self-hosted",
		"Apache-2.0",
		"Rollback Gap Prevention",
	}
	for _, phrase := range spRequired {
		if !strings.Contains(spText, phrase) {
			t.Errorf("SERVICE_POLICY.md missing required section/phrase: %q", phrase)
		}
	}

	// 2. Validate MAINTENANCE.md
	maintenancePath := filepath.Join("..", "docs", "release", "MAINTENANCE.md")
	mContent, err := os.ReadFile(maintenancePath)
	if err != nil {
		t.Fatalf("Failed to read MAINTENANCE.md: %v", err)
	}
	mText := string(mContent)
	mRequired := []string{
		"Toolchain Pins & Dependency Governance",
		"Open Policy Agent (OPA)",
		"Keycloak & OpenID Connect (OIDC)",
		"security@policyhelix.org",
		"ReconcileStartup",
		"Operation Replay & Lost ACK Deduplication",
		"ErrOperationConflict",
		"Fail-Closed Security Posture",
	}
	for _, phrase := range mRequired {
		if !strings.Contains(mText, phrase) {
			t.Errorf("MAINTENANCE.md missing required section/phrase: %q", phrase)
		}
	}
}
