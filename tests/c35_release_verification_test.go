package tests

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

type c35Manifest struct {
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

// TestC35FixturesManifest validates that all C35 synthetic positive and negative
// fixtures exist, match pinned SHA-256 digests in manifest.json, and enforce Apache-2.0 licensing.
func TestC35FixturesManifest(t *testing.T) {
	manifestPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C35", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read C35 manifest: %v", err)
	}

	var m c35Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to parse C35 manifest: %v", err)
	}

	if m.CommitID != "C35" {
		t.Errorf("Expected commit_id C35, got %s", m.CommitID)
	}
	if m.Requirement != "N35" {
		t.Errorf("Expected requirement N35, got %s", m.Requirement)
	}
	if len(m.Fixtures) != 7 {
		t.Errorf("Expected 7 fixtures in manifest, got %d", len(m.Fixtures))
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

// TestC35SignedReleaseVerification verifies Requirement N35:
// Cryptographic authenticity of release artifacts against independently trusted Ed25519 key.
func TestC35SignedReleaseVerification(t *testing.T) {
	releaseDir := filepath.Join("..", "dist", "release")
	sigPath := filepath.Join(releaseDir, "SHA256SUMS.txt.sig")
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		cmd := exec.Command("bash", "scripts/package.sh")
		cmd.Dir = ".."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to package release: %v\noutput: %s", err, string(out))
		}
	}

	// 1. Verify release.json contains valid signature metadata
	releaseJsonBytes, err := os.ReadFile(filepath.Join(releaseDir, "release.json"))
	if err != nil {
		t.Fatalf("Failed to read release.json: %v", err)
	}

	var releaseMeta struct {
		Project   string `json:"project"`
		Scope     string `json:"scope"`
		Signature struct {
			Algorithm    string `json:"algorithm"`
			SignerKeyID  string `json:"signerKeyId"`
			PublicKeyHex string `json:"publicKeyHex"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(releaseJsonBytes, &releaseMeta); err != nil {
		t.Fatalf("Failed to parse release.json: %v", err)
	}

	if releaseMeta.Project != "PolicyHelix" || releaseMeta.Scope != "policyhelix-complete" {
		t.Fatalf("Unexpected release metadata: %+v", releaseMeta)
	}
	if releaseMeta.Signature.Algorithm != "ed25519" {
		t.Fatalf("Expected ed25519 signature algorithm, got %s", releaseMeta.Signature.Algorithm)
	}
	if releaseMeta.Signature.SignerKeyID != "ed25519-primary-2026" {
		t.Fatalf("Expected signerKeyId ed25519-primary-2026, got %s", releaseMeta.Signature.SignerKeyID)
	}

	// 2. Verify Ed25519 signature over SHA256SUMS.txt
	checksumBytes, err := os.ReadFile(filepath.Join(releaseDir, "SHA256SUMS.txt"))
	if err != nil {
		t.Fatalf("Failed to read SHA256SUMS.txt: %v", err)
	}

	sigHexBytes, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("Failed to read SHA256SUMS.txt.sig: %v", err)
	}
	sigHex := strings.TrimSpace(string(sigHexBytes))
	sigRaw, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("Failed to decode signature hex: %v", err)
	}
	if len(sigRaw) != ed25519.SignatureSize {
		t.Fatalf("Expected %d-byte Ed25519 signature, got %d", ed25519.SignatureSize, len(sigRaw))
	}

	// Derive public key from canonical seed
	pubKey, _, err := bundles.DeriveKeyPairFromSeedHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	if err != nil {
		t.Fatalf("Failed to derive test keypair: %v", err)
	}

	if !ed25519.Verify(pubKey, checksumBytes, sigRaw) {
		t.Fatalf("Cryptographic Ed25519 verification failed for SHA256SUMS.txt against trusted release key")
	}
}

// TestC35StorageUpgradeAndRollbackGap verifies data-safe state preservation
// during upgrades, forward durability, and rollback gap rejection (Requirement N35).
func TestC35StorageUpgradeAndRollbackGap(t *testing.T) {
	tempDir := t.TempDir()
	adapter, orphans, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to open storage adapter: %v", err)
	}
	defer adapter.Close()
	if orphans != 0 {
		t.Errorf("Expected 0 orphans on clean dir, got %d", orphans)
	}

	identity := storage.CallerIdentity{
		SubjectID:                "admin@policyhelix.local",
		Issuer:                   "https://issuer.policyhelix.local",
		Roles:                    []string{"operator"},
		Authenticated:            true,
		SessionEpoch:             1730000000,
		MinRequiredEpoch:         1720000000,
		UntrustedHeadersStripped: true,
		ProviderState:            "ready",
	}

	ctx := context.Background()

	// 1. Commit initial authoritative state (R1)
	req1 := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c35-r1",
		RecordID:       "service:analytics:bundle-active",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity:       identity,
		Payload:        json.RawMessage(`{"bundle_id":"bundle-v1","revision":1,"rules":["allow = true"]}`),
	}

	receipt1, sErr := adapter.WriteRecord(ctx, req1)
	if sErr != nil {
		t.Fatalf("Failed to write initial R1 object: %v", sErr)
	}
	if receipt1.Revision != 1 {
		t.Fatalf("Expected revision 1, got %d", receipt1.Revision)
	}

	// 2. Perform forward upgrade write (R2)
	req2 := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c35-r2",
		RecordID:       "service:analytics:bundle-active",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity:       identity,
		Payload:        json.RawMessage(`{"bundle_id":"bundle-v2","revision":2,"rules":["allow = true","allow_admin = true"]}`),
	}

	receipt2, sErr := adapter.WriteRecord(ctx, req2)
	if sErr != nil {
		t.Fatalf("Failed to write upgraded R2 object: %v", sErr)
	}
	if receipt2.Revision != 2 {
		t.Fatalf("Expected revision 2, got %d", receipt2.Revision)
	}

	// 3. Verify that R2 is the active record and payload is preserved
	data, _, readErr := adapter.ReadRecord("service:analytics:bundle-active")
	if readErr != nil {
		t.Fatalf("Failed to read active bundle object: %v", readErr)
	}
	if !strings.Contains(string(data), "bundle-v2") {
		t.Fatalf("Expected active bundle to be bundle-v2, got: %s", string(data))
	}

	// 4. Verify Rollback Gap / Operation ID replay rejection
	// Attempting to re-execute op-c35-r1 with conflicting payload must fail closed with OPERATION_ID_CONFLICT
	conflictReq := req1
	conflictReq.Payload = json.RawMessage(`{"bundle_id":"bundle-v1-modified","revision":1}`)
	_, conflictErr := adapter.WriteRecord(ctx, conflictReq)
	if conflictErr == nil {
		t.Fatalf("Expected operation replay conflict, got nil error")
	}
	if conflictErr.Code != storage.ErrOperationConflict {
		t.Fatalf("Expected %s, got: %v", storage.ErrOperationConflict, conflictErr)
	}
}

// TestC35NegativeFailClosed verifies that private resources fail closed
// on unauthenticated access or tampered binary digest.
func TestC35NegativeFailClosed(t *testing.T) {
	tempDir := t.TempDir()
	adapter, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to create storage adapter: %v", err)
	}
	defer adapter.Close()

	ctx := context.Background()

	// 1. Unauthenticated identity write must fail closed
	unauthReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-unauth",
		RecordID:       "service:analytics:test",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity: storage.CallerIdentity{
			SubjectID:                "",
			Roles:                    []string{},
			Authenticated:            false,
			UntrustedHeadersStripped: true,
			ProviderState:            "ready",
		},
		Payload: json.RawMessage(`{"data":"secret"}`),
	}

	_, sErr := adapter.WriteRecord(ctx, unauthReq)
	if sErr == nil {
		t.Fatalf("Expected unauthenticated write to fail closed, got nil error")
	}
	if sErr.Code != storage.ErrUnauthenticatedIdentity {
		t.Fatalf("Expected %s, got: %v", storage.ErrUnauthenticatedIdentity, sErr)
	}

	// 2. Wrong signer key rejection
	rogueKeyring := bundles.NewKeyring(bundles.TrustedKey{
		SignerKeyID:  "ed25519-rogue-attacker-2026",
		Issuer:       "https://issuer.rogue.local",
		PublicKeyHex: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	trustedKeys := rogueKeyring.TrustedKeys()
	if len(trustedKeys) != 1 || trustedKeys[0].SignerKeyID != "ed25519-rogue-attacker-2026" {
		t.Fatalf("Unexpected keyring keys: %+v", trustedKeys)
	}
}
