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

type c36Manifest struct {
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

// TestC36FixturesManifest validates that all C36 synthetic positive and negative
// fixtures exist, match pinned SHA-256 digests in manifest.json, and enforce Apache-2.0 licensing.
func TestC36FixturesManifest(t *testing.T) {
	manifestPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C36", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read C36 manifest: %v", err)
	}

	var m c36Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to parse C36 manifest: %v", err)
	}

	if m.CommitID != "C36" {
		t.Errorf("Expected commit_id C36, got %s", m.CommitID)
	}
	if m.Requirement != "N36" {
		t.Errorf("Expected requirement N36, got %s", m.Requirement)
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

// TestC36OnboardingInvariants verifies Requirement N36:
// Clean-host independent onboarding invariants, fail-closed handling on missing prerequisites,
// and state recovery across process restart.
func TestC36OnboardingInvariants(t *testing.T) {
	tempDir := t.TempDir()
	adapter, orphans, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to open storage adapter: %v", err)
	}
	defer adapter.Close()
	if orphans != 0 {
		t.Errorf("Expected 0 orphans on clean dir, got %d", orphans)
	}

	ctx := context.Background()

	// 1. Invariant: Private resources fail closed on unauthenticated caller
	unauthReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c36-unauth",
		RecordID:       "service:analytics:bundle-active",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity: storage.CallerIdentity{
			SubjectID:                "",
			Roles:                    []string{},
			Authenticated:            false,
			UntrustedHeadersStripped: true,
			ProviderState:            "ready",
		},
		Payload: json.RawMessage(`{"rules":["allow = false"]}`),
	}

	_, sErr := adapter.WriteRecord(ctx, unauthReq)
	if sErr == nil {
		t.Fatalf("Expected unauthenticated write to fail closed, got nil error")
	}
	if sErr.Code != storage.ErrUnauthenticatedIdentity {
		t.Fatalf("Expected %s, got: %v", storage.ErrUnauthenticatedIdentity, sErr)
	}

	// 2. Invariant: Authorized caller writes initial bundle state
	operatorIdentity := storage.CallerIdentity{
		SubjectID:                "operator@policyhelix.local",
		Issuer:                   "https://issuer.policyhelix.local",
		Roles:                    []string{"operator"},
		Authenticated:            true,
		SessionEpoch:             1730000000,
		MinRequiredEpoch:         1720000000,
		UntrustedHeadersStripped: true,
		ProviderState:            "ready",
	}

	authReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c36-init",
		RecordID:       "service:analytics:bundle-active",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity:       operatorIdentity,
		Payload:        json.RawMessage(`{"bundle_id":"bundle-c36-v1","revision":1,"rules":["allow = true"]}`),
	}

	receipt, sErr := adapter.WriteRecord(ctx, authReq)
	if sErr != nil {
		t.Fatalf("Failed to write initial bundle: %v", sErr)
	}
	if receipt.Revision != 1 {
		t.Fatalf("Expected revision 1, got %d", receipt.Revision)
	}

	// 3. Close and Re-open to simulate process restart & restore invariant
	if err := adapter.Close(); err != nil {
		t.Fatalf("Failed to close adapter: %v", err)
	}

	reopenedAdapter, reopenedOrphans, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to re-open storage adapter after restart: %v", err)
	}
	defer reopenedAdapter.Close()
	if reopenedOrphans != 0 {
		t.Errorf("Expected 0 orphans on clean re-open, got %d", reopenedOrphans)
	}

	// 4. Verify that state survived restart
	data, entry, readErr := reopenedAdapter.ReadRecord("service:analytics:bundle-active")
	if readErr != nil {
		t.Fatalf("Failed to read record after restart: %v", readErr)
	}
	if entry == nil || entry.Revision != 1 {
		t.Fatalf("Expected revision 1 after restart, got: %+v", entry)
	}
	if !strings.Contains(string(data), "bundle-c36-v1") {
		t.Fatalf("Expected data to contain bundle-c36-v1, got: %s", string(data))
	}
}

// TestC36OnboardingDocAndGuideRejectsGatekeeping validates that the onboarding
// documentation explicitly confirms zero paid pilots and zero commercial prerequisites.
func TestC36OnboardingDocAndGuideRejectsGatekeeping(t *testing.T) {
	resultsPath := filepath.Join("..", "docs", "product", "ONBOARDING_RESULTS.md")
	content, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("Failed to read ONBOARDING_RESULTS.md: %v", err)
	}

	text := string(content)
	requiredPhrases := []string{
		"Customer demand and five pilots are not prerequisites for OSS usability",
		"Apache-2.0",
		"npm run setup",
		"npm start",
		"REFERENCE_RUNTIME_UNAVAILABLE",
		"FORGED_HEADER_REJECTED",
	}

	for _, phrase := range requiredPhrases {
		if !strings.Contains(text, phrase) {
			t.Errorf("ONBOARDING_RESULTS.md missing required text: %q", phrase)
		}
	}
}
