package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type c33Manifest struct {
	ManifestVersion int `json:"manifest_version"`
	CommitID        string `json:"commit_id"`
	Fixtures        []struct {
		Path        string `json:"path"`
		Sha256      string `json:"sha256"`
		Kind        string `json:"kind"`
		Description string `json:"description"`
	} `json:"fixtures"`
}

func TestC33UXFixturesAndManifest(t *testing.T) {
	manifestPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C33", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read C33 manifest: %v", err)
	}

	var m c33Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to parse C33 manifest: %v", err)
	}

	if m.CommitID != "C33" {
		t.Errorf("Expected commit_id C33, got %s", m.CommitID)
	}
	if len(m.Fixtures) != 7 {
		t.Errorf("Expected 7 fixtures in manifest, got %d", len(m.Fixtures))
	}

	// Verify every fixture exists and digest matches manifest
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
		actualDigest := hex.EncodeToString(h.Sum(nil))
		if actualDigest != f.Sha256 {
			t.Errorf("Digest mismatch for %s: expected %s, got %s", f.Path, f.Sha256, actualDigest)
		}
	}

	// Verify N-1 export schema compatibility
	nMinus1Path := filepath.Join("..", "tests", "fixtures", "policyhelix", "C33", "positive-n-minus-1-export.json")
	nMinus1Data, err := os.ReadFile(nMinus1Path)
	if err != nil {
		t.Fatalf("Failed to read N-1 fixture: %v", err)
	}
	var nMinus1 struct {
		SchemaVersion int `json:"schema_version"`
		Workflow      struct {
			TotalStages  int `json:"total_stages"`
			PassedStages int `json:"passed_stages"`
			Stages       []struct {
				Stage  string `json:"stage"`
				Status string `json:"status"`
			} `json:"stages"`
		} `json:"workflow"`
	}
	if err := json.Unmarshal(nMinus1Data, &nMinus1); err != nil {
		t.Fatalf("Failed to parse N-1 export fixture: %v", err)
	}
	if nMinus1.SchemaVersion != 1 {
		t.Errorf("Expected N-1 schema_version 1, got %d", nMinus1.SchemaVersion)
	}
	if len(nMinus1.Workflow.Stages) != 6 {
		t.Errorf("Expected 6 stages in N-1 export, got %d", len(nMinus1.Workflow.Stages))
	}

	// Verify negative tampered export fails closed
	tamperedPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C33", "negative-tampered-export.json")
	tamperedData, err := os.ReadFile(tamperedPath)
	if err != nil {
		t.Fatalf("Failed to read tampered export fixture: %v", err)
	}
	var tampered struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(tamperedData, &tampered); err != nil {
		t.Fatalf("Failed to parse tampered export fixture: %v", err)
	}
	if tampered.SchemaVersion == 1 || tampered.SchemaVersion == 2 {
		t.Errorf("Tampered fixture must not claim valid schema version 1 or 2, got %d", tampered.SchemaVersion)
	}

	// Verify negative provider outage invariants
	outagePath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C33", "negative-provider-outage.json")
	outageData, err := os.ReadFile(outagePath)
	if err != nil {
		t.Fatalf("Failed to read provider outage fixture: %v", err)
	}
	var outage struct {
		ExpectedOutcome struct {
			DecisionOutageAllow  bool `json:"decision_outage_allow"`
			IdpOutageAllow       bool `json:"idp_outage_allow"`
			ActiveBundleRetained bool `json:"active_bundle_retained"`
		} `json:"expected_outcome"`
	}
	if err := json.Unmarshal(outageData, &outage); err != nil {
		t.Fatalf("Failed to parse provider outage fixture: %v", err)
	}
	if outage.ExpectedOutcome.DecisionOutageAllow {
		t.Errorf("Decision outage must fail closed with allow=false")
	}
	if outage.ExpectedOutcome.IdpOutageAllow {
		t.Errorf("IdP outage must fail closed with allow=false")
	}
	if !outage.ExpectedOutcome.ActiveBundleRetained {
		t.Errorf("Outage must retain active bundle authority")
	}
}
