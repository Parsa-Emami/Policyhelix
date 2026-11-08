package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type c34Manifest struct {
	ManifestVersion int    `json:"manifest_version"`
	CommitID        string `json:"commit_id"`
	Requirement     string `json:"requirement"`
	Fixtures        []struct {
		Path        string `json:"path"`
		Sha256      string `json:"sha256"`
		Kind        string `json:"kind"`
		Description string `json:"description"`
	} `json:"fixtures"`
}

func TestC34OSSGuidesAndInvariants(t *testing.T) {
	manifestPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C34", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read C34 manifest: %v", err)
	}

	var m c34Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to parse C34 manifest: %v", err)
	}

	if m.CommitID != "C34" {
		t.Errorf("Expected commit_id C34, got %s", m.CommitID)
	}
	if m.Requirement != "N34" {
		t.Errorf("Expected requirement N34, got %s", m.Requirement)
	}
	if len(m.Fixtures) != 6 {
		t.Errorf("Expected 6 fixtures in manifest, got %d", len(m.Fixtures))
	}

	// 1. Verify every fixture exists and digest matches manifest
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

	// 2. Verify all exact target guide deliverables exist and contain required core sections
	targets := []struct {
		path            string
		requiredStrings []string
	}{
		{
			path: filepath.Join("..", "docs", "release", "USER_GUIDE.md"),
			requiredStrings: []string{
				"Prerequisites & System Requirements",
				"Quickstart: Clone, Setup, and Run",
				"Core Task Walkthrough: The 6-Stage Reference Workflow",
				"Independent Source Builds",
				"Licenses & Upstream Attribution",
				"Data Storage & Layout",
				"Operational Limits & Resource Boundaries",
				"Privacy & Telemetry",
				"Crash Recovery & Forward Repair",
				"Community Support & Issue Reporting",
				"Security & Vulnerability Reporting",
				"Apache-2.0",
				"200 ms",
			},
		},
		{
			path: filepath.Join("..", "SECURITY.md"),
			requiredStrings: []string{
				"Confirmed Vulnerability Reporting Route",
				"security@policyhelix.org",
				"GitHub Private Vulnerability Reporting",
				"Response Commitments & SLAs",
				"Supported Versions",
				"Security Architecture & Threat Boundaries",
				"Out of Scope",
				"invalid_host",
				"invalid_origin",
			},
		},
		{
			path: filepath.Join("..", "README.md"),
			requiredStrings: []string{
				"USER_GUIDE.md",
				"CLONE_TO_RUN.md",
				"SECURITY.md",
				"OPEN_SOURCE.md",
				"CONTRIBUTING.md",
				"Independent Source Builds",
				"6-Stage Reference Workflow",
			},
		},
		{
			path: filepath.Join("..", "OPEN_SOURCE.md"),
			requiredStrings: []string{
				"Apache-2.0",
				"No Compulsory Cloud or Paid Accounts",
				"Zero Sibling Repositories",
				"THIRD_PARTY_NOTICES.md",
				"Independent Source Builds",
			},
		},
		{
			path: filepath.Join("..", "CONTRIBUTING.md"),
			requiredStrings: []string{
				"Prerequisites & Toolchain",
				"Planning & Roadmap Governance",
				"Implementation Standards",
				"Verification & Testing",
				"Permanent Owner Restrictions",
				"Developer Certificate of Origin (DCO)",
				"SECURITY.md",
			},
		},
		{
			path: filepath.Join("..", "docs", "engineering", "CLONE_TO_RUN.md"),
			requiredStrings: []string{
				"Runnable Today: Fresh Reader Quickstart",
				"Independent Source Builds",
				"Verified Local-Demo Scope",
				"Local Data Durability, Limits & Recovery",
				"Network Boundaries & Private Hosting",
			},
		},
	}

	for _, tc := range targets {
		content, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("Target document missing: %s (%v)", tc.path, err)
		}
		text := string(content)
		for _, s := range tc.requiredStrings {
			if !strings.Contains(text, s) {
				t.Errorf("Document %s missing required section/string: %q", tc.path, s)
			}
		}
	}

	// 3. Verify negative cases: script sentinels remain inert
	sentinelPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C34", "negative-script-sentinel.json")
	sentinelData, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("Failed to read sentinel fixture: %v", err)
	}
	var sentinelFixture struct {
		Sentinels []string `json:"sentinels"`
	}
	if err := json.Unmarshal(sentinelData, &sentinelFixture); err != nil {
		t.Fatalf("Failed to parse sentinel fixture: %v", err)
	}
	if len(sentinelFixture.Sentinels) == 0 {
		t.Errorf("Expected at least one script sentinel in negative fixture")
	}

	// 4. Verify negative cases: private fail-closed scenarios
	failClosedPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C34", "negative-private-fail-closed.json")
	failClosedData, err := os.ReadFile(failClosedPath)
	if err != nil {
		t.Fatalf("Failed to read fail-closed fixture: %v", err)
	}
	var failClosedFixture struct {
		Scenarios []struct {
			Scenario       string `json:"scenario"`
			ExpectedStatus int    `json:"expected_status"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(failClosedData, &failClosedFixture); err != nil {
		t.Fatalf("Failed to parse fail-closed fixture: %v", err)
	}
	if len(failClosedFixture.Scenarios) < 4 {
		t.Errorf("Expected >= 4 fail-closed scenarios, got %d", len(failClosedFixture.Scenarios))
	}
}
