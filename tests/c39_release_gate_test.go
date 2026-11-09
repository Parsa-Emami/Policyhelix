package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/storage"
)

type c39Manifest struct {
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

type releaseGatesDoc struct {
	Project              string   `json:"project"`
	CoreReady            bool     `json:"core_ready"`
	UsableAt             string   `json:"usable_at"`
	OssV1At              string   `json:"oss_v1_at"`
	ReleasePrerequisites []string `json:"release_prerequisites"`
}

type v1GateDoc struct {
	SchemaVersion int    `json:"schema_version"`
	CommitID      string `json:"commit_id"`
	Requirement   string `json:"requirement"`
	Project       string `json:"project"`
	Passed        bool   `json:"passed"`
	PlanningTmpl  bool   `json:"planning_template"`
	CoreReady     bool   `json:"core_ready"`
	ReleaseGates  struct {
		CoreReady             bool     `json:"core_ready"`
		UsableAt              string   `json:"usable_at"`
		OssV1At               string   `json:"oss_v1_at"`
		LocalUsableVerified   bool     `json:"local_usable_verified"`
		CloneToValueVerified  bool     `json:"clone_to_value_verified"`
		SignedPackagingVerif  bool     `json:"signed_packaging_verified"`
		ServicePolicyVerif    bool     `json:"service_policy_verified"`
		PrerequisitesVerified []string `json:"prerequisites_verified"`
	} `json:"release_gates"`
	CloneToValue struct {
		ReferenceWorkflowEvidence string `json:"reference_workflow_evidence"`
		OnboardingEvidence        string `json:"onboarding_evidence"`
		Status                    string `json:"status"`
	} `json:"clone_to_value"`
	PackagingAndIntegrity struct {
		ReleasePackagingEvidence string `json:"release_packaging_evidence"`
		Status                   string `json:"status"`
	} `json:"packaging_and_integrity"`
	ServicePolicyAndMaintenance struct {
		ServicePolicyDoc string `json:"service_policy_document"`
		MaintenanceDoc   string `json:"maintenance_runbook"`
		Status           string `json:"status"`
	} `json:"service_policy_and_maintenance"`
	LicensingGovernance struct {
		ProjectLicense string `json:"project_license"`
		Status         string `json:"status"`
	} `json:"licensing_governance"`
}

// TestC39FixturesManifest validates that all C39 synthetic positive and negative
// fixtures exist, match pinned SHA-256 digests in manifest.json, and enforce Apache-2.0 licensing.
func TestC39FixturesManifest(t *testing.T) {
	manifestPath := filepath.Join("..", "tests", "fixtures", "policyhelix", "C39", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("Failed to read C39 manifest: %v", err)
	}

	var m c39Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Failed to parse C39 manifest: %v", err)
	}

	if m.CommitID != "C39" {
		t.Errorf("Expected commit_id C39, got %s", m.CommitID)
	}
	if m.Requirement != "N39" {
		t.Errorf("Expected requirement N39, got %s", m.Requirement)
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

// TestC39ReleaseGateVerification validates plans/release-gates.json and docs/evidence/v1-gate.json.
func TestC39ReleaseGateVerification(t *testing.T) {
	// 1. Validate plans/release-gates.json
	gatesPath := filepath.Join("..", "plans", "release-gates.json")
	gatesBytes, err := os.ReadFile(gatesPath)
	if err != nil {
		t.Fatalf("Failed to read release-gates.json: %v", err)
	}
	var gates releaseGatesDoc
	if err := json.Unmarshal(gatesBytes, &gates); err != nil {
		t.Fatalf("Failed to parse release-gates.json: %v", err)
	}
	if !gates.CoreReady {
		t.Errorf("Expected core_ready: true in plans/release-gates.json")
	}
	if gates.UsableAt != "C30" || gates.OssV1At != "C40" {
		t.Errorf("Unexpected gates milestones: usable_at=%s, oss_v1_at=%s", gates.UsableAt, gates.OssV1At)
	}
	if len(gates.ReleasePrerequisites) != 38 {
		t.Errorf("Expected 38 release prerequisites (C01-C38), got %d", len(gates.ReleasePrerequisites))
	}

	// 2. Validate docs/evidence/v1-gate.json
	v1GatePath := filepath.Join("..", "docs", "evidence", "v1-gate.json")
	v1Bytes, err := os.ReadFile(v1GatePath)
	if err != nil {
		t.Fatalf("Failed to read v1-gate.json: %v", err)
	}
	var v1 v1GateDoc
	if err := json.Unmarshal(v1Bytes, &v1); err != nil {
		t.Fatalf("Failed to parse v1-gate.json: %v", err)
	}

	if v1.CommitID != "C39" {
		t.Errorf("Expected commit_id C39 in v1-gate.json, got %s", v1.CommitID)
	}
	if v1.Requirement != "N39" {
		t.Errorf("Expected requirement N39 in v1-gate.json, got %s", v1.Requirement)
	}
	if !v1.Passed {
		t.Errorf("Expected passed: true in v1-gate.json")
	}
	if v1.PlanningTmpl {
		t.Errorf("planning_template must be false in v1-gate.json")
	}
	if !v1.CoreReady {
		t.Errorf("Expected core_ready: true in v1-gate.json")
	}
	if !v1.ReleaseGates.CoreReady {
		t.Errorf("Expected release_gates.core_ready: true in v1-gate.json")
	}
	if len(v1.ReleaseGates.PrerequisitesVerified) != 38 {
		t.Errorf("Expected 38 prerequisites verified in v1-gate.json, got %d", len(v1.ReleaseGates.PrerequisitesVerified))
	}
	if v1.CloneToValue.Status != "verified" {
		t.Errorf("Expected clone_to_value status verified, got %s", v1.CloneToValue.Status)
	}
	if v1.PackagingAndIntegrity.Status != "verified" {
		t.Errorf("Expected packaging_and_integrity status verified, got %s", v1.PackagingAndIntegrity.Status)
	}
	if v1.ServicePolicyAndMaintenance.Status != "verified" {
		t.Errorf("Expected service_policy_and_maintenance status verified, got %s", v1.ServicePolicyAndMaintenance.Status)
	}
	if v1.LicensingGovernance.Status != "verified" {
		t.Errorf("Expected licensing_governance status verified, got %s", v1.LicensingGovernance.Status)
	}
}

// TestC39ReleaseGateCommand verifies that running `node scripts/roadmap.mjs release-check`
// succeeds and exits with code 0 on the verified repo.
func TestC39ReleaseGateCommand(t *testing.T) {
	cmd := exec.Command("node", "scripts/roadmap.mjs", "release-check")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("release-check command failed: %v\nOutput: %s", err, string(output))
	}
	outStr := string(output)
	if !strings.Contains(outStr, "RELEASE GATE PASSED: C01-C38 verified, core readiness certified") {
		t.Errorf("Unexpected release-check output: %s", outStr)
	}
}

// TestC39ReleaseGateFailsClosedOnMissingOrTamperedEvidence verifies Requirement N39:
// Release check must fail closed (exit code 2) when prerequisites are missing,
// planning templates are detected, evidence is missing or corrupted, or required release assets are absent.
func TestC39ReleaseGateFailsClosedOnMissingOrTamperedEvidence(t *testing.T) {
	script := `
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs';
import { resolve } from 'node:path';

function runCheck() {
  try {
    execSync('node scripts/roadmap.mjs release-check', { stdio: 'pipe' });
    return 0;
  } catch (err) {
    return err.status;
  }
}

// Case 1: core_ready: false in plans/release-gates.json -> must exit 2
const gatesPath = resolve('plans/release-gates.json');
const origGates = readFileSync(gatesPath, 'utf8');
try {
  const g = JSON.parse(origGates);
  g.core_ready = false;
  writeFileSync(gatesPath, JSON.stringify(g, null, 2));
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when core_ready=false, got: ' + exitCode);
} finally {
  writeFileSync(gatesPath, origGates);
}

// Case 2: Missing prerequisite task in progress.json -> must exit 2
const progressPath = resolve('plans/progress.json');
const origProgress = readFileSync(progressPath, 'utf8');
try {
  const p = JSON.parse(origProgress);
  p.commits[37].status = 'planned'; // mark C38 unverified
  writeFileSync(progressPath, JSON.stringify(p, null, 2));
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when prerequisite missing, got: ' + exitCode);
} finally {
  writeFileSync(progressPath, origProgress);
}

// Case 3: planning_template: true in v1-gate.json -> must exit 2
const v1GatePath = resolve('docs/evidence/v1-gate.json');
const origV1Gate = readFileSync(v1GatePath, 'utf8');
try {
  const v = JSON.parse(origV1Gate);
  v.planning_template = true;
  writeFileSync(v1GatePath, JSON.stringify(v, null, 2));
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when planning_template=true, got: ' + exitCode);
} finally {
  writeFileSync(v1GatePath, origV1Gate);
}

// Case 4: passed: false in v1-gate.json -> must exit 2
try {
  const v = JSON.parse(origV1Gate);
  v.passed = false;
  writeFileSync(v1GatePath, JSON.stringify(v, null, 2));
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when passed=false, got: ' + exitCode);
} finally {
  writeFileSync(v1GatePath, origV1Gate);
}

// Case 5: Missing v1-gate.json entirely -> must exit 2
try {
  renameSync(v1GatePath, v1GatePath + '.bak');
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when v1-gate.json is missing, got: ' + exitCode);
} finally {
  renameSync(v1GatePath + '.bak', v1GatePath);
}

// Case 6: Malformed JSON in v1-gate.json -> must exit 2
try {
  writeFileSync(v1GatePath, '{"broken json');
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when v1-gate.json is malformed, got: ' + exitCode);
} finally {
  writeFileSync(v1GatePath, origV1Gate);
}

// Case 7: commit_id mismatch in v1-gate.json -> must exit 2
try {
  const v = JSON.parse(origV1Gate);
  v.commit_id = 'C38';
  writeFileSync(v1GatePath, JSON.stringify(v, null, 2));
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 on commit_id mismatch, got: ' + exitCode);
} finally {
  writeFileSync(v1GatePath, origV1Gate);
}

// Case 8: unverified clone_to_value status in v1-gate.json -> must exit 2
try {
  const v = JSON.parse(origV1Gate);
  v.clone_to_value.status = 'unverified';
  writeFileSync(v1GatePath, JSON.stringify(v, null, 2));
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 on unverified clone_to_value, got: ' + exitCode);
} finally {
  writeFileSync(v1GatePath, origV1Gate);
}

// Case 9: Missing required release asset (e.g. docs/release/SERVICE_POLICY.md) -> must exit 2
const servicePolicyPath = resolve('docs/release/SERVICE_POLICY.md');
try {
  renameSync(servicePolicyPath, servicePolicyPath + '.bak');
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when required release asset is missing, got: ' + exitCode);
} finally {
  renameSync(servicePolicyPath + '.bak', servicePolicyPath);
}

// Case 10: Milestone evidence with planning_template: true -> must exit 2
const c30Path = resolve('docs/evidence/C30.json');
const origC30 = readFileSync(c30Path, 'utf8');
try {
  const m = JSON.parse(origC30);
  m.planning_template = true;
  writeFileSync(c30Path, JSON.stringify(m, null, 2));
  const exitCode = runCheck();
  if (exitCode !== 2) throw new Error('Expected exit 2 when milestone planning_template=true, got: ' + exitCode);
} finally {
  writeFileSync(c30Path, origC30);
}

console.log('ALL_FAIL_CLOSED_CASES_PASSED');
`
	cmd := exec.Command("node", "--input-type=module", "-e", script)
	cmd.Dir = ".."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Fail-closed negative checks failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "ALL_FAIL_CLOSED_CASES_PASSED") {
		t.Errorf("Unexpected output: %s", string(out))
	}
}

// TestC39WriterCrashAtStagedByteBoundary verifies Requirement N39:
// Killing the writer at the staged-byte/manifest boundary is cleaned up on restart,
// exposing only the complete prior valid state.
func TestC39WriterCrashAtStagedByteBoundary(t *testing.T) {
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
		OperationID:    "op-c39-init",
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

// TestC39OperationReplayAndLostAck verifies Requirement N39:
// Replaying an operation after a lost ACK returns the cached receipt (idempotent, 0 duplicate side effects),
// and replaying with conflicting payload fails closed with ErrOperationConflict.
func TestC39OperationReplayAndLostAck(t *testing.T) {
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
		OperationID:    "op-c39-idempotent-test",
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

// TestC39DiskAndQuotaExhaustion verifies Requirement N39:
// Exhausting disk space or exceeding payload quota fails closed:
// no duplicate side effect, no partial success, and no unlimited retry.
func TestC39DiskAndQuotaExhaustion(t *testing.T) {
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

	// 1. Quota exhaustion: payload > MaxPayloadBytes (65536) must fail closed with ErrPayloadTooLarge
	oversizedPayload := strings.Repeat("A", storage.MaxPayloadBytes+10)
	oversizedReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c39-quota-oversized",
		RecordID:       "service:analytics:oversized-record",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity:       identity,
		Payload:        json.RawMessage(`"` + oversizedPayload + `"`),
	}
	_, qErr := ad.WriteRecord(ctx, oversizedReq)
	if qErr == nil {
		t.Fatalf("Expected ErrPayloadTooLarge on oversized payload, got nil")
	}
	if qErr.Code != storage.ErrPayloadTooLarge {
		t.Fatalf("Expected %s, got %v", storage.ErrPayloadTooLarge, qErr)
	}

	// Verify no partial record created
	_, _, readErr := ad.ReadRecord("service:analytics:oversized-record")
	if readErr == nil {
		t.Fatalf("Expected missing record after quota failure, but record was found")
	}

	// 2. Disk exhaustion: simulate ENOSPC via fault injection
	ad.Faults.SimulateDiskFull = true
	diskFullReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c39-disk-full",
		RecordID:       "service:analytics:disk-full-record",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity:       identity,
		Payload:        json.RawMessage(`{"status":"fail-on-enospc"}`),
	}
	_, dErr := ad.WriteRecord(ctx, diskFullReq)
	if dErr == nil {
		t.Fatalf("Expected ErrDiskFullOrWriteFailed when disk is full, got nil")
	}
	if dErr.Code != storage.ErrDiskFullOrWriteFailed {
		t.Fatalf("Expected %s, got %v", storage.ErrDiskFullOrWriteFailed, dErr)
	}

	// Verify no partial record created
	_, _, readErr = ad.ReadRecord("service:analytics:disk-full-record")
	if readErr == nil {
		t.Fatalf("Expected missing record after disk full failure, but record was found")
	}

	// 3. Recovery: once disk space is restored (fault cleared), retry succeeds cleanly
	ad.Faults.SimulateDiskFull = false
	receipt, rErr := ad.WriteRecord(ctx, diskFullReq)
	if rErr != nil {
		t.Fatalf("Expected successful write after disk recovery, got: %v", rErr)
	}
	if receipt.Revision != 1 {
		t.Errorf("Expected revision 1 after recovery, got %d", receipt.Revision)
	}

	// Read record to verify integrity
	data, entry, rErr2 := ad.ReadRecord("service:analytics:disk-full-record")
	if rErr2 != nil {
		t.Fatalf("Failed to read record after disk recovery: %v", rErr2)
	}
	if entry.Revision != 1 || !strings.Contains(string(data), "fail-on-enospc") {
		t.Fatalf("Record content mismatch after disk recovery: %s", string(data))
	}
}

// TestC39PrivateResourcesFailClosed verifies Requirement N39:
// Unauthenticated writes to private resources fail closed with ErrUnauthenticatedIdentity.
func TestC39PrivateResourcesFailClosed(t *testing.T) {
	tempDir := t.TempDir()
	ad, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to open storage adapter: %v", err)
	}
	defer ad.Close()

	ctx := context.Background()
	unauthReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c39-unauth",
		RecordID:       "service:analytics:private-record",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity: storage.CallerIdentity{
			SubjectID:                "",
			Roles:                    []string{},
			Authenticated:            false,
			UntrustedHeadersStripped: true,
			ProviderState:            "ready",
		},
		Payload: json.RawMessage(`{"secret":"data"}`),
	}

	_, sErr := ad.WriteRecord(ctx, unauthReq)
	if sErr == nil {
		t.Fatalf("Expected unauthenticated write to private resource to fail closed, got nil")
	}
	if sErr.Code != storage.ErrUnauthenticatedIdentity {
		t.Fatalf("Expected %s, got: %v", storage.ErrUnauthenticatedIdentity, sErr)
	}
}

// TestC39ReleaseGateWorkflow validates that .github/workflows/release-gate.yml exists,
// contains all required steps, and all actions are pinned to 40-character SHAs.
func TestC39ReleaseGateWorkflow(t *testing.T) {
	wfPath := filepath.Join("..", ".github", "workflows", "release-gate.yml")
	content, err := os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("Failed to read release-gate.yml: %v", err)
	}
	text := string(content)

	// Check required steps
	requiredPhrases := []string{
		"Clean Checkout",
		"Setup Go Toolchain",
		"Setup Node Toolchain",
		"npm run validate:plan",
		"python3 scripts/validate_repo.py",
		"npm run build",
		"npm run build:engine",
		"npm run release:check",
		"go test -v -race ./...",
		"npm test",
		"docs/evidence/v1-gate.json",
	}
	for _, phrase := range requiredPhrases {
		if !strings.Contains(text, phrase) {
			t.Errorf("release-gate.yml missing required step/phrase: %q", phrase)
		}
	}

	// Verify all `uses:` actions are pinned to 40-character commit SHAs
	usesRegex := regexp.MustCompile(`uses:\s*([^\s]+)`)
	matches := usesRegex.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		t.Fatalf("No 'uses:' actions found in release-gate.yml")
	}

	shaRegex := regexp.MustCompile(`^[a-zA-Z0-9/_.-]+@[0-9a-f]{40}$`)
	for _, m := range matches {
		action := m[1]
		if !shaRegex.MatchString(action) {
			t.Errorf("Action %q is not pinned to a 40-character commit SHA", action)
		}
	}
}
