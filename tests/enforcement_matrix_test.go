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
	"testing"

	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/gateway"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

type c26ManifestEntry struct {
	FixtureID string `json:"fixture_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Type      string `json:"type"`
	License   string `json:"license"`
}

type c26Manifest struct {
	SchemaVersion string             `json:"schema_version"`
	CommitID      string             `json:"commit_id"`
	Description   string             `json:"description"`
	License       string             `json:"license"`
	Fixtures      []c26ManifestEntry `json:"fixtures"`
}

func TestC26_ManifestIntegrityAndFixtureEvaluation(t *testing.T) {
	manifestPath := filepath.Join("fixtures", "policyhelix", "C26", "manifest.json")
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C26 manifest: %v", err)
	}

	var manifest c26Manifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C26 manifest: %v", err)
	}

	if manifest.CommitID != "C26" || manifest.License != "Apache-2.0" {
		t.Fatalf("expected commit_id C26 and Apache-2.0, got commit_id=%q license=%q", manifest.CommitID, manifest.License)
	}
	if len(manifest.Fixtures) < 11 {
		t.Fatalf("expected at least 11 fixtures in C26 manifest, got %d", len(manifest.Fixtures))
	}

	rootDir := filepath.Clean("..")
	for _, entry := range manifest.Fixtures {
		if entry.License != "Apache-2.0" {
			t.Fatalf("fixture %s must have Apache-2.0 license, got %q", entry.FixtureID, entry.License)
		}

		fullPath := filepath.Join(rootDir, filepath.FromSlash(entry.Path))
		rawBytes, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("failed to read fixture %s at %s: %v", entry.FixtureID, fullPath, err)
		}

		sum := sha256.Sum256(rawBytes)
		expectedDigest := hex.EncodeToString(sum[:])
		if entry.SHA256 != expectedDigest {
			t.Fatalf("digest mismatch for %s: manifest=%s actual=%s", entry.FixtureID, entry.SHA256, expectedDigest)
		}

		var fx gateway.EnforcementMatrixFixture
		if err := json.Unmarshal(rawBytes, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", entry.FixtureID, err)
		}

		rep, evalErr := gateway.EvaluateEnforcementFixture(context.Background(), t.TempDir(), fx)
		if evalErr != nil {
			t.Fatalf("fixture %s (%s) failed verification: %v (report=%+v)", entry.FixtureID, fx.Vector, evalErr, rep)
		}
		if !rep.Passed {
			t.Fatalf("fixture %s (%s) passed=false", entry.FixtureID, fx.Vector)
		}
	}
}

func TestC26_DirectOriginForgedHeaderRevokedSessionExpiredBundleOutage(t *testing.T) {
	cases := []struct {
		file               string
		expectedAllow      bool
		expectedForwarded  bool
		expectedStatus     int
		expectedError      string
		expectedVector     string
		expectedRetention  bool
		expectedRevision   int64
		expectedOutageDisp string
	}{
		{
			file:              "positive-authenticated-gateway-enforcement.json",
			expectedAllow:     true,
			expectedForwarded: true,
			expectedStatus:    http.StatusOK,
			expectedError:     "",
			expectedVector:    "positive_authenticated_gateway",
			expectedRetention: true,
			expectedRevision:  2,
		},
		{
			file:              "negative-direct-origin-bypass.json",
			expectedAllow:     false,
			expectedForwarded: false,
			expectedStatus:    http.StatusForbidden,
			expectedError:     "DIRECT_ORIGIN_BYPASS_DENIED",
			expectedVector:    "direct_origin_bypass",
			expectedRetention: true,
			expectedRevision:  2,
		},
		{
			file:              "negative-forged-identity-header.json",
			expectedAllow:     false,
			expectedForwarded: false,
			expectedStatus:    http.StatusForbidden,
			expectedError:     "FORGED_HEADER_REJECTED",
			expectedVector:    "forged_header",
			expectedRetention: true,
			expectedRevision:  2,
		},
		{
			file:              "negative-revoked-session-denied.json",
			expectedAllow:     false,
			expectedForwarded: false,
			expectedStatus:    http.StatusForbidden,
			expectedError:     "REVOKED_SESSION_DENIED",
			expectedVector:    "revoked_session",
			expectedRetention: true,
			expectedRevision:  2,
		},
		{
			file:              "negative-expired-bundle-denied.json",
			expectedAllow:     false,
			expectedForwarded: false,
			expectedStatus:    http.StatusForbidden,
			expectedError:     "EXPIRED_POLICY_BUNDLE",
			expectedVector:    "expired_bundle",
			expectedRetention: false,
			expectedRevision:  0,
		},
		{
			file:               "negative-policy-outage-private-deny.json",
			expectedAllow:      false,
			expectedForwarded:  false,
			expectedStatus:     http.StatusServiceUnavailable,
			expectedError:      "DECISION_LOSS_SENSITIVE_DENY",
			expectedVector:     "policy_outage_private",
			expectedRetention:  true,
			expectedRevision:   2,
			expectedOutageDisp: "FAIL_CLOSED_DENY",
		},
		{
			file:               "positive-public-route-outage-bypass.json",
			expectedAllow:      true,
			expectedForwarded:  true,
			expectedStatus:     http.StatusOK,
			expectedError:      "",
			expectedVector:     "positive_public_outage_bypass",
			expectedRetention:  true,
			expectedRevision:   2,
			expectedOutageDisp: "INTENTIONAL_PUBLIC_BYPASS",
		},
		{
			file:              "negative-private-resource-fail-closed.json",
			expectedAllow:     false,
			expectedForwarded: false,
			expectedStatus:    http.StatusForbidden,
			expectedError:     "PRIVATE_RESOURCE_FAIL_CLOSED",
			expectedVector:    "private_fail_closed",
			expectedRetention: true,
			expectedRevision:  2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			fxPath := filepath.Join("fixtures", "policyhelix", "C26", tc.file)
			rawBytes, err := os.ReadFile(fxPath)
			if err != nil {
				t.Fatalf("read %s: %v", fxPath, err)
			}

			var fx gateway.EnforcementMatrixFixture
			if err := json.Unmarshal(rawBytes, &fx); err != nil {
				t.Fatalf("unmarshal %s: %v", fxPath, err)
			}

			rep, err := gateway.EvaluateEnforcementFixture(context.Background(), t.TempDir(), fx)
			if err != nil {
				t.Fatalf("EvaluateEnforcementFixture(%s) error: %v", tc.file, err)
			}
			if !rep.Passed {
				t.Fatalf("Passed: got false, want true")
			}
			if rep.Allow != tc.expectedAllow {
				t.Fatalf("Allow: got %v, want %v", rep.Allow, tc.expectedAllow)
			}
			if rep.ForwardedToUpstream != tc.expectedForwarded {
				t.Fatalf("ForwardedToUpstream: got %v, want %v", rep.ForwardedToUpstream, tc.expectedForwarded)
			}
			if rep.StatusCode != tc.expectedStatus {
				t.Fatalf("StatusCode: got %d, want %d", rep.StatusCode, tc.expectedStatus)
			}
			if rep.ErrorCode != tc.expectedError {
				t.Fatalf("ErrorCode: got %q, want %q", rep.ErrorCode, tc.expectedError)
			}
			if rep.Vector != tc.expectedVector {
				t.Fatalf("Vector: got %q, want %q", rep.Vector, tc.expectedVector)
			}
			if rep.ActiveBundleActive != tc.expectedRetention {
				t.Fatalf("ActiveBundleActive: got %v, want %v", rep.ActiveBundleActive, tc.expectedRetention)
			}
			if rep.ActiveRevision != tc.expectedRevision {
				t.Fatalf("ActiveRevision: got %d, want %d", rep.ActiveRevision, tc.expectedRevision)
			}
			if tc.expectedOutageDisp != "" && rep.OutageDisposition != tc.expectedOutageDisp {
				t.Fatalf("OutageDisposition: got %q, want %q", rep.OutageDisposition, tc.expectedOutageDisp)
			}
		})
	}
}

func TestC26_OneModifiedByteMissingEvidenceUntrustedSignerAndStaleReplayRetainAuthority(t *testing.T) {
	// 1. Verify the 3 negative authority retention fixtures from C26
	authorityFixtures := []struct {
		file               string
		expectedCandError  string
		expectedRetainedID string
		expectedRevision   int64
	}{
		{
			file:               "negative-tampered-byte-rejected.json",
			expectedCandError:  "TAMPERED_BUNDLE_DIGEST",
			expectedRetainedID: "bundle-enf-rev2",
			expectedRevision:   2,
		},
		{
			file:               "negative-untrusted-signer-rejected.json",
			expectedCandError:  "UNTRUSTED_OR_MISSING_SIGNER",
			expectedRetainedID: "bundle-enf-rev2",
			expectedRevision:   2,
		},
		{
			file:               "negative-stale-replayed-revision-retained.json",
			expectedCandError:  "STALE_OR_REPLAYED_REVISION",
			expectedRetainedID: "bundle-enf-rev3",
			expectedRevision:   3,
		},
	}

	for _, tc := range authorityFixtures {
		t.Run(tc.file, func(t *testing.T) {
			fxPath := filepath.Join("fixtures", "policyhelix", "C26", tc.file)
			rawBytes, err := os.ReadFile(fxPath)
			if err != nil {
				t.Fatalf("read %s: %v", fxPath, err)
			}

			var fx gateway.EnforcementMatrixFixture
			if err := json.Unmarshal(rawBytes, &fx); err != nil {
				t.Fatalf("unmarshal %s: %v", fxPath, err)
			}

			rep, err := gateway.EvaluateEnforcementFixture(context.Background(), t.TempDir(), fx)
			if err != nil {
				t.Fatalf("EvaluateEnforcementFixture(%s) error: %v", tc.file, err)
			}
			if !rep.Passed {
				t.Fatalf("expected Passed=true for %s", tc.file)
			}
			if rep.CandidateBundleStatus != bundles.ActivationStatusRejected {
				t.Fatalf("expected CandidateBundleStatus=rejected for %s, got %q", tc.file, rep.CandidateBundleStatus)
			}
			if rep.CandidateErrorCode != tc.expectedCandError {
				t.Fatalf("CandidateErrorCode: got %q, want %q", rep.CandidateErrorCode, tc.expectedCandError)
			}
			if !rep.ActiveBundleActive {
				t.Fatalf("expected ActiveBundleActive=true for %s", tc.file)
			}
			if rep.ActiveBundleID != tc.expectedRetainedID {
				t.Fatalf("ActiveBundleID: got %q, want %q", rep.ActiveBundleID, tc.expectedRetainedID)
			}
			if rep.ActiveRevision != tc.expectedRevision {
				t.Fatalf("ActiveRevision: got %d, want %d", rep.ActiveRevision, tc.expectedRevision)
			}
		})
	}

	// 2. Verify missing signature evidence and durable restart authority preservation in SQLite
	dir := t.TempDir()
	ad1, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}

	keyV1 := c25TrustedKey(t, c25KeyV1ID, c25SeedV1Hex)
	validRev3 := c25BuildSignedBundle(t, "bundle-c26-durable-rev3", c25KeyV1ID, c25SeedV1Hex, 3)

	mgr1 := bundles.NewKeyRotationManagerFromAdapter(ad1, bundles.NewKeyring(keyV1))
	mgr1.Now = c12Clock()

	actRes := mgr1.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-c26-durable-rev3",
		Identity:    c12OperatorIdentity(),
		Bundle:      validRev3,
	}, c25EvalTime)
	if actRes.Status == bundles.ActivationStatusRejected {
		t.Fatalf("expected validRev3 activation to succeed: %+v", actRes)
	}

	// Attempt missing signature evidence on rev 4 -> must fail with UNTRUSTED_OR_MISSING_SIGNER and preserve rev 3
	missingSigRev4 := c25BuildSignedBundle(t, "bundle-c26-missing-sig-rev4", c25KeyV1ID, c25SeedV1Hex, 4)
	missingSigRev4.Signature = ""
	missingRes := mgr1.ActivateBundle(context.Background(), bundles.ActivationRequest{
		OperationID: "op-c26-missing-sig-rev4",
		Identity:    c12OperatorIdentity(),
		Bundle:      missingSigRev4,
	}, c25EvalTime)
	if missingRes.Status != bundles.ActivationStatusRejected || missingRes.ErrorCode != policy.ErrCodeUntrustedSigner {
		t.Fatalf("expected UNTRUSTED_OR_MISSING_SIGNER for missing signature evidence, got %+v", missingRes)
	}
	_ = ad1.Close()

	// Simulate restart from durable SQLite store and verify rev 3 remains active and highest_revision == 3
	ad2, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open 2: %v", err)
	}
	defer ad2.Close()

	mgr2 := bundles.NewKeyRotationManagerFromAdapter(ad2, bundles.NewKeyring(keyV1))
	mgr2.Now = c12Clock()
	restored := mgr2.Restore(context.Background())
	if !restored.Valid || !restored.Active || restored.ActiveBundleID != "bundle-c26-durable-rev3" || restored.HighestRevision != 3 {
		t.Fatalf("expected durable state to retain bundle-c26-durable-rev3 at revision 3 after rejected candidate and restart, got %+v", restored)
	}
}

func TestC26_CLIAndHTTPEnforcementVerify(t *testing.T) {
	fxPath := filepath.Join("fixtures", "policyhelix", "C26", "negative-direct-origin-bypass.json")

	// 1. Test CLI -verify-enforcement flag
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "-verify-enforcement", fxPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI -verify-enforcement failed: %v\nOutput: %s", err, string(out))
	}

	var cliRep gateway.EnforcementMatrixReport
	if err := json.Unmarshal(out, &cliRep); err != nil {
		t.Fatalf("failed to parse CLI output JSON: %v\nRaw: %s", err, string(out))
	}
	if !cliRep.Passed || cliRep.ErrorCode != "DIRECT_ORIGIN_BYPASS_DENIED" {
		t.Fatalf("unexpected CLI report: %+v", cliRep)
	}

	// 2. Test HTTP handler parity
	rawFx, err := os.ReadFile(fxPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/gateway/enforcement/verify", func(w http.ResponseWriter, r *http.Request) {
		var fx gateway.EnforcementMatrixFixture
		if err := json.NewDecoder(r.Body).Decode(&fx); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rep, evalErr := gateway.EvaluateEnforcementFixture(r.Context(), t.TempDir(), fx)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if evalErr != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(rep)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/enforcement/verify", bytes.NewReader(rawFx))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for verified fixture, got %d (%s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var httpRep gateway.EnforcementMatrixReport
	if err := json.Unmarshal(rec.Body.Bytes(), &httpRep); err != nil {
		t.Fatalf("unmarshal HTTP response: %v", err)
	}
	if !httpRep.Passed || httpRep.ErrorCode != "DIRECT_ORIGIN_BYPASS_DENIED" {
		t.Fatalf("unexpected HTTP report: %+v", httpRep)
	}
}
