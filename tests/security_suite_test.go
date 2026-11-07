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

	"github.com/parsa-emami/policyhelix/internal/gateway"
)

type c27ManifestEntry struct {
	FixtureID string `json:"fixture_id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Type      string `json:"type"`
	License   string `json:"license"`
}

type c27Manifest struct {
	SchemaVersion string             `json:"schema_version"`
	CommitID      string             `json:"commit_id"`
	Description   string             `json:"description"`
	License       string             `json:"license"`
	Fixtures      []c27ManifestEntry `json:"fixtures"`
}

func TestC27_ManifestIntegrityAndFixtureEvaluation(t *testing.T) {
	manifestPath := filepath.Join("fixtures", "policyhelix", "C27", "manifest.json")
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C27 manifest: %v", err)
	}

	var manifest c27Manifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C27 manifest: %v", err)
	}

	if manifest.CommitID != "C27" || manifest.License != "Apache-2.0" {
		t.Fatalf("expected commit_id C27 and Apache-2.0, got commit_id=%q license=%q", manifest.CommitID, manifest.License)
	}
	if len(manifest.Fixtures) < 10 {
		t.Fatalf("expected at least 10 fixtures in C27 manifest, got %d", len(manifest.Fixtures))
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

		var fx gateway.SecurityBoundaryFixture
		if err := json.Unmarshal(rawBytes, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", entry.FixtureID, err)
		}

		rep, evalErr := gateway.EvaluateSecurityBoundaryFixture(context.Background(), t.TempDir(), fx)
		if evalErr != nil {
			t.Fatalf("fixture %s (%s) failed verification: %v (report=%+v)", entry.FixtureID, fx.Vector, evalErr, rep)
		}
		if !rep.Passed {
			t.Fatalf("fixture %s (%s) passed=false", entry.FixtureID, fx.Vector)
		}
	}
}

func TestC27_IdentityAndIDOROwnerScopeIsolation(t *testing.T) {
	cases := []struct {
		file                string
		expectedAllow       bool
		expectedSideEffects bool
		expectedStatus      int
		expectedErrorCode   string
		expectedStorageCode string
	}{
		{
			file:                "positive-authorized-owner-scope-access.json",
			expectedAllow:       true,
			expectedSideEffects: true,
			expectedStatus:      http.StatusOK,
			expectedErrorCode:   "",
			expectedStorageCode: "",
		},
		{
			file:                "negative-missing-identity-denied.json",
			expectedAllow:       false,
			expectedSideEffects: false,
			expectedStatus:      http.StatusForbidden,
			expectedErrorCode:   "PRIVATE_RESOURCE_FAIL_CLOSED",
			expectedStorageCode: "UNAUTHENTICATED_IDENTITY",
		},
		{
			file:                "negative-expired-replayed-identity-denied.json",
			expectedAllow:       false,
			expectedSideEffects: false,
			expectedStatus:      http.StatusForbidden,
			expectedErrorCode:   "REPLAYED_IDENTITY_DENIED",
			expectedStorageCode: "EXPIRED_OR_REVOKED_IDENTITY",
		},
		{
			file:                "negative-idor-unrelated-owner-scope.json",
			expectedAllow:       false,
			expectedSideEffects: false,
			expectedStatus:      http.StatusForbidden,
			expectedErrorCode:   "UNRELATED_OWNER_SCOPE",
			expectedStorageCode: "OWNER_SCOPE_VIOLATION",
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			fxPath := filepath.Join("fixtures", "policyhelix", "C27", tc.file)
			rawBytes, err := os.ReadFile(fxPath)
			if err != nil {
				t.Fatalf("read %s: %v", fxPath, err)
			}

			var fx gateway.SecurityBoundaryFixture
			if err := json.Unmarshal(rawBytes, &fx); err != nil {
				t.Fatalf("unmarshal %s: %v", fxPath, err)
			}

			rep, err := gateway.EvaluateSecurityBoundaryFixture(context.Background(), t.TempDir(), fx)
			if err != nil {
				t.Fatalf("EvaluateSecurityBoundaryFixture(%s) error: %v", tc.file, err)
			}
			if !rep.Passed {
				t.Fatalf("Passed: got false, want true")
			}
			if rep.Allow != tc.expectedAllow {
				t.Fatalf("Allow: got %v, want %v", rep.Allow, tc.expectedAllow)
			}
			if rep.SideEffectsExecuted != tc.expectedSideEffects {
				t.Fatalf("SideEffectsExecuted: got %v, want %v", rep.SideEffectsExecuted, tc.expectedSideEffects)
			}
			if rep.StatusCode != tc.expectedStatus {
				t.Fatalf("StatusCode: got %d, want %d", rep.StatusCode, tc.expectedStatus)
			}
			if rep.ErrorCode != tc.expectedErrorCode {
				t.Fatalf("ErrorCode: got %q, want %q", rep.ErrorCode, tc.expectedErrorCode)
			}
			if rep.StorageErrorCode != tc.expectedStorageCode {
				t.Fatalf("StorageErrorCode: got %q, want %q", rep.StorageErrorCode, tc.expectedStorageCode)
			}
			if !tc.expectedSideEffects && rep.RecordsAfterAttempt != rep.RecordsBeforeAttempt {
				t.Fatalf("expected zero storage mutations on rejected request, got %d -> %d", rep.RecordsBeforeAttempt, rep.RecordsAfterAttempt)
			}
		})
	}
}

func TestC27_ForgedHeaderWidenedPermissionIdPOutageAndImportAbuse(t *testing.T) {
	cases := []struct {
		file                string
		expectedStatus      int
		expectedErrorCode   string
		expectedStorageCode string
		expectedImportRej   bool
	}{
		{
			file:                "negative-forged-header-privilege-escalation.json",
			expectedStatus:      http.StatusForbidden,
			expectedErrorCode:   "FORGED_HEADER_REJECTED",
			expectedStorageCode: "FORGED_HEADER_REJECTED",
		},
		{
			file:              "negative-widened-path-traversal-denied.json",
			expectedStatus:    http.StatusForbidden,
			expectedErrorCode: "WIDENED_PERMISSION_DENIED",
		},
		{
			file:              "negative-widened-provider-upstream-denied.json",
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "UPSTREAM_NOT_ALLOWLISTED",
		},
		{
			file:                "negative-idp-unavailable-sensitive-deny.json",
			expectedStatus:      http.StatusForbidden,
			expectedErrorCode:   "PROVIDER_UNAVAILABLE",
			expectedStorageCode: "PROVIDER_UNAVAILABLE",
		},
		{
			file:              "negative-xss-import-prototype-pollution-rejected.json",
			expectedStatus:    http.StatusUnprocessableEntity,
			expectedErrorCode: "UNSAFE_IMPORT_PAYLOAD_REJECTED",
			expectedImportRej: true,
		},
		{
			file:                "negative-private-resource-fail-closed.json",
			expectedStatus:      http.StatusForbidden,
			expectedErrorCode:   "WIDENED_PERMISSION_DENIED",
			expectedStorageCode: "PRIVATE_RESOURCE_FAIL_CLOSED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			fxPath := filepath.Join("fixtures", "policyhelix", "C27", tc.file)
			rawBytes, err := os.ReadFile(fxPath)
			if err != nil {
				t.Fatalf("read %s: %v", fxPath, err)
			}

			var fx gateway.SecurityBoundaryFixture
			if err := json.Unmarshal(rawBytes, &fx); err != nil {
				t.Fatalf("unmarshal %s: %v", fxPath, err)
			}

			rep, err := gateway.EvaluateSecurityBoundaryFixture(context.Background(), t.TempDir(), fx)
			if err != nil {
				t.Fatalf("EvaluateSecurityBoundaryFixture(%s) error: %v", tc.file, err)
			}
			if !rep.Passed || rep.Allow || rep.ForwardedToUpstream || rep.SideEffectsExecuted {
				t.Fatalf("expected strict fail-closed rejection for %s, got %+v", tc.file, rep)
			}
			if rep.StatusCode != tc.expectedStatus {
				t.Fatalf("StatusCode: got %d, want %d", rep.StatusCode, tc.expectedStatus)
			}
			if rep.ErrorCode != tc.expectedErrorCode {
				t.Fatalf("ErrorCode: got %q, want %q", rep.ErrorCode, tc.expectedErrorCode)
			}
			if tc.expectedStorageCode != "" && rep.StorageErrorCode != tc.expectedStorageCode {
				t.Fatalf("StorageErrorCode: got %q, want %q", rep.StorageErrorCode, tc.expectedStorageCode)
			}
			if rep.ImportRejected != tc.expectedImportRej {
				t.Fatalf("ImportRejected: got %v, want %v", rep.ImportRejected, tc.expectedImportRej)
			}
			if !rep.XSSInert {
				t.Fatalf("expected XSSInert=true for %s", tc.file)
			}
		})
	}
}

func TestC27_CLIAndHTTPSecurityVerify(t *testing.T) {
	fxPath := filepath.Join("fixtures", "policyhelix", "C27", "negative-idor-unrelated-owner-scope.json")

	// 1. Test CLI -verify-security flag
	cmd := exec.Command("go", "run", "../cmd/policyhelix", "-verify-security", fxPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI -verify-security failed: %v\nOutput: %s", err, string(out))
	}

	var cliRep gateway.SecurityBoundaryReport
	if err := json.Unmarshal(out, &cliRep); err != nil {
		t.Fatalf("failed to parse CLI output JSON: %v\nRaw: %s", err, string(out))
	}
	if !cliRep.Passed || cliRep.ErrorCode != "UNRELATED_OWNER_SCOPE" || cliRep.StorageErrorCode != "OWNER_SCOPE_VIOLATION" {
		t.Fatalf("unexpected CLI report: %+v", cliRep)
	}

	// 2. Test HTTP handler parity
	rawFx, err := os.ReadFile(fxPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/security/verify", func(w http.ResponseWriter, r *http.Request) {
		var fx gateway.SecurityBoundaryFixture
		if err := json.NewDecoder(r.Body).Decode(&fx); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rep, evalErr := gateway.EvaluateSecurityBoundaryFixture(r.Context(), t.TempDir(), fx)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if evalErr != nil || !rep.Passed {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(rep)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/verify", bytes.NewReader(rawFx))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for verified C27 fixture, got %d (%s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var httpRep gateway.SecurityBoundaryReport
	if err := json.Unmarshal(rec.Body.Bytes(), &httpRep); err != nil {
		t.Fatalf("unmarshal HTTP response: %v", err)
	}
	if !httpRep.Passed || httpRep.ErrorCode != "UNRELATED_OWNER_SCOPE" || httpRep.SideEffectsExecuted {
		t.Fatalf("unexpected HTTP report: %+v", httpRep)
	}
}
