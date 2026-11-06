package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/audit"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/rollout"
)

const (
	c23FixtureRelDir = "fixtures/policyhelix/C23"
)

func getC23FixtureDir() string {
	candidates := []string{
		c23FixtureRelDir,
		filepath.Join("tests", c23FixtureRelDir),
		filepath.Join("..", "tests", c23FixtureRelDir),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	// Default to creating/using the local one
	return c23FixtureRelDir
}

type c23FixtureEnvelope struct {
	SchemaVersion  string                    `json:"schema_version"`
	FixtureID      string                    `json:"fixture_id"`
	CommitID       string                    `json:"commit_id"`
	Description    string                    `json:"description"`
	License        string                    `json:"license"`
	TrustedIssuers []string                  `json:"trusted_issuers,omitempty"`
	TrustedSigners []string                  `json:"trusted_signers,omitempty"`
	Request        rollout.ShadowEvalRequest `json:"request"`
	Expected       struct {
		Allow           bool                   `json:"allow"`
		StatusCode      int                    `json:"status_code"`
		EnforcedAllow   bool                   `json:"enforced_allow"`
		CandidateAllow  bool                   `json:"candidate_allow"`
		Diverged        bool                   `json:"diverged"`
		DivergenceType  rollout.DivergenceType `json:"divergence_type"`
		ErrorCode       string                 `json:"error_code,omitempty"`
		SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
	} `json:"expected"`
}

func makeC23SignedBundle(bundleID string, rev int64, issuedAt, expiresAt string, pathPattern string, roles []string, class policy.ResourceClass, reasonCode, reasonMsg string) policy.LocalPolicyBundle {
	b := policy.LocalPolicyBundle{
		SchemaVersion:     "1",
		BundleID:          bundleID,
		Package:           "policyhelix.authz",
		Issuer:            "https://issuer.policyhelix.local",
		SignerKeyID:       "ed25519-primary-2026",
		Signature:         "ed25519:7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
		SignatureVerified: true,
		Revision:          rev,
		IssuedAt:          issuedAt,
		ExpiresAt:         expiresAt,
		RegoModule:        "package policyhelix.authz\ndefault allow = false\nallow { input.subject.authenticated == true }",
		Routes: []policy.RouteRule{
			{
				Pattern:              pathPattern,
				Action:               "read",
				Classification:       class,
				AllowUnauthenticated: false,
				RequiredRoles:        roles,
				Description:          fmt.Sprintf("Route rule for %s (rev %d)", pathPattern, rev),
			},
		},
		Rules: []policy.PolicyRule{
			{
				ID:            fmt.Sprintf("rule-%s-%d", strings.ReplaceAll(strings.Trim(pathPattern, "/"), "/", "-"), rev),
				Effect:        "allow",
				PathPattern:   pathPattern,
				Actions:       []string{"read"},
				Roles:         roles,
				ResourceClass: class,
				ReasonCode:    reasonCode,
				ReasonMessage: reasonMsg,
			},
		},
	}
	b.Digest = policy.ComputeCanonicalBundleDigest(b)
	return b
}

func generateC23FixturesIfMissing(t *testing.T) string {
	t.Helper()
	dir := getC23FixtureDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create C23 fixtures dir %s: %v", dir, err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	if _, err := os.Stat(manifestPath); err == nil {
		return dir // Already generated
	}

	issued := "2026-11-06T00:00:00Z"
	expires := "2026-11-07T00:00:00Z"

	// Bundle 1: Enforced allow operator (rev 10)
	bEnforcedAllowOperator := makeC23SignedBundle(
		"bundle-workloads-enf-v10", 10, issued, expires,
		"/api/v1/workloads/jobs", []string{"operator", "admin"}, policy.ResourceClassPrivate,
		"policy_allow_operator", "Operator allowed in enforced policy revision 10",
	)

	// Bundle 2: Candidate restrict to admin only (rev 11)
	bCandidateAdminOnly := makeC23SignedBundle(
		"bundle-workloads-cand-v11", 11, issued, expires,
		"/api/v1/workloads/jobs", []string{"admin"}, policy.ResourceClassRestricted,
		"policy_allow_admin_only", "Admin strictly allowed in candidate revision 11",
	)

	// Bundle 3: Enforced require admin only (rev 12)
	bEnforcedAdminOnly := makeC23SignedBundle(
		"bundle-workloads-enf-v12", 12, issued, expires,
		"/api/v1/workloads/jobs", []string{"admin"}, policy.ResourceClassRestricted,
		"policy_allow_admin_only", "Admin strictly allowed in enforced revision 12",
	)

	// Bundle 4: Candidate expand to operator and admin (rev 13)
	bCandidateAllowOperator := makeC23SignedBundle(
		"bundle-workloads-cand-v13", 13, issued, expires,
		"/api/v1/workloads/jobs", []string{"operator", "admin"}, policy.ResourceClassPrivate,
		"policy_allow_operator", "Operator allowed in candidate revision 13",
	)

	// Bundle 5: Candidate unchanged allow operator (rev 14)
	bCandidateUnchanged := makeC23SignedBundle(
		"bundle-workloads-cand-v14", 14, issued, expires,
		"/api/v1/workloads/jobs", []string{"operator", "admin"}, policy.ResourceClassPrivate,
		"policy_allow_operator", "Operator allowed in candidate revision 14",
	)

	// Bundle 6: Vault private bundle (rev 15)
	bVaultPrivate := makeC23SignedBundle(
		"bundle-vault-v15", 15, issued, expires,
		"/api/v1/secure/vault", []string{"admin"}, policy.ResourceClassPrivate,
		"policy_allow_vault_admin", "Vault access restricted to admin",
	)

	// Bundle 7: Candidate vault bundle claiming public bypass (rev 16)
	bVaultCandidate := makeC23SignedBundle(
		"bundle-vault-cand-v16", 16, issued, expires,
		"/api/v1/secure/vault", []string{"operator", "admin"}, policy.ResourceClassPrivate,
		"policy_allow_vault_candidate", "Candidate attempts vault permit",
	)

	fixtures := []struct {
		name     string
		envelope c23FixtureEnvelope
		fType    string
	}{
		{
			name: "positive-shadow-allow-to-deny.json",
			fType: "positive",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-shadow-allow-to-deny",
				CommitID:       "C23",
				Description:    "Enforced policy allows operator; candidate policy restricts to admin only. Enforced decision remains allow=true (invariant), candidate divergence allow_to_deny is recorded.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID:              "req-c23-shadow-01",
					Path:                   "/api/v1/workloads/jobs",
					Action:                 "read",
					ResourceID:             "job-worker-101",
					ResourceClassification: policy.ResourceClassPrivate,
					Subject: policy.SubjectIdentity{
						ID:            "usr-operator-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					Headers: map[string]string{
						"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Itb3BlcmF0b3ItMDEifQ.sigShadow01",
						"Cookie":        "policyhelix_session=shadowCookieToken01",
						"X-Request-Id":  "req-c23-shadow-01",
					},
					Context: map[string]interface{}{
						"downstream_token": "Bearer secretToken99",
						"client_ip":        "127.0.0.1",
					},
					DeadlineMS:      200,
					EvalTime:        "2026-11-06T12:00:00Z",
					EnforcedBundle:  &bEnforcedAllowOperator,
					CandidateBundle: &bCandidateAdminOnly,
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:          true,
					StatusCode:     200,
					EnforcedAllow:  true,
					CandidateAllow: false,
					Diverged:       true,
					DivergenceType: rollout.DivergenceAllowToDeny,
				},
			},
		},
		{
			name: "positive-shadow-deny-to-allow.json",
			fType: "positive",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-shadow-deny-to-allow",
				CommitID:       "C23",
				Description:    "Enforced policy requires admin; candidate policy permits operator. Authoritative result remains allow=false (enforced wins), candidate divergence deny_to_allow is recorded.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID:              "req-c23-shadow-02",
					Path:                   "/api/v1/workloads/jobs",
					Action:                 "read",
					ResourceID:             "job-worker-102",
					ResourceClassification: policy.ResourceClassRestricted,
					Subject: policy.SubjectIdentity{
						ID:            "usr-operator-02",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					Headers: map[string]string{
						"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Itb3BlcmF0b3ItMDIifQ.sigShadow02",
						"Cookie":        "policyhelix_session=shadowCookieToken02",
					},
					DeadlineMS:      200,
					EvalTime:        "2026-11-06T12:00:00Z",
					EnforcedBundle:  &bEnforcedAdminOnly,
					CandidateBundle: &bCandidateAllowOperator,
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:          false,
					StatusCode:     403,
					EnforcedAllow:  false,
					CandidateAllow: true,
					Diverged:       true,
					DivergenceType: rollout.DivergenceDenyToAllow,
				},
			},
		},
		{
			name: "positive-shadow-unchanged-allow.json",
			fType: "positive",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-shadow-unchanged-allow",
				CommitID:       "C23",
				Description:    "Both enforced and candidate policies allow operator access. Authoritative result is allow=true, no divergence observed.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID:              "req-c23-shadow-03",
					Path:                   "/api/v1/workloads/jobs",
					Action:                 "read",
					ResourceID:             "job-worker-103",
					ResourceClassification: policy.ResourceClassPrivate,
					Subject: policy.SubjectIdentity{
						ID:            "usr-operator-03",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					DeadlineMS:      200,
					EvalTime:        "2026-11-06T12:00:00Z",
					EnforcedBundle:  &bEnforcedAllowOperator,
					CandidateBundle: &bCandidateUnchanged,
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:          true,
					StatusCode:     200,
					EnforcedAllow:  true,
					CandidateAllow: true,
					Diverged:       false,
					DivergenceType: rollout.DivergenceNone,
				},
			},
		},
		{
			name: "positive-shadow-resilience-panic.json",
			fType: "positive",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-shadow-resilience-panic",
				CommitID:       "C23",
				Description:    "Candidate policy triggers evaluation panic; enforced evaluation succeeds (allow=true). Authoritative result remains allow=true without failure.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID:              "req-c23-shadow-04",
					Path:                   "/api/v1/workloads/jobs",
					Action:                 "read",
					ResourceID:             "job-worker-104",
					ResourceClassification: policy.ResourceClassPrivate,
					Subject: policy.SubjectIdentity{
						ID:            "usr-operator-04",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					DeadlineMS:          200,
					EvalTime:            "2026-11-06T12:00:00Z",
					EnforcedBundle:      &bEnforcedAllowOperator,
					SimulateShadowPanic: true,
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:          true,
					StatusCode:     200,
					EnforcedAllow:  true,
					CandidateAllow: false,
					Diverged:       true,
					DivergenceType: rollout.DivergenceShadowError,
				},
			},
		},
		{
			name: "positive-shadow-restart-invariant.json",
			fType: "positive",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-shadow-restart-invariant",
				CommitID:       "C23",
				Description:    "Repeated shadow evaluation across engine restarts produces identical deterministic subject pseudonyms and zero token exposure.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID:              "req-c23-shadow-05",
					Path:                   "/api/v1/workloads/jobs",
					Action:                 "read",
					ResourceID:             "job-worker-105",
					ResourceClassification: policy.ResourceClassPrivate,
					Subject: policy.SubjectIdentity{
						ID:            "usr-operator-persisted",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					Headers: map[string]string{
						"Authorization": "Bearer restartedSessionBearerTokenC23",
						"Cookie":        "policyhelix_session=restartedSessionCookieValueC23",
					},
					DeadlineMS:      200,
					EvalTime:        "2026-11-06T12:00:00Z",
					EnforcedBundle:  &bEnforcedAllowOperator,
					CandidateBundle: &bCandidateUnchanged,
					PseudonymSalt:   "policyhelix-test-salt-c23",
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:            true,
					StatusCode:       200,
					EnforcedAllow:    true,
					CandidateAllow:   true,
					Diverged:         false,
					DivergenceType:   rollout.DivergenceNone,
					SubjectPseudonym: "pseudo:sha256:553bbf7c42c884665d0b2e0e8b680c78c48861e35cdbce472b110d2927d245bb",
				},
			},
		},
		{
			name: "negative-private-resource-fail-closed.json",
			fType: "negative",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "negative-private-resource-fail-closed",
				CommitID:       "C23",
				Description:    "Unauthenticated access to a private resource fails closed on enforced evaluation (allow=false, 403 Forbidden) regardless of candidate policy.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID:              "req-c23-shadow-06",
					Path:                   "/api/v1/secure/vault",
					Action:                 "read",
					ResourceID:             "vault-secrets-01",
					ResourceClassification: policy.ResourceClassPrivate,
					Subject: policy.SubjectIdentity{
						ID:            "",
						Authenticated: false,
					},
					DeadlineMS:      200,
					EvalTime:        "2026-11-06T12:00:00Z",
					EnforcedBundle:  &bVaultPrivate,
					CandidateBundle: &bVaultCandidate,
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:          false,
					StatusCode:     403,
					EnforcedAllow:  false,
					CandidateAllow: false,
					Diverged:       false,
					DivergenceType: rollout.DivergenceNone,
					ErrorCode:      "PRIVATE_RESOURCE_FAIL_CLOSED",
				},
			},
		},
		{
			name: "negative-provider-unavailable.json",
			fType: "negative",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "negative-provider-unavailable",
				CommitID:       "C23",
				Description:    "Unavailable policy provider produces an explicit 503 error rather than placeholder success.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID:           "req-c23-shadow-07",
					Path:                "/api/v1/workloads/jobs",
					Action:              "read",
					ProviderUnavailable: true,
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:      false,
					StatusCode: 503,
					ErrorCode:  "PROVIDER_UNAVAILABLE",
				},
			},
		},
		{
			name: "negative-malformed-request.json",
			fType: "negative",
			envelope: c23FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "negative-malformed-request",
				CommitID:       "C23",
				Description:    "Missing required prerequisites (path and action) produces an explicit 400 error rather than placeholder success.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: rollout.ShadowEvalRequest{
					RequestID: "req-c23-shadow-08",
					Path:      "",
					Action:    "",
				},
				Expected: struct {
					Allow           bool                   `json:"allow"`
					StatusCode      int                    `json:"status_code"`
					EnforcedAllow   bool                   `json:"enforced_allow"`
					CandidateAllow  bool                   `json:"candidate_allow"`
					Diverged        bool                   `json:"diverged"`
					DivergenceType  rollout.DivergenceType `json:"divergence_type"`
					ErrorCode       string                 `json:"error_code,omitempty"`
					SubjectPseudonym string                `json:"subject_pseudonym,omitempty"`
				}{
					Allow:      false,
					StatusCode: 400,
					ErrorCode:  "MALFORMED_REQUEST",
				},
			},
		},
	}

	type manifestEntry struct {
		FixtureID string `json:"fixture_id"`
		Path      string `json:"path"`
		SHA256    string `json:"sha256"`
		Type      string `json:"type"`
		License   string `json:"license"`
	}

	var manifestEntries []manifestEntry

	for _, fx := range fixtures {
		filePath := filepath.Join(dir, fx.name)
		raw, err := json.MarshalIndent(fx.envelope, "", "  ")
		if err != nil {
			t.Fatalf("failed to marshal fixture %s: %v", fx.name, err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filePath, raw, 0644); err != nil {
			t.Fatalf("failed to write fixture %s: %v", filePath, err)
		}

		sum := sha256.Sum256(raw)
		manifestEntries = append(manifestEntries, manifestEntry{
			FixtureID: fx.envelope.FixtureID,
			Path:      filepath.Join("tests", "fixtures", "policyhelix", "C23", fx.name),
			SHA256:    hex.EncodeToString(sum[:]),
			Type:      fx.fType,
			License:   "Apache-2.0",
		})
	}

	manifestObj := struct {
		CommitID      string          `json:"commit_id"`
		SchemaVersion string          `json:"schema_version"`
		License       string          `json:"license"`
		Description   string          `json:"description"`
		Fixtures      []manifestEntry `json:"fixtures"`
	}{
		CommitID:      "C23",
		SchemaVersion: "1",
		License:       "Apache-2.0",
		Description:   "Synthetic licensed fixtures for PolicyHelix C23: test candidate policies in shadow mode (Requirement F17).",
		Fixtures:      manifestEntries,
	}

	manifestRaw, err := json.MarshalIndent(manifestObj, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal C23 manifest: %v", err)
	}
	manifestRaw = append(manifestRaw, '\n')
	if err := os.WriteFile(manifestPath, manifestRaw, 0644); err != nil {
		t.Fatalf("failed to write C23 manifest: %v", err)
	}

	return dir
}

func TestC23_ManifestIntegrity(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	manifestRaw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C23 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C23 manifest: %v", err)
	}
	if manifest.CommitID != "C23" {
		t.Fatalf("expected commit_id C23, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 8 {
		t.Fatalf("expected at least 8 C23 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(dir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		sum := sha256.Sum256(raw)
		actualSHA := hex.EncodeToString(sum[:])
		if actualSHA != entry.SHA256 {
			t.Fatalf("SHA256 mismatch for fixture %s: expected %s, got %s", entry.Path, entry.SHA256, actualSHA)
		}
	}
}

func TestC23_Acceptance_EnforcedResultNeverChanged(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	// Scenario 1: Allow to Deny divergence
	{
		raw, err := os.ReadFile(filepath.Join(dir, "positive-shadow-allow-to-deny.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		var env c23FixtureEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		enfEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
		candEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
		engine := rollout.NewShadowEngine(enfEval, candEval, nil)

		res, err := engine.Evaluate(context.Background(), env.Request)
		if err != nil {
			t.Fatalf("evaluation returned unexpected error: %v", err)
		}

		if !res.Allow {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: authoritative allow must be true (enforced decision), got false")
		}
		if res.StatusCode != 200 {
			t.Fatalf("expected status code 200, got %d", res.StatusCode)
		}
		if !res.Diverged {
			t.Fatalf("expected diverged=true when candidate denies, got false")
		}
		if res.DivergenceType != rollout.DivergenceAllowToDeny {
			t.Fatalf("expected divergence_type %s, got %s", rollout.DivergenceAllowToDeny, res.DivergenceType)
		}
		if res.CandidateDecision == nil || res.CandidateDecision.Allow != false {
			t.Fatalf("expected candidate decision allow=false, got %+v", res.CandidateDecision)
		}
		if res.EnforcedDecision.Allow != true {
			t.Fatalf("expected enforced decision allow=true, got %+v", res.EnforcedDecision)
		}
	}

	// Scenario 2: Deny to Allow divergence
	{
		raw, err := os.ReadFile(filepath.Join(dir, "positive-shadow-deny-to-allow.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		var env c23FixtureEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		enfEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
		candEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
		engine := rollout.NewShadowEngine(enfEval, candEval, nil)

		res, err := engine.Evaluate(context.Background(), env.Request)
		if err != nil {
			t.Fatalf("evaluation returned unexpected error: %v", err)
		}

		if res.Allow {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: authoritative allow must be false (enforced decision), got true")
		}
		if res.StatusCode != 403 {
			t.Fatalf("expected status code 403, got %d", res.StatusCode)
		}
		if !res.Diverged {
			t.Fatalf("expected diverged=true when candidate permits denied request, got false")
		}
		if res.DivergenceType != rollout.DivergenceDenyToAllow {
			t.Fatalf("expected divergence_type %s, got %s", rollout.DivergenceDenyToAllow, res.DivergenceType)
		}
		if res.CandidateDecision == nil || res.CandidateDecision.Allow != true {
			t.Fatalf("expected candidate decision allow=true, got %+v", res.CandidateDecision)
		}
		if res.EnforcedDecision.Allow != false {
			t.Fatalf("expected enforced decision allow=false, got %+v", res.EnforcedDecision)
		}
	}

	// Scenario 3: Unchanged Allow
	{
		raw, err := os.ReadFile(filepath.Join(dir, "positive-shadow-unchanged-allow.json"))
		if err != nil {
			t.Fatalf("failed to read fixture: %v", err)
		}
		var env c23FixtureEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		enfEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
		candEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
		engine := rollout.NewShadowEngine(enfEval, candEval, nil)

		res, err := engine.Evaluate(context.Background(), env.Request)
		if err != nil {
			t.Fatalf("evaluation returned unexpected error: %v", err)
		}

		if !res.Allow {
			t.Fatalf("expected allow=true, got false")
		}
		if res.Diverged {
			t.Fatalf("expected diverged=false for identical decisions, got true")
		}
		if res.DivergenceType != rollout.DivergenceNone {
			t.Fatalf("expected divergence_type NONE, got %s", res.DivergenceType)
		}
	}
}

func TestC23_DivergenceAuditing_ZeroTokenLeaks(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	raw, err := os.ReadFile(filepath.Join(dir, "positive-shadow-allow-to-deny.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c23FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	enfEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	candEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	engine := rollout.NewShadowEngine(enfEval, candEval, nil)

	res, err := engine.Evaluate(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("evaluation returned unexpected error: %v", err)
	}

	if res.DivergenceRecord == nil {
		t.Fatalf("expected divergence record to be created, got nil")
	}

	// 1. Verify subject pseudonymization
	if strings.Contains(res.DivergenceRecord.SubjectPseudonym, "usr-operator-01") {
		t.Fatalf("raw subject ID leaked into subject pseudonym: %s", res.DivergenceRecord.SubjectPseudonym)
	}
	if !strings.HasPrefix(res.DivergenceRecord.SubjectPseudonym, "pseudo:sha256:") {
		t.Fatalf("subject pseudonym must be formatted pseudo:sha256:<hash>, got %s", res.DivergenceRecord.SubjectPseudonym)
	}

	// 2. Verify VerifyNoTokenOrCookie on record passes
	if err := rollout.VerifyNoTokenOrCookie(res.DivergenceRecord); err != nil {
		t.Fatalf("VerifyNoTokenOrCookie failed: %v", err)
	}

	// 3. Inspect serialized JSON for zero token leakage
	serialized, err := json.Marshal(res.DivergenceRecord)
	if err != nil {
		t.Fatalf("failed to marshal divergence record: %v", err)
	}
	serializedStr := string(serialized)

	forbiddenTokens := []string{
		"sigShadow01",
		"shadowCookieToken01",
		"secretToken99",
	}
	for _, tok := range forbiddenTokens {
		if strings.Contains(serializedStr, tok) {
			t.Fatalf("raw token %q leaked into divergence record JSON: %s", tok, serializedStr)
		}
	}
}

func TestC23_ShadowResilience_PanicAndTimeout(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	raw, err := os.ReadFile(filepath.Join(dir, "positive-shadow-resilience-panic.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c23FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	enfEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	candEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	engine := rollout.NewShadowEngine(enfEval, candEval, nil)

	res, err := engine.Evaluate(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("evaluation returned unexpected error on shadow panic: %v", err)
	}

	if !res.Allow {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: enforced allow must not be disrupted by shadow panic, got allow=false")
	}
	if res.StatusCode != 200 {
		t.Fatalf("expected status code 200, got %d", res.StatusCode)
	}
	if !res.Diverged {
		t.Fatalf("expected diverged=true for shadow error")
	}
	if res.DivergenceType != rollout.DivergenceShadowError {
		t.Fatalf("expected divergence_type %s, got %s", rollout.DivergenceShadowError, res.DivergenceType)
	}
	if res.CandidateDecision == nil || !strings.Contains(res.DivergenceRecord.CandidateDecision.Error, "SHADOW_PANIC") {
		t.Fatalf("expected candidate error to record panic recovery, got %+v", res.DivergenceRecord.CandidateDecision)
	}
}

func TestC23_Negative_MissingPrerequisitesAndMalformed(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	raw, err := os.ReadFile(filepath.Join(dir, "negative-malformed-request.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c23FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	engine := rollout.NewShadowEngine(nil, nil, nil)
	res, err := engine.Evaluate(context.Background(), env.Request)

	if err == nil {
		t.Fatalf("expected explicit error for malformed request, got nil")
	}
	var rErr *rollout.RolloutError
	if !strings.Contains(err.Error(), rollout.ErrCodeMalformedRequest) {
		t.Fatalf("expected error containing %s, got %v", rollout.ErrCodeMalformedRequest, err)
	}
	_ = rErr

	if res == nil || res.StatusCode != 400 || res.Allow {
		t.Fatalf("expected res.StatusCode=400 and allow=false, got %+v", res)
	}
}

func TestC23_Negative_ProviderUnavailable(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	raw, err := os.ReadFile(filepath.Join(dir, "negative-provider-unavailable.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c23FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	engine := rollout.NewShadowEngine(nil, nil, nil)
	res, err := engine.Evaluate(context.Background(), env.Request)

	if err == nil {
		t.Fatalf("expected explicit error for provider unavailable, got nil")
	}
	if !strings.Contains(err.Error(), rollout.ErrCodeProviderUnavailable) {
		t.Fatalf("expected error containing %s, got %v", rollout.ErrCodeProviderUnavailable, err)
	}
	if res == nil || res.StatusCode != 503 || res.Allow {
		t.Fatalf("expected res.StatusCode=503 and allow=false, got %+v", res)
	}
}

func TestC23_Negative_PrivateResourcesFailClosed(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	raw, err := os.ReadFile(filepath.Join(dir, "negative-private-resource-fail-closed.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c23FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	enfEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	candEval := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	engine := rollout.NewShadowEngine(enfEval, candEval, nil)

	res, err := engine.Evaluate(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("evaluation returned unexpected error: %v", err)
	}

	if res.Allow {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: unauthenticated private resource access must fail closed (allow=false), got true")
	}
	if res.StatusCode != 403 {
		t.Fatalf("expected 403 Forbidden, got %d", res.StatusCode)
	}
}

func TestC23_RestartInvariance(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	raw, err := os.ReadFile(filepath.Join(dir, "positive-shadow-restart-invariant.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}
	var env c23FixtureEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// 1. Evaluate on engine 1 with store 1
	store1 := rollout.NewMemoryDivergenceStore(100)
	enfEval1 := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	candEval1 := policy.NewBundleEvaluator(env.TrustedIssuers, env.TrustedSigners)
	engine1 := rollout.NewShadowEngine(enfEval1, candEval1, store1)

	res1, err := engine1.Evaluate(context.Background(), env.Request)
	if err != nil {
		t.Fatalf("evaluation error on engine 1: %v", err)
	}
	if !res1.Allow {
		t.Fatalf("expected allow=true, got false")
	}

	// Expected pseudonym check
	expectedPseudo := audit.ComputeSubjectPseudonym(env.Request.Subject.ID, env.Request.PseudonymSalt)
	if res1.DivergenceRecord.SubjectPseudonym != expectedPseudo {
		t.Fatalf("subject pseudonym mismatch: expected %s, got %s", expectedPseudo, res1.DivergenceRecord.SubjectPseudonym)
	}
	if env.Expected.SubjectPseudonym != "" && res1.DivergenceRecord.SubjectPseudonym != env.Expected.SubjectPseudonym {
		t.Fatalf("declared fixture expected subject pseudonym mismatch: expected %s, got %s", env.Expected.SubjectPseudonym, res1.DivergenceRecord.SubjectPseudonym)
	}

	// 2. Export store state
	snapBytes, err := store1.ExportJSON()
	if err != nil {
		t.Fatalf("failed to export store state: %v", err)
	}

	// 3. Import into store 2 on simulated engine restart
	store2 := rollout.NewMemoryDivergenceStore(100)
	if err := store2.ImportJSON(snapBytes); err != nil {
		t.Fatalf("failed to import store state: %v", err)
	}

	stats1 := store1.GetStats()
	stats2 := store2.GetStats()
	if stats1 != stats2 {
		t.Fatalf("stats mismatch across restart: %+v != %+v", stats1, stats2)
	}

	recs1 := store1.GetRecords(rollout.DivergenceFilter{})
	recs2 := store2.GetRecords(rollout.DivergenceFilter{})
	if len(recs1) != len(recs2) || len(recs1) != 1 {
		t.Fatalf("records length mismatch across restart: %d != %d", len(recs1), len(recs2))
	}
	if recs1[0].RecordID != recs2[0].RecordID || recs1[0].SubjectPseudonym != recs2[0].SubjectPseudonym {
		t.Fatalf("record contents mismatch across restart")
	}
}

func TestC23_CLIExecution(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	// 1. Positive: Allow to Deny divergence (authoritative allow=true, diverged=true)
	{
		posFixture := filepath.Join(dir, "positive-shadow-allow-to-deny.json")
		cmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-shadow", posFixture)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("CLI execution failed for allow-to-deny: %v, stderr: %s", err, stderr.String())
		}
		var res rollout.ShadowResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to parse CLI JSON output: %v, raw: %s", err, stdout.String())
		}
		if !res.Allow || !res.Diverged || res.DivergenceType != rollout.DivergenceAllowToDeny {
			t.Fatalf("unexpected CLI allow-to-deny result: %+v", res)
		}
	}

	// 2. Positive: Deny to Allow divergence (authoritative allow=false, status=403, diverged=true)
	{
		posFixture := filepath.Join(dir, "positive-shadow-deny-to-allow.json")
		cmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-shadow", posFixture)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("CLI execution unexpectedly failed for deny-to-allow fixture: %v, stderr: %s", err, stderr.String())
		}
		var res rollout.ShadowResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to parse CLI JSON output: %v, raw: %s", err, stdout.String())
		}
		if res.Allow || res.StatusCode != 403 || !res.Diverged || res.DivergenceType != rollout.DivergenceDenyToAllow {
			t.Fatalf("unexpected CLI deny-to-allow result: %+v", res)
		}
	}

	// 3. Positive: Unchanged Allow
	{
		posFixture := filepath.Join(dir, "positive-shadow-unchanged-allow.json")
		cmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-shadow", posFixture)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("CLI execution failed for unchanged-allow: %v, stderr: %s", err, stderr.String())
		}
		var res rollout.ShadowResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to parse CLI JSON output: %v, raw: %s", err, stdout.String())
		}
		if !res.Allow || res.Diverged || res.DivergenceType != rollout.DivergenceNone {
			t.Fatalf("unexpected CLI unchanged-allow result: %+v", res)
		}
	}

	// 4. Positive: Resilience Panic
	{
		posFixture := filepath.Join(dir, "positive-shadow-resilience-panic.json")
		cmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-shadow", posFixture)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("CLI execution failed for resilience-panic: %v, stderr: %s", err, stderr.String())
		}
		var res rollout.ShadowResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to parse CLI JSON output: %v, raw: %s", err, stdout.String())
		}
		if !res.Allow || !res.Diverged || res.DivergenceType != rollout.DivergenceShadowError {
			t.Fatalf("unexpected CLI resilience-panic result: %+v", res)
		}
	}

	// 5. Negative: Missing prerequisites / Malformed (must exit non-zero)
	{
		negFixture := filepath.Join(dir, "negative-malformed-request.json")
		negCmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-shadow", negFixture)
		var negStdout, negStderr bytes.Buffer
		negCmd.Stdout = &negStdout
		negCmd.Stderr = &negStderr
		if err := negCmd.Run(); err == nil {
			t.Fatalf("expected non-zero exit code for malformed fixture CLI execution, got success: stdout=%s", negStdout.String())
		}
	}

	// 6. Negative: Provider unavailable (must exit non-zero)
	{
		negFixture := filepath.Join(dir, "negative-provider-unavailable.json")
		negCmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-shadow", negFixture)
		var negStdout, negStderr bytes.Buffer
		negCmd.Stdout = &negStdout
		negCmd.Stderr = &negStderr
		if err := negCmd.Run(); err == nil {
			t.Fatalf("expected non-zero exit code for provider-unavailable fixture CLI execution, got success: stdout=%s", negStdout.String())
		}
	}

	// 7. Negative: Private resources fail closed (must exit non-zero)
	{
		negFixture := filepath.Join(dir, "negative-private-resource-fail-closed.json")
		negCmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-shadow", negFixture)
		var negStdout, negStderr bytes.Buffer
		negCmd.Stdout = &negStdout
		negCmd.Stderr = &negStderr
		if err := negCmd.Run(); err == nil {
			t.Fatalf("expected non-zero exit code for private-fail-closed fixture CLI execution, got success: stdout=%s", negStdout.String())
		}
	}
}

func TestC23_ObligationParameterDivergence(t *testing.T) {
	issued := "2026-11-06T00:00:00Z"
	expires := "2026-11-07T00:00:00Z"

	// Enforced bundle with obligation grace_period = 300
	bEnf := makeC23SignedBundle("bundle-ob-enf", 20, issued, expires, "/api/v1/data", []string{"operator"}, policy.ResourceClassPrivate, "allow", "msg")
	bEnf.Rules[0].Obligations = []policy.PolicyObligation{
		{
			ID:         "ob-mfa",
			Type:       "mfa_challenge",
			Parameters: map[string]interface{}{"grace_period": float64(300)},
		},
	}
	bEnf.Digest = policy.ComputeCanonicalBundleDigest(bEnf)

	// Candidate bundle with changed parameter grace_period = 60
	bCand := makeC23SignedBundle("bundle-ob-cand", 21, issued, expires, "/api/v1/data", []string{"operator"}, policy.ResourceClassPrivate, "allow", "msg")
	bCand.Rules[0].Obligations = []policy.PolicyObligation{
		{
			ID:         "ob-mfa",
			Type:       "mfa_challenge",
			Parameters: map[string]interface{}{"grace_period": float64(60)},
		},
	}
	bCand.Digest = policy.ComputeCanonicalBundleDigest(bCand)

	enfEval := policy.NewBundleEvaluator([]string{"https://issuer.policyhelix.local"}, []string{"ed25519-primary-2026"})
	candEval := policy.NewBundleEvaluator([]string{"https://issuer.policyhelix.local"}, []string{"ed25519-primary-2026"})
	engine := rollout.NewShadowEngine(enfEval, candEval, nil)

	req := rollout.ShadowEvalRequest{
		RequestID: "req-ob-param-test",
		Path:      "/api/v1/data",
		Action:    "read",
		Subject: policy.SubjectIdentity{
			ID:            "usr-op",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
		},
		EnforcedBundle:  &bEnf,
		CandidateBundle: &bCand,
	}

	res, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected evaluate error: %v", err)
	}

	if !res.Diverged {
		t.Fatalf("expected diverged=true when obligation parameters differ, got false")
	}
	if res.DivergenceType != rollout.DivergenceObligation {
		t.Fatalf("expected divergence_type %s, got %s", rollout.DivergenceObligation, res.DivergenceType)
	}
}

func TestC23_ConcurrentStressDivergenceStore(t *testing.T) {
	store := rollout.NewMemoryDivergenceStore(500)
	var wg sync.WaitGroup

	// 20 concurrent writer goroutines recording 50 records each
	for w := 0; w < 20; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				rec := rollout.DivergenceRecord{
					RecordID: fmt.Sprintf("rec-%d-%d", workerID, i),
					RequestID: fmt.Sprintf("req-%d-%d", workerID, i),
					Path: "/api/v1/jobs",
					Action: "read",
					Diverged: i%2 == 0,
					DivergenceType: rollout.DivergenceAllowToDeny,
				}
				store.Record(rec)
			}
		}(w)
	}

	// 10 concurrent reader goroutines querying records and stats
	for r := 0; r < 10; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = store.GetRecords(rollout.DivergenceFilter{DivergedOnly: true})
				_ = store.GetStats()
			}
		}()
	}

	wg.Wait()

	stats := store.GetStats()
	if stats.TotalEvaluations != 1000 {
		t.Fatalf("expected 1000 total evaluations, got %d", stats.TotalEvaluations)
	}
	if stats.TotalDivergences != 500 {
		t.Fatalf("expected 500 total divergences, got %d", stats.TotalDivergences)
	}

	// Verify store is bounded to maxRecords (500)
	records := store.GetRecords(rollout.DivergenceFilter{})
	if len(records) != 500 {
		t.Fatalf("expected store bounded to 500 records, got %d", len(records))
	}
}

func TestC23_HTTPEndpoints(t *testing.T) {
	dir := generateC23FixturesIfMissing(t)

	raw, err := os.ReadFile(filepath.Join(dir, "positive-shadow-allow-to-deny.json"))
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	// Use test server with an engine instance
	store := rollout.NewMemoryDivergenceStore(100)
	engine := rollout.NewShadowEngine(nil, nil, store)

	handleEvaluate := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "method_not_allowed"})
			return
		}
		var env c23FixtureEnvelope
		var req rollout.ShadowEvalRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &env); err == nil && env.Request.Path != "" {
			req = env.Request
		} else {
			if err := json.Unmarshal(body, &req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "malformed_request"})
				return
			}
		}

		res, rErr := engine.Evaluate(r.Context(), req)
		status := http.StatusOK
		if res != nil && res.StatusCode > 0 {
			status = res.StatusCode
		} else if rErr != nil {
			var roErr *rollout.RolloutError
			if errors.As(rErr, &roErr) && roErr.StatusCode > 0 {
				status = roErr.StatusCode
			} else {
				status = http.StatusBadRequest
			}
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(res)
	}

	handleDivergence := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Query().Get("clear") == "true" {
			store.Clear()
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "cleared"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "method_not_allowed"})
			return
		}
		filter := rollout.DivergenceFilter{}
		if r.URL.Query().Get("diverged_only") == "true" {
			filter.DivergedOnly = true
		}
		records := store.GetRecords(filter)
		stats := store.GetStats()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"stats":   stats,
			"records": records,
			"count":   len(records),
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/rollout/shadow/evaluate", handleEvaluate)
	mux.HandleFunc("/v1/runtime/rollout/shadow", handleEvaluate)
	mux.HandleFunc("/api/v1/rollout/shadow/divergence", handleDivergence)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// 1. Test POST /api/v1/rollout/shadow/evaluate
	resp, err := http.Post(srv.URL+"/api/v1/rollout/shadow/evaluate", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST evaluate failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	var res rollout.ShadowResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !res.Allow || !res.Diverged {
		t.Fatalf("expected allow=true and diverged=true, got allow=%v diverged=%v", res.Allow, res.Diverged)
	}

	// 2. Test alias route POST /v1/runtime/rollout/shadow
	aliasResp, err := http.Post(srv.URL+"/v1/runtime/rollout/shadow", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST alias evaluate failed: %v", err)
	}
	defer aliasResp.Body.Close()
	if aliasResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 on alias route, got %d", aliasResp.StatusCode)
	}

	// 3. Test GET /api/v1/rollout/shadow/divergence with filter
	divResp, err := http.Get(srv.URL + "/api/v1/rollout/shadow/divergence?diverged_only=true")
	if err != nil {
		t.Fatalf("GET divergence failed: %v", err)
	}
	defer divResp.Body.Close()

	if divResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", divResp.StatusCode)
	}
	var divData struct {
		Stats   rollout.DivergenceStats    `json:"stats"`
		Records []rollout.DivergenceRecord `json:"records"`
		Count   int                        `json:"count"`
	}
	if err := json.NewDecoder(divResp.Body).Decode(&divData); err != nil {
		t.Fatalf("failed to decode divergence response: %v", err)
	}
	if divData.Count != 2 || divData.Stats.TotalEvaluations != 2 || divData.Stats.AllowToDenyCount != 2 {
		t.Fatalf("unexpected divergence stats: %+v", divData)
	}

	// 4. Test POST /api/v1/rollout/shadow/divergence?clear=true
	clearResp, err := http.Post(srv.URL+"/api/v1/rollout/shadow/divergence?clear=true", "application/json", nil)
	if err != nil {
		t.Fatalf("POST clear failed: %v", err)
	}
	defer clearResp.Body.Close()
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 on clear, got %d", clearResp.StatusCode)
	}
	if len(store.GetRecords(rollout.DivergenceFilter{})) != 0 {
		t.Fatalf("expected store to be empty after clear")
	}

	// 5. Test malformed POST
	badResp, err := http.Post(srv.URL+"/api/v1/rollout/shadow/evaluate", "application/json", strings.NewReader("invalid-json"))
	if err != nil {
		t.Fatalf("POST malformed failed: %v", err)
	}
	defer badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid JSON, got %d", badResp.StatusCode)
	}
}
