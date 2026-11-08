package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
)

const (
	c24FixtureRelDir = "fixtures/policyhelix/C24"
)

func getC24FixtureDir() string {
	candidates := []string{
		c24FixtureRelDir,
		filepath.Join("tests", c24FixtureRelDir),
		filepath.Join("..", "tests", c24FixtureRelDir),
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			return c
		}
	}
	return c24FixtureRelDir
}

type c24FixtureEnvelope struct {
	SchemaVersion  string                     `json:"schema_version"`
	FixtureID      string                     `json:"fixture_id"`
	CommitID       string                     `json:"commit_id"`
	Description    string                     `json:"description"`
	License        string                     `json:"license"`
	TrustedIssuers []string                   `json:"trusted_issuers,omitempty"`
	TrustedSigners []string                   `json:"trusted_signers,omitempty"`
	Request        policy.EvaluateCacheRequest `json:"request"`
	Expected       struct {
		Allow      bool   `json:"allow"`
		StatusCode int    `json:"status_code"`
		Cached     bool   `json:"cached"`
		ErrorCode  string `json:"error_code,omitempty"`
	} `json:"expected"`
}

func makeC24SignedBundle(bundleID string, rev int64, issuedAt, expiresAt string, pathPattern string, roles []string, class policy.ResourceClass, reasonCode, reasonMsg string) policy.LocalPolicyBundle {
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

// c24IssuedAt and c24ExpiresAt return a rolling validity window so the fixture suite does not
// become a time bomb once a hard-coded calendar date passes.
func c24IssuedAt() string { return time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339) }
func c24ExpiresAt() string { return time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339) }

func generateC24FixturesIfMissing(t *testing.T) string {
	t.Helper()
	dir := getC24FixtureDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create C24 fixtures dir %s: %v", dir, err)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	if _, err := os.Stat(manifestPath); err == nil {
		return dir // Already generated
	}

	issued := c24IssuedAt()
	expires := c24ExpiresAt()

	bundleRev20 := makeC24SignedBundle(
		"bundle-workloads-v20", 20, issued, expires,
		"/api/v1/workloads/jobs", []string{"operator", "admin"}, policy.ResourceClassPrivate,
		"policy_allow_operator", "Operator allowed in revision 20",
	)

	bundleRev21 := makeC24SignedBundle(
		"bundle-workloads-v21", 21, issued, expires,
		"/api/v1/workloads/jobs", []string{"admin"}, policy.ResourceClassRestricted,
		"policy_allow_admin", "Admin only in revision 21",
	)

	bundleVaultRev22 := makeC24SignedBundle(
		"bundle-vault-v22", 22, issued, expires,
		"/api/v1/secure/vault", []string{"admin"}, policy.ResourceClassPrivate,
		"policy_allow_vault_admin", "Vault admin only in revision 22",
	)

	fixtures := []struct {
		name     string
		envelope c24FixtureEnvelope
		fType    string
	}{
		{
			name:  "positive-cache-hit-bound-keys.json",
			fType: "positive",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-cache-hit-bound-keys",
				CommitID:       "C24",
				Description:    "Decision cache hit when subject, action, context, and revision match exactly.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-01",
					Path:      "/api/v1/workloads/jobs",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					SessionID:              "sess-c24-001",
					ResourceID:             "job-worker-101",
					OwnerScope:             "tenant-alpha",
					ResourceClassification: policy.ResourceClassPrivate,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleRev20,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      true,
					StatusCode: 200,
					Cached:     false, // First evaluation is miss, second is hit
				},
			},
		},
		{
			name:  "positive-cache-miss-on-revision-change.json",
			fType: "positive",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-cache-miss-on-revision-change",
				CommitID:       "C24",
				Description:    "Decision cache misses and re-evaluates when bundle revision changes from 20 to 21.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-02",
					Path:      "/api/v1/workloads/jobs",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					SessionID:              "sess-c24-001",
					ResourceID:             "job-worker-101",
					OwnerScope:             "tenant-alpha",
					ResourceClassification: policy.ResourceClassRestricted,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleRev21,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      false,
					StatusCode: 403,
					Cached:     false,
				},
			},
		},
		{
			name:  "positive-cache-miss-on-context-change.json",
			fType: "positive",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-cache-miss-on-context-change",
				CommitID:       "C24",
				Description:    "Decision cache misses when context resource_id or owner_scope differs.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-03",
					Path:      "/api/v1/workloads/jobs",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					SessionID:              "sess-c24-001",
					ResourceID:             "job-worker-999-different",
					OwnerScope:             "tenant-beta-different",
					ResourceClassification: policy.ResourceClassPrivate,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleRev20,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      true,
					StatusCode: 200,
					Cached:     false,
				},
			},
		},
		{
			name:  "positive-cache-miss-on-action-change.json",
			fType: "positive",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-cache-miss-on-action-change",
				CommitID:       "C24",
				Description:    "Decision cache misses when action changes (e.g. read to write).",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-04",
					Path:      "/api/v1/workloads/jobs",
					Action:    "write",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					SessionID:              "sess-c24-001",
					ResourceID:             "job-worker-101",
					OwnerScope:             "tenant-alpha",
					ResourceClassification: policy.ResourceClassPrivate,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleRev20,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      false,
					StatusCode: 403,
					Cached:     false,
				},
			},
		},
		{
			name:  "positive-revoke-invalidates-session.json",
			fType: "positive",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-revoke-invalidates-session",
				CommitID:       "C24",
				Description:    "Session revocation immediately invalidates cached decision entries for that session ID.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-05",
					Path:      "/api/v1/workloads/jobs",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-revoked-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					SessionID:              "sess-c24-revoked-session",
					ResourceID:             "job-worker-101",
					OwnerScope:             "tenant-alpha",
					ResourceClassification: policy.ResourceClassPrivate,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleRev20,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      true,
					StatusCode: 200,
					Cached:     false,
				},
			},
		},
		{
			name:  "positive-revoke-invalidates-subject-epoch.json",
			fType: "positive",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-revoke-invalidates-subject-epoch",
				CommitID:       "C24",
				Description:    "Subject epoch advance invalidates all cached decisions for that subject below min epoch.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-06",
					Path:      "/api/v1/workloads/jobs",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-epoch-revoked",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1000, // below min epoch 2000
					},
					SessionID:              "sess-c24-epoch-test",
					ResourceID:             "job-worker-101",
					OwnerScope:             "tenant-alpha",
					ResourceClassification: policy.ResourceClassPrivate,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleRev20,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      true,
					StatusCode: 200,
					Cached:     false,
				},
			},
		},
		{
			name:  "positive-restart-invariant.json",
			fType: "positive",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "positive-restart-invariant",
				CommitID:       "C24",
				Description:    "Cache restart invariance: fresh cache initialized with safe bounded capacity and TTL preserves fail-closed posture.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-07",
					Path:      "/api/v1/workloads/jobs",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-restart-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					SessionID:              "sess-c24-restart-test",
					ResourceID:             "job-worker-101",
					OwnerScope:             "tenant-alpha",
					ResourceClassification: policy.ResourceClassPrivate,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleRev20,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      true,
					StatusCode: 200,
					Cached:     false,
				},
			},
		},
		{
			name:  "negative-private-resource-fail-closed.json",
			fType: "negative",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "negative-private-resource-fail-closed",
				CommitID:       "C24",
				Description:    "Unauthenticated request to a private resource strictly fails closed without caching an allow decision.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-neg-01",
					Path:      "/api/v1/secure/vault",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "",
						Issuer:        "",
						Roles:         nil,
						Authenticated: false,
						SessionEpoch:  0,
					},
					ResourceID:             "vault-secrets-01",
					OwnerScope:             "tenant-alpha",
					ResourceClassification: policy.ResourceClassPrivate,
					DeadlineMS:             200,
					EvalTime:               "2026-11-06T12:00:00Z",
					Bundle:                 &bundleVaultRev22,
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      false,
					StatusCode: 403,
					Cached:     false,
					ErrorCode:  "PRIVATE_RESOURCE_FAIL_CLOSED",
				},
			},
		},
		{
			name:  "negative-provider-unavailable.json",
			fType: "negative",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "negative-provider-unavailable",
				CommitID:       "C24",
				Description:    "When policy decision provider is unavailable, engine returns 503 error without polluting the cache.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-neg-02",
					Path:      "/api/v1/workloads/jobs",
					Action:    "read",
					Subject: policy.SubjectIdentity{
						ID:            "usr-op-01",
						Issuer:        "https://issuer.policyhelix.local",
						Roles:         []string{"operator"},
						Authenticated: true,
						SessionEpoch:  1793793000,
					},
					ProviderUnavailable: true,
					DeadlineMS:          200,
					EvalTime:            "2026-11-06T12:00:00Z",
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      false,
					StatusCode: 503,
					Cached:     false,
					ErrorCode:  "PROVIDER_UNAVAILABLE",
				},
			},
		},
		{
			name:  "negative-malformed-request.json",
			fType: "negative",
			envelope: c24FixtureEnvelope{
				SchemaVersion:  "1",
				FixtureID:      "negative-malformed-request",
				CommitID:       "C24",
				Description:    "Malformed cache request missing path and action produces an explicit 400 error.",
				License:        "Apache-2.0",
				TrustedIssuers: []string{"https://issuer.policyhelix.local"},
				TrustedSigners: []string{"ed25519-primary-2026"},
				Request: policy.EvaluateCacheRequest{
					RequestID: "req-c24-cache-neg-03",
					Path:      "",
					Action:    "",
					Subject: policy.SubjectIdentity{
						ID:            "",
						Issuer:        "",
						Roles:         nil,
						Authenticated: false,
						SessionEpoch:  0,
					},
				},
				Expected: struct {
					Allow      bool   `json:"allow"`
					StatusCode int    `json:"status_code"`
					Cached     bool   `json:"cached"`
					ErrorCode  string `json:"error_code,omitempty"`
				}{
					Allow:      false,
					StatusCode: 400,
					Cached:     false,
					ErrorCode:  "MALFORMED_REQUEST",
				},
			},
		},
	}

	type manifestItem struct {
		FixtureID string `json:"fixture_id"`
		Path      string `json:"path"`
		SHA256    string `json:"sha256"`
		Type      string `json:"type"`
		License   string `json:"license"`
	}

	manifestItems := make([]manifestItem, 0, len(fixtures))

	for _, fix := range fixtures {
		filePath := filepath.Join(dir, fix.name)
		raw, err := json.MarshalIndent(fix.envelope, "", "  ")
		if err != nil {
			t.Fatalf("failed to marshal fixture %s: %v", fix.name, err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filePath, raw, 0644); err != nil {
			t.Fatalf("failed to write fixture file %s: %v", filePath, err)
		}

		sum := sha256.Sum256(raw)
		hexSum := hex.EncodeToString(sum[:])

		relPath := filepath.ToSlash(filepath.Join("tests", c24FixtureRelDir, fix.name))
		manifestItems = append(manifestItems, manifestItem{
			FixtureID: fix.envelope.FixtureID,
			Path:      relPath,
			SHA256:    hexSum,
			Type:      fix.fType,
			License:   "Apache-2.0",
		})
	}

	manifestData := map[string]interface{}{
		"commit_id":      "C24",
		"schema_version": "1",
		"license":        "Apache-2.0",
		"description":    "Synthetic licensed fixtures for PolicyHelix C24: bound policy decision cache keys and expiry (Requirement F18).",
		"fixtures":       manifestItems,
	}

	manifestRaw, err := json.MarshalIndent(manifestData, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}
	manifestRaw = append(manifestRaw, '\n')
	if err := os.WriteFile(manifestPath, manifestRaw, 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	return dir
}

// 1. Manifest integrity test
func TestC24_ManifestIntegrity(t *testing.T) {
	dir := generateC24FixturesIfMissing(t)
	manifestPath := filepath.Join(dir, "manifest.json")

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read C24 manifest: %v", err)
	}

	var manifest struct {
		CommitID string `json:"commit_id"`
		License  string `json:"license"`
		Fixtures []struct {
			FixtureID string `json:"fixture_id"`
			Path      string `json:"path"`
			SHA256    string `json:"sha256"`
			Type      string `json:"type"`
			License   string `json:"license"`
		} `json:"fixtures"`
	}

	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("failed to parse C24 manifest JSON: %v", err)
	}

	if manifest.CommitID != "C24" {
		t.Errorf("expected commit_id C24, got %s", manifest.CommitID)
	}
	if manifest.License != "Apache-2.0" {
		t.Errorf("expected license Apache-2.0, got %s", manifest.License)
	}
	if len(manifest.Fixtures) < 10 {
		t.Fatalf("expected at least 10 fixtures in C24 manifest, got %d", len(manifest.Fixtures))
	}

	for _, f := range manifest.Fixtures {
		baseName := filepath.Base(f.Path)
		targetFile := filepath.Join(dir, baseName)
		content, err := os.ReadFile(targetFile)
		if err != nil {
			t.Fatalf("fixture file missing: %s: %v", targetFile, err)
		}
		sum := sha256.Sum256(content)
		actualSHA := hex.EncodeToString(sum[:])
		if actualSHA != f.SHA256 {
			t.Errorf("fixture %s SHA256 mismatch: recorded %s, actual %s", f.FixtureID, f.SHA256, actualSHA)
		}
		if f.License != "Apache-2.0" {
			t.Errorf("fixture %s has non-Apache-2.0 license: %s", f.FixtureID, f.License)
		}
	}
}

// 2. Cache key binding tests across all 4 dimensions
func TestC24_KeyBindingFourDimensions(t *testing.T) {
	baseComp := policy.CacheKeyComponents{
		SubjectID:     "usr-42",
		Issuer:        "https://issuer.policyhelix.local",
		Roles:         []string{"operator", "admin"},
		Authenticated: true,
		SessionEpoch:  1000,
		SessionID:     "sess-001",
		Action:        "read",
		Path:          "/api/v1/workloads/jobs",
		ResourceID:    "job-101",
		OwnerScope:    "tenant-alpha",
		Revision:      5,
		PolicyDigest:  "sha256:5e08449017a14e9061dd5f6658cab2db23d75704b711f9c7e1eacc5d0657661d",
	}

	baseKey := policy.ComputeCacheKey(baseComp)
	if !strings.HasPrefix(baseKey, "pk:") || len(baseKey) != 67 { // "pk:" + 64 hex chars
		t.Fatalf("invalid cache key format: %s", baseKey)
	}

	// Permutation: roles ordering must be deterministic
	permRolesComp := baseComp
	permRolesComp.Roles = []string{"admin", "operator"}
	permKey := policy.ComputeCacheKey(permRolesComp)
	if permKey != baseKey {
		t.Errorf("cache key must be invariant to roles order: base=%s, perm=%s", baseKey, permKey)
	}

	// Dimension 1: Subject change (e.g. SessionID, SubjectID, SessionEpoch, Authenticated)
	dimSub1 := baseComp
	dimSub1.SessionID = "sess-002"
	if policy.ComputeCacheKey(dimSub1) == baseKey {
		t.Errorf("cache key must bind SessionID")
	}

	dimSub2 := baseComp
	dimSub2.SubjectID = "usr-43"
	if policy.ComputeCacheKey(dimSub2) == baseKey {
		t.Errorf("cache key must bind SubjectID")
	}

	dimSub3 := baseComp
	dimSub3.SessionEpoch = 1001
	if policy.ComputeCacheKey(dimSub3) == baseKey {
		t.Errorf("cache key must bind SessionEpoch")
	}

	dimSub4 := baseComp
	dimSub4.Authenticated = false
	if policy.ComputeCacheKey(dimSub4) == baseKey {
		t.Errorf("cache key must bind Authenticated")
	}

	// Dimension 2: Action change
	dimAct := baseComp
	dimAct.Action = "write"
	if policy.ComputeCacheKey(dimAct) == baseKey {
		t.Errorf("cache key must bind Action")
	}

	// Action normalization (case insensitive)
	dimActNorm := baseComp
	dimActNorm.Action = "READ"
	if policy.ComputeCacheKey(dimActNorm) != baseKey {
		t.Errorf("cache key must normalize action to lowercase")
	}

	// Dimension 3: Context change (Path, ResourceID, OwnerScope)
	dimCtx1 := baseComp
	dimCtx1.Path = "/api/v1/workloads/other"
	if policy.ComputeCacheKey(dimCtx1) == baseKey {
		t.Errorf("cache key must bind Path")
	}

	dimCtx2 := baseComp
	dimCtx2.ResourceID = "job-999"
	if policy.ComputeCacheKey(dimCtx2) == baseKey {
		t.Errorf("cache key must bind ResourceID")
	}

	dimCtx3 := baseComp
	dimCtx3.OwnerScope = "tenant-beta"
	if policy.ComputeCacheKey(dimCtx3) == baseKey {
		t.Errorf("cache key must bind OwnerScope")
	}

	// Dimension 4: Revision change (Revision, PolicyDigest)
	dimRev1 := baseComp
	dimRev1.Revision = 6
	if policy.ComputeCacheKey(dimRev1) == baseKey {
		t.Errorf("cache key must bind Revision")
	}

	dimRev2 := baseComp
	dimRev2.PolicyDigest = "sha256:7b6b7a534de82d7954cc6d50d5909685808d95ecc18803045b5dc1e2b7d6226e"
	if policy.ComputeCacheKey(dimRev2) == baseKey {
		t.Errorf("cache key must bind PolicyDigest")
	}
}

// mockRevocationChecker for testing revocation integration
type mockRevocationChecker struct {
	mu              sync.RWMutex
	revokedSessions map[string]bool
	subjectEpochs   map[string]int64
	scopeEpochs     map[string]int64
}

func newMockRevocationChecker() *mockRevocationChecker {
	return &mockRevocationChecker{
		revokedSessions: make(map[string]bool),
		subjectEpochs:   make(map[string]int64),
		scopeEpochs:     make(map[string]int64),
	}
}

func (m *mockRevocationChecker) IsRevoked(_ context.Context, sessionID, subjectID, ownerScope string, sessionEpoch int64, _ time.Time) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.revokedSessions[sessionID] {
		return true
	}
	if minEp, ok := m.subjectEpochs[subjectID]; ok && sessionEpoch < minEp {
		return true
	}
	if minEp, ok := m.scopeEpochs[ownerScope]; ok && sessionEpoch < minEp {
		return true
	}
	return false
}

// 3. TTL Expiry and bounds enforcement
func TestC24_TTLExpiryAndBounds(t *testing.T) {
	// 1. Enforce max TTL bound <= 30s
	_, err := policy.NewDecisionCache(policy.CacheConfig{
		TTL: 35 * time.Second,
	})
	if err == nil {
		t.Fatalf("expected error for TTL exceeding 30s bound")
	}

	// 2. Controlled clock TTL expiry test
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	clock := now

	cache, err := policy.NewDecisionCache(policy.CacheConfig{
		TTL: 15 * time.Second,
		Clock: func() time.Time {
			return clock
		},
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	comp := policy.CacheKeyComponents{
		SubjectID:  "usr-ttl",
		Action:     "read",
		Path:       "/test",
		Revision:   1,
		SessionID:  "sess-ttl",
		OwnerScope: "tenant-a",
	}
	key := policy.ComputeCacheKey(comp)

	dec := policy.BundleDecision{
		Allow:          true,
		Revision:       1,
		Classification: policy.ResourceClassPrivate,
		WithinDeadline: true,
	}

	if err := cache.Put(key, dec, comp, clock); err != nil {
		t.Fatalf("put failed: %v", err)
	}

	// Immediate hit
	if _, hit := cache.Get(context.Background(), key, clock); !hit {
		t.Fatalf("expected cache hit immediately after put")
	}

	// Advance clock within TTL (+10s) -> still hit
	clock = now.Add(10 * time.Second)
	if _, hit := cache.Get(context.Background(), key, clock); !hit {
		t.Fatalf("expected cache hit at +10s (TTL=15s)")
	}

	// Advance clock beyond TTL (+16s) -> miss
	clock = now.Add(16 * time.Second)
	if _, hit := cache.Get(context.Background(), key, clock); hit {
		t.Fatalf("expected cache miss at +16s (TTL=15s)")
	}

	// Verify stats reflect expiry
	stats := cache.Stats()
	if stats.Misses < 1 {
		t.Errorf("expected at least 1 miss recorded, got %d", stats.Misses)
	}
}

// 4. Revocation invalidation tests (Session, Subject, Scope)
func TestC24_RevocationInvalidation(t *testing.T) {
	mockRev := newMockRevocationChecker()
	cache, err := policy.NewDecisionCache(policy.CacheConfig{
		TTL:               15 * time.Second,
		RevocationChecker: mockRev,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	now := time.Now().UTC()

	// Entry 1: Session 1
	comp1 := policy.CacheKeyComponents{
		SubjectID:    "usr-alice",
		SessionID:    "sess-alice-01",
		OwnerScope:   "scope-alpha",
		SessionEpoch: 100,
		Action:       "read",
		Path:         "/api/data",
		Revision:     1,
	}
	key1 := policy.ComputeCacheKey(comp1)
	_ = cache.Put(key1, policy.BundleDecision{Allow: true, WithinDeadline: true}, comp1, now)

	// Entry 2: Session 2 (same subject, different session)
	comp2 := policy.CacheKeyComponents{
		SubjectID:    "usr-alice",
		SessionID:    "sess-alice-02",
		OwnerScope:   "scope-alpha",
		SessionEpoch: 100,
		Action:       "read",
		Path:         "/api/data",
		Revision:     1,
	}
	key2 := policy.ComputeCacheKey(comp2)
	_ = cache.Put(key2, policy.BundleDecision{Allow: true, WithinDeadline: true}, comp2, now)

	// Entry 3: Bob in same scope
	comp3 := policy.CacheKeyComponents{
		SubjectID:    "usr-bob",
		SessionID:    "sess-bob-01",
		OwnerScope:   "scope-alpha",
		SessionEpoch: 100,
		Action:       "read",
		Path:         "/api/data",
		Revision:     1,
	}
	key3 := policy.ComputeCacheKey(comp3)
	_ = cache.Put(key3, policy.BundleDecision{Allow: true, WithinDeadline: true}, comp3, now)

	// Verify all 3 hit
	if _, hit := cache.Get(context.Background(), key1, now); !hit {
		t.Errorf("key1 expected hit")
	}
	if _, hit := cache.Get(context.Background(), key2, now); !hit {
		t.Errorf("key2 expected hit")
	}
	if _, hit := cache.Get(context.Background(), key3, now); !hit {
		t.Errorf("key3 expected hit")
	}

	// 1. Invalidate Session 1 explicitly
	invCount := cache.InvalidateSession("sess-alice-01")
	if invCount != 1 {
		t.Errorf("expected 1 session invalidated, got %d", invCount)
	}
	if _, hit := cache.Get(context.Background(), key1, now); hit {
		t.Errorf("key1 should miss after session invalidation")
	}
	if _, hit := cache.Get(context.Background(), key2, now); !hit {
		t.Errorf("key2 should still hit")
	}

	// 2. Invalidate Subject Alice by epoch
	invSubj := cache.InvalidateSubject("usr-alice", 200)
	if invSubj != 1 { // key2 had epoch 100 < 200
		t.Errorf("expected 1 subject entry invalidated, got %d", invSubj)
	}
	if _, hit := cache.Get(context.Background(), key2, now); hit {
		t.Errorf("key2 should miss after subject epoch invalidation")
	}
	if _, hit := cache.Get(context.Background(), key3, now); !hit {
		t.Errorf("key3 (Bob) should still hit")
	}

	// 3. Live revocation checker drop on Get
	mockRev.revokedSessions["sess-bob-01"] = true
	if _, hit := cache.Get(context.Background(), key3, now); hit {
		t.Errorf("key3 should be dropped by live revocation check on Get")
	}
	if cache.Stats().RevocationDrop < 1 {
		t.Errorf("expected revocation_drop metric incremented")
	}
}

// 5. Bounded capacity and LRU eviction
func TestC24_BoundedLRUEviction(t *testing.T) {
	cache, err := policy.NewDecisionCache(policy.CacheConfig{
		Capacity: 3,
		TTL:      30 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	now := time.Now().UTC()

	compA := policy.CacheKeyComponents{SubjectID: "A", Action: "read", Path: "/a"}
	keyA := policy.ComputeCacheKey(compA)
	_ = cache.Put(keyA, policy.BundleDecision{Allow: true, WithinDeadline: true}, compA, now)

	compB := policy.CacheKeyComponents{SubjectID: "B", Action: "read", Path: "/b"}
	keyB := policy.ComputeCacheKey(compB)
	_ = cache.Put(keyB, policy.BundleDecision{Allow: true, WithinDeadline: true}, compB, now)

	compC := policy.CacheKeyComponents{SubjectID: "C", Action: "read", Path: "/c"}
	keyC := policy.ComputeCacheKey(compC)
	_ = cache.Put(keyC, policy.BundleDecision{Allow: true, WithinDeadline: true}, compC, now)

	if cache.Stats().Count != 3 {
		t.Fatalf("expected count 3, got %d", cache.Stats().Count)
	}

	// Access keyA to make it most recently used (LRU order: B oldest, then C, then A)
	if _, hit := cache.Get(context.Background(), keyA, now); !hit {
		t.Fatalf("keyA hit expected")
	}

	// Insert D -> should evict B (the least recently used)
	compD := policy.CacheKeyComponents{SubjectID: "D", Action: "read", Path: "/d"}
	keyD := policy.ComputeCacheKey(compD)
	_ = cache.Put(keyD, policy.BundleDecision{Allow: true, WithinDeadline: true}, compD, now)

	if cache.Stats().Count != 3 {
		t.Errorf("count must remain bounded at 3, got %d", cache.Stats().Count)
	}
	if cache.Stats().Evictions != 1 {
		t.Errorf("expected 1 eviction, got %d", cache.Stats().Evictions)
	}

	// Verify B was evicted
	if _, hit := cache.Get(context.Background(), keyB, now); hit {
		t.Errorf("keyB should have been evicted")
	}

	// Verify A, C, D are present
	if _, hit := cache.Get(context.Background(), keyA, now); !hit {
		t.Errorf("keyA should still be present")
	}
	if _, hit := cache.Get(context.Background(), keyC, now); !hit {
		t.Errorf("keyC should still be present")
	}
	if _, hit := cache.Get(context.Background(), keyD, now); !hit {
		t.Errorf("keyD should still be present")
	}
}

// 6. Concurrency and race safety (-race)
func TestC24_ConcurrentAccessRaceSafety(t *testing.T) {
	cache, err := policy.NewDecisionCache(policy.CacheConfig{
		Capacity: 50,
		TTL:      20 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	const goroutines = 20
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	now := time.Now().UTC()

	// Writers
	for i := 0; i < goroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				comp := policy.CacheKeyComponents{
					SubjectID: fmt.Sprintf("usr-%d", j%10),
					Action:    "read",
					Path:      fmt.Sprintf("/res/%d", j%5),
					Revision:  int64(j % 3),
				}
				key := policy.ComputeCacheKey(comp)
				_ = cache.Put(key, policy.BundleDecision{Allow: j%2 == 0, WithinDeadline: true}, comp, now)
			}
		}(i)
	}

	// Readers
	for i := 0; i < goroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				comp := policy.CacheKeyComponents{
					SubjectID: fmt.Sprintf("usr-%d", j%10),
					Action:    "read",
					Path:      fmt.Sprintf("/res/%d", j%5),
					Revision:  int64(j % 3),
				}
				key := policy.ComputeCacheKey(comp)
				_, _ = cache.Get(context.Background(), key, now)
			}
		}(i)
	}

	// Invalidation & stats callers
	for i := 0; i < goroutines; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				if j%10 == 0 {
					cache.InvalidateSubject(fmt.Sprintf("usr-%d", j%10), 0)
				}
				_ = cache.Stats()
			}
		}(i)
	}

	wg.Wait()

	stats := cache.Stats()
	if stats.Count > 50 {
		t.Errorf("cache count %d exceeded capacity 50", stats.Count)
	}
}

// 7. Zero token invariant
func TestC24_ZeroTokenInvariant(t *testing.T) {
	cache, err := policy.NewDecisionCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Put with a Bearer token in components must be strictly rejected
	compLeakingBearer := policy.CacheKeyComponents{
		SubjectID: "Bearer eyJhbGciOi...",
		Action:    "read",
		Path:      "/vault",
	}
	key := policy.ComputeCacheKey(compLeakingBearer)
	err = cache.Put(key, policy.BundleDecision{Allow: true, WithinDeadline: true}, compLeakingBearer, time.Now().UTC())
	if err == nil {
		t.Fatalf("expected error rejecting bearer token in cache components")
	}

	// Put with a JWT in components must be strictly rejected
	compLeakingJWT := policy.CacheKeyComponents{
		SubjectID: "usr-01",
		Action:    "read",
		Path:      "/vault",
		ResourceID: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	}
	keyJWT := policy.ComputeCacheKey(compLeakingJWT)
	err = cache.Put(keyJWT, policy.BundleDecision{Allow: true, WithinDeadline: true}, compLeakingJWT, time.Now().UTC())
	if err == nil {
		t.Fatalf("expected error rejecting JWT token in cache components")
	}
}

// 8. Fail-closed on private resources
func TestC24_FailClosedPrivateResources(t *testing.T) {
	cache, err := policy.NewDecisionCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	bundle := makeC24SignedBundle(
		"bundle-vault-v1", 1, c24IssuedAt(), c24ExpiresAt(),
		"/vault/secret", []string{"admin"}, policy.ResourceClassPrivate,
		"allow_vault", "admin only",
	)

	evaluator := policy.NewBundleEvaluator([]string{bundle.Issuer}, []string{bundle.SignerKeyID})
	_ = evaluator.LoadBundle(bundle, time.Now().UTC())

	// Unauthenticated request to private resource
	req := policy.EvaluateCacheRequest{
		Path:   "/vault/secret",
		Action: "read",
		Subject: policy.SubjectIdentity{
			Authenticated: false,
		},
		ResourceClassification: policy.ResourceClassPrivate,
		Bundle:                 &bundle,
	}

	res, err := cache.EvaluateRequest(context.Background(), evaluator, req)
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	if res.Decision.Allow {
		t.Fatalf("unauthenticated access to private resource must fail closed with allow=false")
	}
	if res.StatusCode != 403 {
		t.Errorf("expected HTTP 403 for private resource fail-closed, got %d", res.StatusCode)
	}
}

// 9. CLI execution of fixtures under tests/fixtures/policyhelix/C24/
func TestC24_CLIExecution(t *testing.T) {
	dir := generateC24FixturesIfMissing(t)

	manifestPath := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("failed to read manifest: %v", err)
	}

	var manifest struct {
		Fixtures []struct {
			FixtureID string `json:"fixture_id"`
			Path      string `json:"path"`
			Type      string `json:"type"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("failed to unmarshal manifest: %v", err)
	}

	for _, f := range manifest.Fixtures {
		fixtureFilePath := filepath.Join(dir, filepath.Base(f.Path))

		cmd := exec.Command("go", "run", "../cmd/policyhelix", "-evaluate-cache", fixtureFilePath)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		runErr := cmd.Run()

		if f.Type == "positive" {
			if runErr != nil {
				t.Errorf("fixture %s failed CLI execution: %v, stderr: %s, stdout: %s", f.FixtureID, runErr, stderr.String(), stdout.String())
			}
		} else if f.Type == "negative" {
			if runErr == nil {
				t.Errorf("negative fixture %s expected non-zero exit code, but succeeded: stdout: %s", f.FixtureID, stdout.String())
			}
		}
	}
}

// 10. HTTP endpoints over loopback
func TestC24_HTTPEndpoints(t *testing.T) {
	cache, err := policy.NewDecisionCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	bundle := makeC24SignedBundle(
		"bundle-http-v1", 1, c24IssuedAt(), c24ExpiresAt(),
		"/api/v1/jobs", []string{"operator"}, policy.ResourceClassPrivate,
		"allow_op", "operator allowed",
	)
	evaluator := policy.NewBundleEvaluator([]string{bundle.Issuer}, []string{bundle.SignerKeyID})
	_ = evaluator.LoadBundle(bundle, time.Now().UTC())

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/policy/cache/evaluate", func(w http.ResponseWriter, r *http.Request) {
		var req policy.EvaluateCacheRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		res, _ := cache.EvaluateRequest(r.Context(), evaluator, req)
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusOK
		if res.StatusCode > 0 {
			status = res.StatusCode
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("/api/v1/policy/cache/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cache.Stats())
	})

	mux.HandleFunc("/api/v1/policy/cache/invalidate", func(w http.ResponseWriter, r *http.Request) {
		cache.Clear()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "cleared", "stats": cache.Stats()})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := server.Client()

	// 1. Evaluate request
	reqBody := `{
		"path": "/api/v1/jobs",
		"action": "read",
		"subject": {
			"id": "usr-http-01",
			"issuer": "https://issuer.policyhelix.local",
			"roles": ["operator"],
			"authenticated": true
		},
		"bundle": `
	bRaw, _ := json.Marshal(bundle)
	reqBody += string(bRaw) + `}`

	resp, err := client.Post(server.URL+"/api/v1/policy/cache/evaluate", "application/json", strings.NewReader(reqBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP evaluate failed: %v, status: %v", err, resp.Status)
	}
	var res policy.EvaluateCacheResponse
	_ = json.NewDecoder(resp.Body).Decode(&res)
	_ = resp.Body.Close()
	if !res.Decision.Allow {
		t.Errorf("expected allow=true")
	}
	if res.Cached {
		t.Errorf("first evaluate should be a cache miss (cached=false)")
	}

	// 2. Second evaluate request should hit cache
	resp2, err := client.Post(server.URL+"/api/v1/policy/cache/evaluate", "application/json", strings.NewReader(reqBody))
	if err != nil || resp2.StatusCode != http.StatusOK {
		t.Fatalf("HTTP second evaluate failed: %v, status: %v", err, resp2.Status)
	}
	var res2 policy.EvaluateCacheResponse
	_ = json.NewDecoder(resp2.Body).Decode(&res2)
	_ = resp2.Body.Close()
	if !res2.Cached {
		t.Errorf("second evaluate should be a cache hit (cached=true)")
	}

	// 3. GET /api/v1/policy/cache/stats
	sResp, err := client.Get(server.URL + "/api/v1/policy/cache/stats")
	if err != nil || sResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP stats failed: %v, status: %v", err, sResp.Status)
	}
	var stats policy.CacheStats
	_ = json.NewDecoder(sResp.Body).Decode(&stats)
	_ = sResp.Body.Close()
	if stats.Hits < 1 {
		t.Errorf("expected at least 1 hit in stats, got %d", stats.Hits)
	}

	// 4. Invalidate / Clear
	invResp, err := client.Post(server.URL+"/api/v1/policy/cache/invalidate", "application/json", nil)
	if err != nil || invResp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP invalidate failed: %v, status: %v", err, invResp.Status)
	}
	_ = invResp.Body.Close()

	if cache.Stats().Count != 0 {
		t.Errorf("expected count 0 after invalidate/clear, got %d", cache.Stats().Count)
	}
}

// 11. Test EvaluateWithCache using BundleEvalInput (the core evaluator method)
func TestC24_EvaluateWithCache_BundleEvalInput(t *testing.T) {
	cache, err := policy.NewDecisionCache(policy.CacheConfig{
		TTL: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	bundle := makeC24SignedBundle(
		"bundle-core-v1", 1, c24IssuedAt(), c24ExpiresAt(),
		"/api/v1/workloads/jobs", []string{"operator"}, policy.ResourceClassPrivate,
		"allow_op", "operator allowed",
	)
	evaluator := policy.NewBundleEvaluator([]string{bundle.Issuer}, []string{bundle.SignerKeyID})
	if err := evaluator.LoadBundle(bundle, time.Now().UTC()); err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}

	input := policy.BundleEvalInput{
		RequestID: "req-c24-core-01",
		Path:      "/api/v1/workloads/jobs",
		Action:    "read",
		Subject: policy.SubjectIdentity{
			ID:            "usr-core-01",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
			SessionEpoch:  100,
		},
		ResourceID: "job-101",
		DeadlineMS: 200,
		EvalTime:   time.Now().UTC().Format(time.RFC3339),
	}

	// First call: cache miss, cached=false
	dec1, hit1 := cache.EvaluateWithCache(context.Background(), evaluator, input)
	if hit1 {
		t.Errorf("first evaluation must be a cache miss (hit=false)")
	}
	if !dec1.Allow {
		t.Errorf("expected allow=true, got allow=false")
	}

	// Second call: cache hit, cached=true
	dec2, hit2 := cache.EvaluateWithCache(context.Background(), evaluator, input)
	if !hit2 {
		t.Errorf("second evaluation must be a cache hit (hit=true)")
	}
	if !dec2.Allow {
		t.Errorf("expected cached allow=true")
	}

	// Invalidate subject epoch
	cache.InvalidateSubject("usr-core-01", 200)

	// Third call: after invalidation, should be cache miss
	_, hit3 := cache.EvaluateWithCache(context.Background(), evaluator, input)
	if hit3 {
		t.Errorf("evaluation after invalidation must be a cache miss")
	}

	// Negative case: unauthenticated request to private resource must fail closed
	unauthInput := input
	unauthInput.Subject.Authenticated = false
	unauthDec, _ := cache.EvaluateWithCache(context.Background(), evaluator, unauthInput)
	if unauthDec.Allow {
		t.Errorf("unauthenticated request to private resource must fail closed")
	}
}

// 12. Test canonicalization and whitespace handling for cache keys and invalidation
func TestC24_CanonicalizationAndWhitespace(t *testing.T) {
	cache, err := policy.NewDecisionCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Roles with whitespace and duplicate values
	comp1 := policy.CacheKeyComponents{
		SubjectID:     "usr-ws-01",
		Issuer:        "https://issuer.policyhelix.local",
		Roles:         []string{" admin ", "operator", "admin"},
		Authenticated: true,
		Action:        "READ ",
		Path:          " /api/data ",
		SessionID:     " sess-ws-01 ",
		OwnerScope:    " scope-ws-01 ",
		Revision:      1,
		PolicyDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
	}

	comp2 := policy.CacheKeyComponents{
		SubjectID:     "usr-ws-01",
		Issuer:        "https://issuer.policyhelix.local",
		Roles:         []string{"operator", "admin"},
		Authenticated: true,
		Action:        "read",
		Path:          "/api/data",
		SessionID:     "sess-ws-01",
		OwnerScope:    "scope-ws-01",
		Revision:      1,
		PolicyDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
	}

	key1 := policy.ComputeCacheKey(comp1)
	key2 := policy.ComputeCacheKey(comp2)
	if key1 != key2 {
		t.Errorf("cache key must be canonicalized: key1=%s, key2=%s", key1, key2)
	}

	// Put with comp1 (which has untrimmed whitespace)
	now := time.Now().UTC()
	if err := cache.Put(key1, policy.BundleDecision{Allow: true, WithinDeadline: true}, comp1, now); err != nil {
		t.Fatalf("put failed: %v", err)
	}

	// Invalidate using clean session ID "sess-ws-01" must succeed
	invSess := cache.InvalidateSession("sess-ws-01")
	if invSess != 1 {
		t.Errorf("expected 1 session invalidated, got %d", invSess)
	}
	if _, hit := cache.Get(context.Background(), key1, now); hit {
		t.Errorf("entry should have been invalidated by InvalidateSession")
	}

	// Re-insert and test InvalidateScope with clean scope
	_ = cache.Put(key1, policy.BundleDecision{Allow: true, WithinDeadline: true}, comp1, now)
	invScope := cache.InvalidateScope("scope-ws-01", 0)
	if invScope != 1 {
		t.Errorf("expected 1 scope invalidated, got %d", invScope)
	}
	if _, hit := cache.Get(context.Background(), key1, now); hit {
		t.Errorf("entry should have been invalidated by InvalidateScope")
	}
}

// 13. Test restart invariance
func TestC24_RestartInvariance(t *testing.T) {
	// Simulate engine restart: new cache constructed from default configuration
	cache, err := policy.NewDecisionCache(policy.CacheConfig{})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	stats := cache.Stats()
	if stats.Count != 0 {
		t.Errorf("fresh restarted cache must have count=0, got %d", stats.Count)
	}
	if stats.Capacity != policy.DefaultCacheCapacity {
		t.Errorf("fresh cache must have default capacity %d, got %d", policy.DefaultCacheCapacity, stats.Capacity)
	}

	// Posture after restart without any bundles: strictly fails closed
	res, err := cache.EvaluateRequest(context.Background(), nil, policy.EvaluateCacheRequest{
		Path:   "/api/v1/workloads/jobs",
		Action: "read",
		Subject: policy.SubjectIdentity{
			ID:            "usr-op-01",
			Authenticated: true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected eval error: %v", err)
	}
	if res.Decision.Allow {
		t.Errorf("restarted cache without bundle must fail closed (allow=false)")
	}
	if res.StatusCode != 500 {
		t.Errorf("expected 500 status code when no active bundle, got %d", res.StatusCode)
	}
}

// 14. Test non-blocking live revocation check under concurrent reads
func TestC24_ConcurrentRevocationNonBlocking(t *testing.T) {
	slowChecker := &slowMockRevocationChecker{
		delay: 30 * time.Millisecond,
	}

	cache, err := policy.NewDecisionCache(policy.CacheConfig{
		TTL:               15 * time.Second,
		RevocationChecker: slowChecker,
	})
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	now := time.Now().UTC()

	compSlow := policy.CacheKeyComponents{SubjectID: "usr-slow", Action: "read", Path: "/slow"}
	keySlow := policy.ComputeCacheKey(compSlow)
	_ = cache.Put(keySlow, policy.BundleDecision{Allow: true, WithinDeadline: true}, compSlow, now)

	compFast := policy.CacheKeyComponents{SubjectID: "usr-fast", Action: "read", Path: "/fast"}
	keyFast := policy.ComputeCacheKey(compFast)
	_ = cache.Put(keyFast, policy.BundleDecision{Allow: true, WithinDeadline: true}, compFast, now)

	// Launch slow reader
	slowDone := make(chan struct{})
	go func() {
		_, _ = cache.Get(context.Background(), keySlow, now)
		close(slowDone)
	}()

	// Give the slow reader time to enter Get and call IsRevoked
	time.Sleep(10 * time.Millisecond)

	// Fast reader should NOT be blocked by slow reader
	fastStart := time.Now()
	_, hit := cache.Get(context.Background(), keyFast, now)
	fastDuration := time.Since(fastStart)

	if !hit {
		t.Errorf("keyFast expected hit")
	}
	if fastDuration >= 25*time.Millisecond {
		t.Errorf("keyFast was blocked by keySlow revocation check (took %v, expected < 25ms)", fastDuration)
	}

	<-slowDone
}

type slowMockRevocationChecker struct {
	delay time.Duration
}

func (s *slowMockRevocationChecker) IsRevoked(_ context.Context, _, subjectID, _ string, _ int64, _ time.Time) bool {
	if subjectID == "usr-slow" {
		time.Sleep(s.delay)
	}
	return false
}

