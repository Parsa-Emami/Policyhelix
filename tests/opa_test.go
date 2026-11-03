package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
)

func newTestTrustedEvaluator() *policy.BundleEvaluator {
	return policy.NewBundleEvaluator(
		[]string{"https://issuer.policyhelix.local"},
		[]string{"ed25519-primary-2026"},
	)
}

func makeSignedBundle(rev int64, issuedAt, expiresAt string) policy.LocalPolicyBundle {
	b := policy.LocalPolicyBundle{
		SchemaVersion:     "1",
		BundleID:          "bundle-analytics-v1",
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
				Pattern:              "/api/v1/analytics/reports",
				Action:               "read",
				Classification:       policy.ResourceClassPrivate,
				AllowUnauthenticated: false,
				RequiredRoles:        []string{"operator", "admin"},
				Description:          "Private analytics reports endpoint",
			},
			{
				Pattern:              "/healthz",
				Action:               "read",
				Classification:       policy.ResourceClassPublic,
				AllowUnauthenticated: true,
				Description:          "Explicit public health endpoint",
			},
		},
		Rules: []policy.PolicyRule{
			{
				ID:            "rule-operator-analytics-read",
				Effect:        "allow",
				PathPattern:   "/api/v1/analytics/reports",
				Actions:       []string{"read"},
				Roles:         []string{"operator", "admin"},
				ResourceClass: policy.ResourceClassPrivate,
				ReasonCode:    "policy_allow_role_operator",
				ReasonMessage: "Operator granted read access to analytics reports",
				Obligations: []policy.PolicyObligation{
					{
						ID:   "audit_log_decision",
						Type: "audit",
					},
				},
			},
			{
				ID:            "rule-public-healthz",
				Effect:        "allow",
				PathPattern:   "/healthz",
				Actions:       []string{"read"},
				ResourceClass: policy.ResourceClassPublic,
				ReasonCode:    policy.ReasonExplicitPublicAllow,
				ReasonMessage: "Explicit public health route",
			},
		},
	}
	b.Digest = policy.ComputeCanonicalBundleDigest(b)
	return b
}

// TestC08InvalidPolicyProducesDenyError verifies Requirement F02:
// Invalid policy syntax, missing fail-closed default, or malformed rules produce deny/error
// with zero silent fallback permits.
func TestC08InvalidPolicyProducesDenyError(t *testing.T) {
	ev := newTestTrustedEvaluator()
	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")

	// 1. Missing 'default allow = false' in Rego module
	noDefault := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	noDefault.RegoModule = "package policyhelix.authz\nallow { true }"
	noDefault.Digest = policy.ComputeCanonicalBundleDigest(noDefault)

	if err := ev.LoadBundle(noDefault, evalTime); err == nil || err.Code != policy.ErrCodeInvalidPolicyBundle {
		t.Fatalf("Expected INVALID_POLICY_BUNDLE for missing default allow=false, got: %v", err)
	}

	// 2. Unbalanced braces / syntax error in Rego module
	badSyntax := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	badSyntax.RegoModule = "package policyhelix.authz\ndefault allow = false\nallow { input.subject.authenticated == true "
	badSyntax.Digest = policy.ComputeCanonicalBundleDigest(badSyntax)

	dec := ev.Evaluate(context.Background(), policy.BundleEvalInput{
		RequestID:  "req-bad-syntax",
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
		},
		Bundle: &badSyntax,
	})
	if dec.Allow {
		t.Fatalf("Security invariant violated: invalid policy bundle produced allow=true")
	}
	if dec.Error == nil || dec.Error.Code != policy.ErrCodeInvalidPolicyBundle {
		t.Fatalf("Expected error code %s, got: %+v", policy.ErrCodeInvalidPolicyBundle, dec.Error)
	}

	// 3. Invalid rule effect ("permit" instead of "allow"/"deny")
	badEffect := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	badEffect.Rules[0].Effect = "permit_fallback"
	badEffect.Digest = policy.ComputeCanonicalBundleDigest(badEffect)

	if err := ev.LoadBundle(badEffect, evalTime); err == nil || err.Code != policy.ErrCodeInvalidPolicyBundle {
		t.Fatalf("Expected INVALID_POLICY_BUNDLE for invalid rule effect, got: %v", err)
	}
}

// TestC08DeadlineProducesDenyError verifies Requirement F02:
// Exceeding the evaluation deadline or cancelling context produces allow=false and explicit error.
func TestC08DeadlineProducesDenyError(t *testing.T) {
	ev := newTestTrustedEvaluator()
	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")
	validBundle := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")

	if err := ev.LoadBundle(validBundle, evalTime); err != nil {
		t.Fatalf("Failed to load valid bundle: %v", err)
	}

	// 1. Simulated execution exceeding deadline_ms (15ms deadline vs 45ms simulated delay)
	timeoutDec := ev.Evaluate(context.Background(), policy.BundleEvalInput{
		RequestID:        "req-timeout-1",
		Path:             "/api/v1/analytics/reports",
		Action:           "read",
		DeadlineMS:       15,
		SimulatedDelayMS: 45,
		EvalTime:         "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
		},
	})
	if timeoutDec.Allow {
		t.Fatalf("Security invariant violated: deadline timeout produced fallback permit")
	}
	if timeoutDec.WithinDeadline {
		t.Errorf("Expected WithinDeadline=false on timeout")
	}
	if timeoutDec.Error == nil || timeoutDec.Error.Code != policy.ErrCodeDeadlineExceeded {
		t.Fatalf("Expected error code %s, got: %+v", policy.ErrCodeDeadlineExceeded, timeoutDec.Error)
	}

	// 2. Deadline exceeding 200ms SLO bound is rejected immediately
	overBoundDec := ev.Evaluate(context.Background(), policy.BundleEvalInput{
		RequestID:  "req-over-slo",
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 250,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
		},
	})
	if overBoundDec.Allow || overBoundDec.Error == nil || overBoundDec.Error.Code != policy.ErrCodeDeadlineExceeded {
		t.Fatalf("Expected over-bound deadline to fail closed with %s, got: %+v", policy.ErrCodeDeadlineExceeded, overBoundDec)
	}

	// 3. Cancelled context fails closed
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelDec := ev.Evaluate(ctx, policy.BundleEvalInput{
		RequestID:  "req-cancelled",
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
		},
	})
	if cancelDec.Allow || cancelDec.Error == nil || cancelDec.Error.Code != policy.ErrCodeRequestCancelled {
		t.Fatalf("Expected cancelled context to fail closed with %s, got: %+v", policy.ErrCodeRequestCancelled, cancelDec)
	}
}

// TestC08TamperedByteAndUntrustedSignerRejected verifies required negative case 1:
// "One modified byte, missing evidence or a wrong/untrusted signer must not produce trusted success."
func TestC08TamperedByteAndUntrustedSignerRejected(t *testing.T) {
	ev := newTestTrustedEvaluator()
	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")

	// 1. Single modified byte in RegoModule without updating signed digest
	tampered := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	tampered.RegoModule = tampered.RegoModule + "\n# 1-byte-mod"
	if err := ev.LoadBundle(tampered, evalTime); err == nil || err.Code != policy.ErrCodeTamperedBundle {
		t.Fatalf("Expected single-byte modification in RegoModule to fail with %s, got: %v", policy.ErrCodeTamperedBundle, err)
	}

	// 2. Single modified byte in route pattern
	tamperedRoute := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	tamperedRoute.Routes[0].Pattern = "/api/v1/analytics/reportX"
	if err := ev.LoadBundle(tamperedRoute, evalTime); err == nil || err.Code != policy.ErrCodeTamperedBundle {
		t.Fatalf("Expected single-byte modification in route pattern to fail with %s, got: %v", policy.ErrCodeTamperedBundle, err)
	}

	// 3. Untrusted signer key ID
	wrongSigner := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	wrongSigner.SignerKeyID = "ed25519-attacker-key"
	wrongSigner.Digest = policy.ComputeCanonicalBundleDigest(wrongSigner)
	if err := ev.LoadBundle(wrongSigner, evalTime); err == nil || err.Code != policy.ErrCodeUntrustedSigner {
		t.Fatalf("Expected untrusted signer to fail with %s, got: %v", policy.ErrCodeUntrustedSigner, err)
	}

	// 4. Missing signature evidence (SignatureVerified = false)
	unsigned := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	unsigned.SignatureVerified = false
	if err := ev.LoadBundle(unsigned, evalTime); err == nil || err.Code != policy.ErrCodeUntrustedSigner {
		t.Fatalf("Expected unverified signature to fail with %s, got: %v", policy.ErrCodeUntrustedSigner, err)
	}
}

// TestC08ExpiredStaleReplayedRevisionPreservesAuthority verifies required negative case 2:
// "An expired/stale/replayed revision cannot replace the last valid accepted authority."
func TestC08ExpiredStaleReplayedRevisionPreservesAuthority(t *testing.T) {
	ev := newTestTrustedEvaluator()
	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")

	// Load valid revision 2 as authoritative baseline
	rev2 := makeSignedBundle(2, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	if err := ev.LoadBundle(rev2, evalTime); err != nil {
		t.Fatalf("Failed to load initial valid revision 2: %v", err)
	}

	// 1. Attempt to replay revision 2
	if err := ev.LoadBundle(rev2, evalTime); err == nil || err.Code != policy.ErrCodeStaleOrReplayedRevision {
		t.Fatalf("Expected replayed revision 2 to be rejected with %s, got: %v", policy.ErrCodeStaleOrReplayedRevision, err)
	}

	// 2. Attempt to downgrade to stale revision 1
	rev1 := makeSignedBundle(1, "2026-11-03T09:00:00Z", "2026-11-04T09:00:00Z")
	if err := ev.LoadBundle(rev1, evalTime); err == nil || err.Code != policy.ErrCodeStaleOrReplayedRevision {
		t.Fatalf("Expected stale revision 1 to be rejected with %s, got: %v", policy.ErrCodeStaleOrReplayedRevision, err)
	}

	// 3. Attempt to replace with expired revision 3
	expiredRev3 := makeSignedBundle(3, "2026-11-01T10:00:00Z", "2026-11-02T10:00:00Z")
	if err := ev.LoadBundle(expiredRev3, evalTime); err == nil || err.Code != policy.ErrCodeExpiredPolicyBundle {
		t.Fatalf("Expected expired revision 3 to be rejected with %s, got: %v", policy.ErrCodeExpiredPolicyBundle, err)
	}

	// Verify last valid accepted authority (revision 2) is strictly preserved
	if ev.HighestRevision() != 2 {
		t.Fatalf("Expected highest revision to remain 2, got %d", ev.HighestRevision())
	}
	active, ok := ev.ActiveBundle()
	if !ok || active.Digest != rev2.Digest || active.Revision != 2 {
		t.Fatalf("Expected active bundle to remain revision 2 (%s), got: %+v", rev2.Digest, active)
	}
}

// TestC08PrivateResourcesFailClosed verifies required negative case 3:
// "Private resources fail closed"
func TestC08PrivateResourcesFailClosed(t *testing.T) {
	ev := newTestTrustedEvaluator()
	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")
	rev1 := makeSignedBundle(1, "2026-11-03T10:00:00Z", "2026-11-04T10:00:00Z")
	if err := ev.LoadBundle(rev1, evalTime); err != nil {
		t.Fatalf("Failed to load valid bundle: %v", err)
	}

	// 1. Unauthenticated access to explicit private resource
	unauthDec := ev.Evaluate(context.Background(), policy.BundleEvalInput{
		RequestID:  "req-unauth-private",
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "anonymous",
			Authenticated: false,
		},
	})
	if unauthDec.Allow || unauthDec.Error == nil || unauthDec.Error.Code != policy.ErrCodePrivateFailClosed {
		t.Fatalf("Expected unauthenticated access to private resource to fail closed, got: %+v", unauthDec)
	}

	// 2. Unspecified route defaults to private and fails closed even for authenticated operator if no allow rule matches
	unspecDec := ev.Evaluate(context.Background(), policy.BundleEvalInput{
		RequestID:  "req-unspecified-route",
		Path:       "/api/v1/unmapped/internal-vault",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
		},
	})
	if unspecDec.Allow || unspecDec.Classification != policy.ResourceClassPrivate {
		t.Fatalf("Expected unspecified route to default private and fail closed without matching allow rule, got: %+v", unspecDec)
	}
}

// TestC08FixturesIntegration verifies all synthetic fixtures and manifest hashes under tests/fixtures/policyhelix/C08/
func TestC08FixturesIntegration(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "policyhelix", "C08")
	manifestBytes, err := os.ReadFile(filepath.Join(fixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("Failed to read C08 manifest.json: %v", err)
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
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("Failed to unmarshal C08 manifest.json: %v", err)
	}
	if manifest.CommitID != "C08" {
		t.Fatalf("Expected manifest commit_id=C08, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 6 {
		t.Fatalf("Expected at least 6 C08 fixtures, got %d", len(manifest.Fixtures))
	}

	type C08Fixture struct {
		FixtureID          string                    `json:"fixture_id"`
		CommitID           string                    `json:"commit_id"`
		Description        string                    `json:"description"`
		TrustedIssuers     []string                  `json:"trusted_issuers"`
		TrustedSigners     []string                  `json:"trusted_signers"`
		PreloadBundle      *policy.LocalPolicyBundle `json:"preload_bundle,omitempty"`
		CandidateBundle    *policy.LocalPolicyBundle `json:"candidate_bundle,omitempty"`
		Input              policy.BundleEvalInput    `json:"input"`
		Expected           struct {
			Allow            bool   `json:"allow"`
			ErrorCode        string `json:"error_code,omitempty"`
			ReasonCode       string `json:"reason_code"`
			WithinDeadline   bool   `json:"within_deadline"`
			RetainedRevision int64  `json:"retained_revision,omitempty"`
		} `json:"expected"`
	}

	for _, entry := range manifest.Fixtures {
		baseName := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(fixtureDir, baseName))
		if err != nil {
			t.Fatalf("Failed to read fixture %s: %v", baseName, err)
		}

		sum := sha256.Sum256(raw)
		actualHash := hex.EncodeToString(sum[:])
		if actualHash != entry.SHA256 {
			t.Fatalf("Fixture %s hash mismatch: manifest=%s actual=%s", baseName, entry.SHA256, actualHash)
		}

		var fx C08Fixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("Failed to parse fixture %s: %v", baseName, err)
		}

		ev := policy.NewBundleEvaluator(fx.TrustedIssuers, fx.TrustedSigners)
		evalTime, _ := time.Parse(time.RFC3339, fx.Input.EvalTime)

		if fx.PreloadBundle != nil {
			if err := ev.LoadBundle(*fx.PreloadBundle, evalTime); err != nil {
				t.Fatalf("Fixture %s preload_bundle failed unexpectedly: %v", baseName, err)
			}
		}

		if fx.CandidateBundle != nil {
			loadErr := ev.LoadBundle(*fx.CandidateBundle, evalTime)
			if fx.Expected.ErrorCode != "" {
				if loadErr == nil || loadErr.Code != fx.Expected.ErrorCode {
					t.Errorf("Fixture %s expected candidate load error %s, got %v", baseName, fx.Expected.ErrorCode, loadErr)
				}
			}
			if fx.Expected.RetainedRevision > 0 && ev.HighestRevision() != fx.Expected.RetainedRevision {
				t.Errorf("Fixture %s expected retained revision %d, got %d", baseName, fx.Expected.RetainedRevision, ev.HighestRevision())
			}
		}

		dec := ev.Evaluate(context.Background(), fx.Input)
		if dec.Allow != fx.Expected.Allow {
			t.Errorf("Fixture %s: expected allow=%v, got %v (err=%v, reasons=%v)", baseName, fx.Expected.Allow, dec.Allow, dec.Error, dec.Reasons)
		}
		if dec.WithinDeadline != fx.Expected.WithinDeadline {
			t.Errorf("Fixture %s: expected within_deadline=%v, got %v", baseName, fx.Expected.WithinDeadline, dec.WithinDeadline)
		}
		if fx.Expected.ErrorCode != "" && fx.CandidateBundle == nil {
			if dec.Error == nil || dec.Error.Code != fx.Expected.ErrorCode {
				t.Errorf("Fixture %s: expected error_code=%s, got %+v", baseName, fx.Expected.ErrorCode, dec.Error)
			}
		}
		if len(dec.Reasons) == 0 || dec.Reasons[0] != fx.Expected.ReasonCode {
			t.Errorf("Fixture %s: expected primary reason_code=%s, got %v", baseName, fx.Expected.ReasonCode, dec.Reasons)
		}
	}
}
