package policy

import (
	"context"
	"testing"
	"time"
)

func buildValidTestBundle(rev int64) LocalPolicyBundle {
	b := LocalPolicyBundle{
		SchemaVersion:     "1",
		BundleID:          "bundle-analytics-v1",
		Package:           "policyhelix.authz",
		Issuer:            "https://issuer.policyhelix.local",
		SignerKeyID:       "ed25519-primary-2026",
		Signature:         "ed25519:7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
		SignatureVerified: true,
		Revision:          rev,
		IssuedAt:          "2026-11-03T10:00:00Z",
		ExpiresAt:         "2026-11-04T10:00:00Z",
		RegoModule:        "package policyhelix.authz\ndefault allow = false\nallow { input.subject.authenticated == true }",
		Routes: []RouteRule{
			{
				Pattern:              "/api/v1/analytics/reports",
				Action:               "read",
				Classification:       ResourceClassPrivate,
				AllowUnauthenticated: false,
				RequiredRoles:        []string{"operator", "admin"},
			},
			{
				Pattern:              "/healthz",
				Action:               "read",
				Classification:       ResourceClassPublic,
				AllowUnauthenticated: true,
			},
		},
		Rules: []PolicyRule{
			{
				ID:            "rule-operator-analytics-read",
				Effect:        "allow",
				PathPattern:   "/api/v1/analytics/reports",
				Actions:       []string{"read"},
				Roles:         []string{"operator", "admin"},
				ResourceClass: ResourceClassPrivate,
				ReasonCode:    "policy_allow_role_operator",
				Obligations: []PolicyObligation{
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
				ResourceClass: ResourceClassPublic,
				ReasonCode:    ReasonExplicitPublicAllow,
			},
		},
	}
	b.Digest = ComputeCanonicalBundleDigest(b)
	return b
}

func TestBundleEvaluatorUnit(t *testing.T) {
	evalTime, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:00Z")
	ev := NewBundleEvaluator(
		[]string{"https://issuer.policyhelix.local"},
		[]string{"ed25519-primary-2026"},
	)

	b := buildValidTestBundle(1)
	if err := ev.LoadBundle(b, evalTime); err != nil {
		t.Fatalf("Expected valid bundle to load, got error: %v", err)
	}

	dec := ev.Evaluate(context.Background(), BundleEvalInput{
		RequestID:  "req-unit-1",
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   "2026-11-03T12:00:00Z",
		Subject: SubjectIdentity{
			ID:            "subj-operator-1",
			Issuer:        "https://issuer.policyhelix.local",
			Roles:         []string{"operator"},
			Authenticated: true,
		},
	})
	if !dec.Allow {
		t.Fatalf("Expected allow=true for operator, got false: %+v", dec)
	}
	if dec.PolicyDigest != b.Digest {
		t.Errorf("Expected policy digest %s, got %s", b.Digest, dec.PolicyDigest)
	}
}
