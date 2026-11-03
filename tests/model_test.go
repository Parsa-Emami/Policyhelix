package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/policy"
)

// setupStandardRegistry creates a test route registry with explicit public routes.
func setupStandardRegistry(t *testing.T) *policy.RouteRegistry {
	reg, err := policy.NewRouteRegistry(
		policy.RouteRule{
			Pattern:              "/healthz",
			Action:               "read",
			Classification:       policy.ResourceClassPublic,
			AllowUnauthenticated: true,
			Description:          "Explicit public health endpoint",
		},
		policy.RouteRule{
			Pattern:              "/status",
			Action:               "read",
			Classification:       policy.ResourceClassPublic,
			AllowUnauthenticated: true,
			Description:          "Explicit public status endpoint",
		},
		policy.RouteRule{
			Pattern:              "/api/v1/vault/secrets",
			Action:               "read",
			Classification:       policy.ResourceClassPrivate,
			AllowUnauthenticated: false,
			RequiredRoles:        []string{"operator", "admin"},
			Description:          "Private secrets vault",
		},
		policy.RouteRule{
			Pattern:              "/api/v1/admin/*",
			Action:               "*",
			Classification:       policy.ResourceClassRestricted,
			AllowUnauthenticated: false,
			RequiredRoles:        []string{"admin"},
			Description:          "Restricted admin subtree",
		},
	)
	if err != nil {
		t.Fatalf("Failed to initialize RouteRegistry: %v", err)
	}
	return reg
}

// TestPublicRoutesExplicitConfiguration verifies that public routes can only be
// established via explicit configuration, and cannot be accidentally created.
func TestPublicRoutesExplicitConfiguration(t *testing.T) {
	// Attempting to register an unauthenticated route with non-public class must fail
	err := (&policy.RouteRegistry{}).Register(policy.RouteRule{
		Pattern:              "/invalid",
		Classification:       policy.ResourceClassPrivate,
		AllowUnauthenticated: true,
	})
	if err == nil {
		t.Fatalf("Expected error when registering unauthenticated route as non-public class, got nil")
	}

	reg := setupStandardRegistry(t)

	// Explicit public route resolves as explicit and public
	rule, explicit := reg.Resolve("/healthz", "read")
	if !explicit {
		t.Errorf("Expected /healthz to be explicitly resolved")
	}
	if rule.Classification != policy.ResourceClassPublic {
		t.Errorf("Expected /healthz classification to be public, got: %s", rule.Classification)
	}
	if !rule.AllowUnauthenticated {
		t.Errorf("Expected /healthz to allow unauthenticated")
	}
}

// TestUnspecifiedRoutesDefaultPrivate verifies Requirement F01:
// All unspecified routes strictly default to private classification.
func TestUnspecifiedRoutesDefaultPrivate(t *testing.T) {
	reg := setupStandardRegistry(t)

	unspecifiedPaths := []string{
		"/unknown",
		"/api/unmapped",
		"/internal/metrics",
		"/admin/dashboard",
		"/anything/at/all",
	}

	for _, path := range unspecifiedPaths {
		rule, explicit := reg.Resolve(path, "read")
		if explicit {
			t.Errorf("Path %s was unexpectedly marked as explicitly registered", path)
		}
		if rule.Classification != policy.ResourceClassPrivate {
			t.Errorf("Unspecified route %s must default to private, got %s", path, rule.Classification)
		}
		if rule.AllowUnauthenticated {
			t.Errorf("Unspecified route %s must not allow unauthenticated access", path)
		}

		// Evaluating unauthenticated access against unspecified route must fail closed
		evalOut := reg.EvaluateRoute(policy.EvaluationInput{
			Path:   path,
			Action: "read",
			Subject: policy.SubjectIdentity{
				ID:            "anonymous",
				Authenticated: false,
			},
		})
		if evalOut.Allow {
			t.Errorf("Security invariant violated: unspecified route %s allowed unauthenticated access", path)
		}
		if evalOut.Classification != policy.ResourceClassPrivate {
			t.Errorf("Evaluation of unspecified route %s expected private class, got: %s", path, evalOut.Classification)
		}
		if evalOut.ReasonCode != policy.ReasonUnspecifiedRouteDeny {
			t.Errorf("Expected reason code %s, got %s", policy.ReasonUnspecifiedRouteDeny, evalOut.ReasonCode)
		}
	}
}

// TestPrivateResourcesFailClosed verifies that unauthenticated access
// to private, internal, or restricted resources fails closed.
func TestPrivateResourcesFailClosed(t *testing.T) {
	reg := setupStandardRegistry(t)

	anonSubject := policy.SubjectIdentity{
		ID:            "anon_user",
		Authenticated: false,
	}

	// 1. Explicit private endpoint
	out := reg.EvaluateRoute(policy.EvaluationInput{
		Path:    "/api/v1/vault/secrets",
		Action:  "read",
		Subject: anonSubject,
	})
	if out.Allow {
		t.Errorf("Private endpoint allowed unauthenticated access")
	}
	if out.ReasonCode != policy.ReasonUnauthenticatedDeny {
		t.Errorf("Expected ReasonUnauthenticatedDeny, got: %s", out.ReasonCode)
	}

	// 2. Restricted prefix endpoint
	outRestricted := reg.EvaluateRoute(policy.EvaluationInput{
		Path:    "/api/v1/admin/users",
		Action:  "read",
		Subject: anonSubject,
	})
	if outRestricted.Allow {
		t.Errorf("Restricted endpoint allowed unauthenticated access")
	}

	// 3. Authenticated but insufficient role
	guestSubject := policy.SubjectIdentity{
		ID:            "guest_user",
		Roles:         []string{"viewer"},
		Authenticated: true,
	}
	outRole := reg.EvaluateRoute(policy.EvaluationInput{
		Path:    "/api/v1/vault/secrets",
		Action:  "read",
		Subject: guestSubject,
	})
	if outRole.Allow {
		t.Errorf("Private secrets allowed user with viewer role")
	}
	if outRole.ReasonCode != policy.ReasonInsufficientRoles {
		t.Errorf("Expected ReasonInsufficientRoles, got: %s", outRole.ReasonCode)
	}

	// 4. Authenticated with required role succeeds
	opSubject := policy.SubjectIdentity{
		ID:            "op_user",
		Roles:         []string{"operator"},
		Authenticated: true,
	}
	outOp := reg.EvaluateRoute(policy.EvaluationInput{
		Path:    "/api/v1/vault/secrets",
		Action:  "read",
		Subject: opSubject,
	})
	if !outOp.Allow {
		t.Errorf("Operator was denied access to secrets: %+v", outOp)
	}
}

// TestC07FixturesIntegration exercises all synthetic fixtures under tests/fixtures/policyhelix/C07/
func TestC07FixturesIntegration(t *testing.T) {
	reg := setupStandardRegistry(t)
	fixtureDir := filepath.Join("fixtures", "policyhelix", "C07")

	fixtureFiles := []string{
		"positive-explicit-public-allow.json",
		"positive-authenticated-private-allow.json",
		"negative-unspecified-route-fails-closed.json",
		"negative-unauthenticated-private-denied.json",
	}

	type FixtureSchema struct {
		Path     string                 `json:"path"`
		Action   string                 `json:"action"`
		Subject  policy.SubjectIdentity `json:"subject"`
		Expected struct {
			Allow          bool   `json:"allow"`
			Classification string `json:"classification"`
			IsExplicit     bool   `json:"is_explicit"`
			ReasonCode     string `json:"reason_code"`
		} `json:"expected"`
	}

	for _, fileName := range fixtureFiles {
		bytes, err := os.ReadFile(filepath.Join(fixtureDir, fileName))
		if err != nil {
			t.Fatalf("Failed to read fixture %s: %v", fileName, err)
		}
		var f FixtureSchema
		if err := json.Unmarshal(bytes, &f); err != nil {
			t.Fatalf("Failed to parse fixture %s: %v", fileName, err)
		}

		out := reg.EvaluateRoute(policy.EvaluationInput{
			Path:    f.Path,
			Action:  f.Action,
			Subject: f.Subject,
		})

		if out.Allow != f.Expected.Allow {
			t.Errorf("Fixture %s: expected allow=%v, got allow=%v (reason: %s)", fileName, f.Expected.Allow, out.Allow, out.ReasonMessage)
		}
		if string(out.Classification) != f.Expected.Classification {
			t.Errorf("Fixture %s: expected classification=%s, got %s", fileName, f.Expected.Classification, out.Classification)
		}
		if out.IsExplicit != f.Expected.IsExplicit {
			t.Errorf("Fixture %s: expected is_explicit=%v, got %v", fileName, f.Expected.IsExplicit, out.IsExplicit)
		}
		if out.ReasonCode != f.Expected.ReasonCode {
			t.Errorf("Fixture %s: expected reason_code=%s, got %s", fileName, f.Expected.ReasonCode, out.ReasonCode)
		}
	}
}

// TestRestartInvariance verifies that restarting and reconstructing the route registry
// produces identical route classification and evaluation decisions.
func TestRestartInvariance(t *testing.T) {
	reg1 := setupStandardRegistry(t)
	reg2 := setupStandardRegistry(t)

	testCases := []struct {
		path    string
		action  string
		subject policy.SubjectIdentity
	}{
		{"/healthz", "read", policy.SubjectIdentity{Authenticated: false}},
		{"/status", "read", policy.SubjectIdentity{Authenticated: false}},
		{"/api/v1/vault/secrets", "read", policy.SubjectIdentity{Authenticated: false}},
		{"/api/v1/vault/secrets", "read", policy.SubjectIdentity{Authenticated: true, Roles: []string{"operator"}}},
		{"/unmapped/resource/1", "read", policy.SubjectIdentity{Authenticated: false}},
		{"/unmapped/resource/2", "write", policy.SubjectIdentity{Authenticated: true, Roles: []string{"admin"}}},
	}

	for _, tc := range testCases {
		out1 := reg1.EvaluateRoute(policy.EvaluationInput{Path: tc.path, Action: tc.action, Subject: tc.subject})
		out2 := reg2.EvaluateRoute(policy.EvaluationInput{Path: tc.path, Action: tc.action, Subject: tc.subject})

		if out1 != out2 {
			t.Fatalf("Restart invariance violated for path %s: instance1=%+v, instance2=%+v", tc.path, out1, out2)
		}
	}
}
