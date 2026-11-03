package policy

import (
	"testing"
)

func TestModelUnit(t *testing.T) {
	reg, err := NewRouteRegistry(
		RouteRule{
			Pattern:              "/health",
			Action:               "read",
			Classification:       ResourceClassPublic,
			AllowUnauthenticated: true,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	rule, ok := reg.Resolve("/health", "read")
	if !ok || rule.Classification != ResourceClassPublic {
		t.Errorf("Expected explicit public route, got: %+v (ok=%v)", rule, ok)
	}

	unspec, ok := reg.Resolve("/secret", "read")
	if ok || unspec.Classification != ResourceClassPrivate {
		t.Errorf("Expected unspecified route to default private, got: %+v (ok=%v)", unspec, ok)
	}
}
