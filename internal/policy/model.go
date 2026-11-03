package policy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ResourceClass defines the security classification of a system resource or route.
type ResourceClass string

const (
	// ResourceClassPublic indicates resources accessible without authentication when explicitly declared.
	ResourceClassPublic ResourceClass = "public"
	// ResourceClassInternal indicates resources accessible only within the authenticated local boundary.
	ResourceClassInternal ResourceClass = "internal"
	// ResourceClassPrivate indicates private resources requiring authenticated operator/subject identity.
	// All unspecified routes strictly default to this classification.
	ResourceClassPrivate ResourceClass = "private"
	// ResourceClassRestricted indicates sensitive resources requiring elevated roles or step-up verification.
	ResourceClassRestricted ResourceClass = "restricted"
)

// IsValid checks whether a ResourceClass string is recognized.
func (rc ResourceClass) IsValid() bool {
	switch rc {
	case ResourceClassPublic, ResourceClassInternal, ResourceClassPrivate, ResourceClassRestricted:
		return true
	default:
		return false
	}
}

// RouteRule defines explicit routing access policy for a path and action.
type RouteRule struct {
	Pattern             string        `json:"pattern"`
	Action              string        `json:"action"` // "read", "write", "execute", "*"
	Classification      ResourceClass `json:"classification"`
	AllowUnauthenticated bool         `json:"allow_unauthenticated"`
	RequiredRoles       []string      `json:"required_roles,omitempty"`
	Description         string        `json:"description,omitempty"`
}

// RouteRegistry manages route rules with thread safety and enforces the F01 invariant:
// public routes are explicit configuration and all unspecified routes default private.
type RouteRegistry struct {
	mu     sync.RWMutex
	routes map[string]RouteRule // key: action + ":" + pattern
}

// NewRouteRegistry constructs a registry with the provided explicit route rules.
func NewRouteRegistry(explicitRoutes ...RouteRule) (*RouteRegistry, error) {
	reg := &RouteRegistry{
		routes: make(map[string]RouteRule),
	}
	for _, r := range explicitRoutes {
		if err := reg.Register(r); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// Register adds an explicit route rule to the registry.
func (r *RouteRegistry) Register(rule RouteRule) error {
	if rule.Pattern == "" {
		return errors.New("route pattern cannot be empty")
	}
	if !rule.Classification.IsValid() {
		return fmt.Errorf("invalid route classification: %s", rule.Classification)
	}
	// An unauthenticated route MUST be explicitly classified as public.
	if rule.AllowUnauthenticated && rule.Classification != ResourceClassPublic {
		return fmt.Errorf("route '%s' allows unauthenticated access but is classified as '%s'; only public routes may allow unauthenticated access", rule.Pattern, rule.Classification)
	}

	action := strings.ToLower(rule.Action)
	if action == "" {
		action = "*"
	}
	rule.Action = action

	r.mu.Lock()
	defer r.mu.Unlock()
	key := action + ":" + rule.Pattern
	r.routes[key] = rule
	return nil
}

// Resolve looks up the route classification and rule for a given path and action.
// If the path/action is not explicitly registered, it strictly returns a default
// private rule (Requirement F01: all unspecified routes default private).
func (r *RouteRegistry) Resolve(path, action string) (RouteRule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	normalizedAction := strings.ToLower(action)
	if normalizedAction == "" {
		normalizedAction = "read"
	}

	// 1. Try exact action match
	if rule, found := r.routes[normalizedAction+":"+path]; found {
		return rule, true
	}

	// 2. Try wildcard action match
	if rule, found := r.routes["*:"+path]; found {
		return rule, true
	}

	// 3. Try prefix matching for registered directory/path prefixes
	for _, rule := range r.routes {
		if rule.Action == "*" || rule.Action == normalizedAction {
			if strings.HasSuffix(rule.Pattern, "/*") {
				prefix := strings.TrimSuffix(rule.Pattern, "/*")
				if strings.HasPrefix(path, prefix) {
					return rule, true
				}
			}
		}
	}

	// F01 Default: All unspecified routes default to private fail-closed
	return RouteRule{
		Pattern:             path,
		Action:              normalizedAction,
		Classification:      ResourceClassPrivate,
		AllowUnauthenticated: false,
		Description:         "Unspecified route default-private rule",
	}, false
}

// SubjectIdentity represents the normalized caller identity entering policy evaluation.
type SubjectIdentity struct {
	ID            string   `json:"id"`
	Issuer        string   `json:"issuer"`
	Roles         []string `json:"roles"`
	Authenticated bool     `json:"authenticated"`
	SessionEpoch  int64    `json:"session_epoch"`
}

// HasRole checks whether the subject possesses a specific role.
func (s SubjectIdentity) HasRole(role string) bool {
	for _, r := range s.Roles {
		if r == role || r == "admin" || r == "platform_admin" {
			return true
		}
	}
	return false
}

// EvaluationInput is the strongly typed input for route and resource access evaluation.
type EvaluationInput struct {
	Path        string          `json:"path"`
	Action      string          `json:"action"`
	Subject     SubjectIdentity `json:"subject"`
	ResourceID  string          `json:"resource_id,omitempty"`
	OwnerScope  string          `json:"owner_scope,omitempty"`
}

// EvaluationOutput is the outcome of the policy access evaluation.
type EvaluationOutput struct {
	Allow          bool          `json:"allow"`
	Classification ResourceClass `json:"classification"`
	IsExplicit     bool          `json:"is_explicit"`
	ReasonCode     string        `json:"reason_code"`
	ReasonMessage  string        `json:"reason_message"`
}

// Reason codes
const (
	ReasonExplicitPublicAllow  = "EXPLICIT_PUBLIC_ALLOW"
	ReasonAuthenticatedAllow   = "AUTHENTICATED_ALLOW"
	ReasonUnauthenticatedDeny  = "UNAUTHENTICATED_DENY"
	ReasonInsufficientRoles    = "INSUFFICIENT_ROLES"
	ReasonUnspecifiedRouteDeny = "UNSPECIFIED_ROUTE_DEFAULT_PRIVATE_DENY"
)

// EvaluateRoute evaluates route access against the registry, enforcing fail-closed
// semantics on unauthenticated or unauthorized access to private, internal, or unspecified routes.
func (r *RouteRegistry) EvaluateRoute(input EvaluationInput) EvaluationOutput {
	if input.Path == "" {
		return EvaluationOutput{
			Allow:          false,
			Classification: ResourceClassPrivate,
			IsExplicit:     false,
			ReasonCode:     ReasonUnauthenticatedDeny,
			ReasonMessage:  "Route path cannot be empty; default private deny",
		}
	}

	rule, explicit := r.Resolve(input.Path, input.Action)

	// Case 1: Explicit public route allowing unauthenticated access
	if explicit && rule.Classification == ResourceClassPublic && rule.AllowUnauthenticated {
		return EvaluationOutput{
			Allow:          true,
			Classification: ResourceClassPublic,
			IsExplicit:     true,
			ReasonCode:     ReasonExplicitPublicAllow,
			ReasonMessage:  "Explicit public route allows access",
		}
	}

	// Case 2: Subject is not authenticated
	if !input.Subject.Authenticated {
		if !explicit {
			return EvaluationOutput{
				Allow:          false,
				Classification: ResourceClassPrivate,
				IsExplicit:     false,
				ReasonCode:     ReasonUnspecifiedRouteDeny,
				ReasonMessage:  "Unspecified route defaults to private; unauthenticated access denied",
			}
		}
		return EvaluationOutput{
			Allow:          false,
			Classification: rule.Classification,
			IsExplicit:     true,
			ReasonCode:     ReasonUnauthenticatedDeny,
			ReasonMessage:  fmt.Sprintf("Route classified as '%s' requires authenticated identity", rule.Classification),
		}
	}

	// Case 3: Subject is authenticated, check role constraints if specified on rule
	if len(rule.RequiredRoles) > 0 {
		hasRequired := false
		for _, reqRole := range rule.RequiredRoles {
			if input.Subject.HasRole(reqRole) {
				hasRequired = true
				break
			}
		}
		if !hasRequired {
			return EvaluationOutput{
				Allow:          false,
				Classification: rule.Classification,
				IsExplicit:     explicit,
				ReasonCode:     ReasonInsufficientRoles,
				ReasonMessage:  fmt.Sprintf("Subject lacks required roles: %v", rule.RequiredRoles),
			}
		}
	}

	// Case 4: Authenticated with sufficient privileges
	return EvaluationOutput{
		Allow:          true,
		Classification: rule.Classification,
		IsExplicit:     explicit,
		ReasonCode:     ReasonAuthenticatedAllow,
		ReasonMessage:  "Authenticated access granted",
	}
}
