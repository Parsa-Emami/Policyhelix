package reference

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/gateway"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

// The reference workflow is the locally usable product path proven by C30. It wires the accepted
// domain engines together against durable local storage, an owned synthetic upstream and a
// synthetic local OIDC-compatible session issuer. Nothing here is a placeholder: every stage
// performs the same verification the corresponding domain engine performs for its own fixtures.
const (
	EngineName               = "policyhelix-engine"
	EngineVersion            = "0.0.1"
	ReferenceIssuer          = "https://idp.policyhelix.local"
	ReferenceBundleIssuer    = "https://issuer.policyhelix.local"
	ReferenceSignerKeyID     = "ed25519-reference-2026"
	ReferenceSubjectID       = "usr-local-operator"
	ReferenceOwnerScope      = "tenant:default"
	ReferenceUpstreamPath    = "/api/v1/analytics/reports"
	ReferenceUpstreamHealth  = "/health"
	referenceSigningSeedHex  = "eacde9a8fce5201e3e5f1d891df7df833307fd17a45907c3265910d2406d2a7b"
	referenceSelfTestSeedHex = "b6d4d7f4a2d84e2bb8a1c9dc2e6fbb4c3f0e1d9a7c6b512c8f2e3a4b5c6d7e8f"
	referenceRegoModule      = "package policyhelix.authz\ndefault allow = false\nallow { input.subject.authenticated == true }"
	referenceMaxRequestBody  = 1 << 20
	referenceSessionTTL      = 2 * time.Hour
)

// SigningKey returns the deterministic synthetic signing key used by the local reference
// workflow. It is deliberately public test material, not a deployment secret.
func SigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return bundles.DeriveKeyPairFromSeedHex(referenceSigningSeedHex)
}

// TrustedKey is the deterministic trust anchor for the local reference workflow.
func TrustedKey() (bundles.TrustedKey, error) {
	pub, _, err := SigningKey()
	if err != nil {
		return bundles.TrustedKey{}, err
	}
	return bundles.TrustedKey{
		SignerKeyID:  ReferenceSignerKeyID,
		Issuer:       ReferenceBundleIssuer,
		PublicKeyHex: hex.EncodeToString(pub),
	}, nil
}

// SessionRequest is the typed input for issuing a local reference session.
type SessionRequest struct {
	SubjectID string   `json:"subject_id,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
}

// SessionResponse reports a really issued, fingerprint-bound, revocable session.
type SessionResponse struct {
	Valid            bool     `json:"valid"`
	SessionID        string   `json:"session_id,omitempty"`
	SubjectID        string   `json:"subject_id,omitempty"`
	Issuer           string   `json:"issuer,omitempty"`
	Roles            []string `json:"roles,omitempty"`
	OwnerScope       string   `json:"owner_scope,omitempty"`
	SessionEpoch     int64    `json:"session_epoch,omitempty"`
	ExpiresAt        string   `json:"expires_at,omitempty"`
	IssuerMode       string   `json:"issuer_mode,omitempty"`
	StaleWindowSecs  int      `json:"stale_window_seconds,omitempty"`
	ErrorCode        string   `json:"error_code,omitempty"`
	ErrorMessage     string   `json:"error_message,omitempty"`
	StorageDurable   bool     `json:"storage_durable"`
	SetCookiePresent bool     `json:"set_cookie_present"`
}

// SimulateRequest evaluates a synthetic decision fixture against the live active bundle.
type SimulateRequest struct {
	FixtureRef string `json:"fixture_ref,omitempty"`
	Path       string `json:"path,omitempty"`
}

// SimulateResponse reports the fixture expectation next to the live decision.
type SimulateResponse struct {
	FixtureRef      string                 `json:"fixture_ref"`
	FixtureID       string                 `json:"fixture_id,omitempty"`
	ExpectedAllow   *bool                  `json:"expected_allow,omitempty"`
	ObservedAllow   bool                   `json:"observed_allow"`
	ExpectedMatched bool                   `json:"expected_matched"`
	ObservedReasons []string               `json:"observed_reasons,omitempty"`
	Decision        *policy.BundleDecision `json:"decision,omitempty"`
	ErrorCode       string                 `json:"error_code,omitempty"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
}

// BundleRequest controls the signed bundle activation stage.
type BundleRequest struct {
	Expired bool `json:"expired,omitempty"`
}

// BundleResponse reports signature, freshness, monotonic revision and activation outcome.
type BundleResponse struct {
	Status               string                  `json:"status"`
	Accepted             bool                    `json:"accepted"`
	Active               bool                    `json:"active"`
	Replayed             bool                    `json:"replayed"`
	BundleID             string                  `json:"bundle_id,omitempty"`
	Revision             int64                   `json:"revision,omitempty"`
	HighestRevision      int64                   `json:"highest_revision,omitempty"`
	Digest               string                  `json:"digest,omitempty"`
	Signature            string                  `json:"signature,omitempty"`
	SignatureVerified    bool                    `json:"signature_verified"`
	IssuedAt             string                  `json:"issued_at,omitempty"`
	ExpiresAt            string                  `json:"expires_at,omitempty"`
	MonotonicRevision    bool                    `json:"monotonic_revision_enforced"`
	Durable              bool                    `json:"durable"`
	ErrorCode            string                  `json:"error_code,omitempty"`
	Message              string                  `json:"message,omitempty"`
	ActiveBundleRetained bool                    `json:"active_bundle_retained"`
	State                bundles.KeyRotationState `json:"state"`
}

// ProxyRequest drives the protected-upstream stage.
type ProxyRequest struct {
	SessionID      string            `json:"session_id,omitempty"`
	Path           string            `json:"path,omitempty"`
	Method         string            `json:"method,omitempty"`
	ForgedHeaders  map[string]string `json:"forged_headers,omitempty"`
	ProviderState  string            `json:"provider_state,omitempty"`
	DecisionState  string            `json:"decision_engine_state,omitempty"`
	Classification string            `json:"resource_classification,omitempty"`
}

// ProxyResponse carries the typed access check, proxy and policy authority outcomes.
type ProxyResponse struct {
	Allow           bool                    `json:"allow"`
	Valid           bool                    `json:"valid"`
	Forwarded       bool                    `json:"forwarded_to_upstream"`
	StatusCode      int                     `json:"status_code"`
	ErrorCode       string                  `json:"error_code,omitempty"`
	ErrorMessage    string                  `json:"error_message,omitempty"`
	UpstreamStatus  int                     `json:"upstream_status_code,omitempty"`
	UpstreamBody    string                  `json:"upstream_response_body,omitempty"`
	StrippedHeaders []string                `json:"stripped_headers,omitempty"`
	InjectedHeaders map[string]string       `json:"downstream_injected_headers,omitempty"`
	AccessCheck     *auth.AccessCheckResult `json:"access_check,omitempty"`
	Decision        *policy.BundleDecision  `json:"decision,omitempty"`
	Proxy           *gateway.ProxyResult    `json:"proxy,omitempty"`
}

// SpoofResponse proves spoofed identity headers and direct origin access are denied.
type SpoofResponse struct {
	SpoofedAllow     bool                       `json:"spoofed_allow"`
	SpoofedErrorCode string                     `json:"spoofed_error_code"`
	SpoofedError     string                     `json:"spoofed_error_message"`
	SpoofedForwarded bool                       `json:"spoofed_forwarded_to_upstream"`
	SpoofedStripped  []string                   `json:"spoofed_stripped_headers,omitempty"`
	Direct           *gateway.DirectOriginProbe `json:"direct_origin"`
	DirectBlocked    bool                       `json:"direct_origin_blocked"`
	DirectStatus     int                        `json:"direct_origin_status_code"`
	DirectBody       string                     `json:"direct_origin_body,omitempty"`
}

// RevokeResponse proves the revocation epoch stopped subsequent access.
type RevokeResponse struct {
	Revoked             bool    `json:"revoked"`
	SessionID           string  `json:"session_id"`
	Reason              string  `json:"reason,omitempty"`
	RevokedAt           string  `json:"revoked_at,omitempty"`
	MaxStaleSeconds     int     `json:"max_stale_seconds"`
	StoppedWithinBound  bool    `json:"stopped_within_bound"`
	ElapsedSinceRevoke  float64 `json:"elapsed_since_revoke_seconds"`
	SubsequentAllow     bool    `json:"subsequent_allow"`
	SubsequentErrorCode string  `json:"subsequent_error_code,omitempty"`
	SubsequentMessage   string  `json:"subsequent_error_message,omitempty"`
	SideEffectsExecuted bool    `json:"side_effects_executed"`
	ErrorCode           string  `json:"error_code,omitempty"`
	ErrorMessage        string  `json:"error_message,omitempty"`
}

// OutageResponse proves decision-engine, IdP and expired-bundle fail-closed behavior.
type OutageResponse struct {
	DecisionOutageAllow    bool   `json:"decision_outage_allow"`
	DecisionOutageCode     string `json:"decision_outage_error_code"`
	DecisionOutageMessage  string `json:"decision_outage_message"`
	IdPOutageAllow         bool   `json:"idp_outage_allow"`
	IdPOutageCode          string `json:"idp_outage_error_code"`
	ExpiredBundleAccepted  bool   `json:"expired_bundle_accepted"`
	ExpiredBundleErrorCode string `json:"expired_bundle_error_code,omitempty"`
	ExpiredBundleMessage   string `json:"expired_bundle_message,omitempty"`
	ActiveBundleRetained   bool   `json:"active_bundle_retained"`
	ActiveRevision         int64  `json:"active_revision"`
	PublicHealthStillOK    bool   `json:"public_health_bypass_ok"`
}

// BundleSummary is the restart-safe projection of the active bundle.
type BundleSummary struct {
	BundleID      string `json:"bundle_id"`
	Revision      int64  `json:"revision"`
	Digest        string `json:"digest"`
	SignerKeyID   string `json:"signer_key_id"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
	RemainingSecs int64  `json:"remaining_seconds"`
}

// StateResponse reports durable restart/restore-visible workflow state.
type StateResponse struct {
	Status             string                     `json:"status"`
	Ready              bool                       `json:"ready"`
	Engine             string                     `json:"engine"`
	Version            string                     `json:"version"`
	StorageDurable     bool                       `json:"storage_durable"`
	StorageRevision    int64                      `json:"storage_revision"`
	ActiveBundle       *BundleSummary             `json:"active_bundle,omitempty"`
	HighestRevision    int64                      `json:"highest_revision"`
	TrustedKeyIDs      []string                   `json:"trusted_key_ids"`
	IssuerMode         string                     `json:"issuer_mode"`
	SessionCount       int                        `json:"session_count"`
	RevokedSessionIDs  []string                   `json:"revoked_session_ids"`
	StaleWindowSeconds int                        `json:"stale_window_seconds"`
	Upstream           gateway.UpstreamProbe      `json:"upstream"`
	Providers          []gateway.ProviderReadiness `json:"providers"`
	CheckedAt          string                     `json:"checked_at"`
}

type referenceOrigin struct {
	server   *http.Server
	listener net.Listener
	url      string
}

// startReferenceOrigin starts the owned synthetic upstream on loopback. It accepts only requests
// carrying a valid gateway origin proof; direct access is rejected by real HTTP status, not a fixture.
func startReferenceOrigin() (*referenceOrigin, error) {
	mux := http.NewServeMux()
	mux.HandleFunc(ReferenceUpstreamHealth, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service": gateway.DefaultAllowlistedUpstreamID,
			"status":  "ok",
			"owner":   ReferenceOwnerScope,
		})
	})
	protected := gateway.ProtectedOriginMiddleware(gateway.DefaultGatewayProofSecret)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated := r.Header.Get(gateway.HeaderPolicyHelixAuthenticated)
		if !strings.EqualFold(authenticated, "true") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"allow":      false,
				"error_code": gateway.ErrCodeDirectOriginBypass,
				"message":    "Fail closed: normalized authenticated identity is required",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":        gateway.DefaultAllowlistedUpstreamID,
			"status":         "ok",
			"report":         "synthetic-quarterly-analytics",
			"path":           r.URL.Path,
			"subject":        r.Header.Get(gateway.HeaderPolicyHelixSubject),
			"issuer":         r.Header.Get(gateway.HeaderPolicyHelixIssuer),
			"roles":          r.Header.Get(gateway.HeaderPolicyHelixRoles),
			"owner_scope":    r.Header.Get(gateway.HeaderPolicyHelixTenantID),
			"session_epoch":  r.Header.Get(gateway.HeaderPolicyHelixSessionEpoch),
			"classification": "private",
			"license":        "Apache-2.0 synthetic repository-authored fixture",
		})
	}))
	mux.Handle("/api/v1/analytics/", protected)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind owned synthetic upstream on loopback: %w", err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() { _ = srv.Serve(listener) }()
	return &referenceOrigin{server: srv, listener: listener, url: "http://" + listener.Addr().String()}, nil
}

func (o *referenceOrigin) close() {
	if o == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = o.server.Shutdown(ctx)
}

// Runtime owns the live workflow state across browser requests and process restarts.
type Runtime struct {
	mu sync.Mutex

	adapter      *storage.Adapter
	storageDir   string
	sessionStore auth.SessionStore
	revStore     auth.RevocationStore
	sessionMgr   *auth.SessionManager
	enforcer     *auth.RevocationEnforcer
	keys         *bundles.KeyRotationManager
	upstream     *gateway.UpstreamConfig
	proxy        *gateway.AllowlistedGatewayProxy
	transport    http.RoundTripper
	origin       *referenceOrigin

	lastSessionID string
}

// NewRuntime initializes the live workflow against durable storage and a real loopback
// upstream. A nil adapter keeps the runtime usable but not durable; the caller must report that.
// When keys is nil the runtime owns its own manager; otherwise it shares the engine's durable
// trust/activation manager so the reference workflow and the key-state endpoints cannot diverge.
func NewRuntime(adapter *storage.Adapter, storageDir string, keys *bundles.KeyRotationManager) (*Runtime, error) {
	trusted, err := TrustedKey()
	if err != nil {
		return nil, fmt.Errorf("failed to derive reference trust anchor: %w", err)
	}
	origin, err := startReferenceOrigin()
	if err != nil {
		return nil, err
	}

	rt := &Runtime{
		adapter:    adapter,
		storageDir: storageDir,
		origin:     origin,
		transport:  http.DefaultTransport,
	}

	if adapter != nil {
		rt.sessionStore = auth.NewStorageSessionStore(adapter)
		rt.revStore = auth.NewStorageRevocationStore(adapter)
	} else {
		rt.sessionStore = auth.NewMemorySessionStore()
		rt.revStore = auth.NewMemoryRevocationStore()
	}
	if keys != nil {
		rt.keys = keys
	} else if adapter != nil {
		rt.keys = bundles.NewKeyRotationManagerFromAdapter(adapter, bundles.NewKeyring(trusted))
		_ = rt.keys.Restore(context.Background())
	} else {
		rt.keys = bundles.NewKeyRotationManager(nil, nil, bundles.NewKeyring(trusted))
	}

	rt.sessionMgr = auth.NewSessionManager(rt.sessionStore, auth.SessionConfig{DefaultTTL: referenceSessionTTL})
	enforcer, err := auth.NewRevocationEnforcer(rt.sessionMgr, rt.revStore, auth.RevocationConfig{StaleWindowSeconds: 5})
	if err != nil {
		origin.close()
		return nil, err
	}
	rt.enforcer = enforcer

	cfg := gateway.DefaultUpstreamConfig()
	cfg.OriginURL = origin.url
	cfg.ID = gateway.DefaultAllowlistedUpstreamID
	cfg.RequiredOwnerScope = ReferenceOwnerScope
	cfg.ResourceClassification = "private"
	cfg.AllowedPathPrefixes = []string{"/api/v1/analytics", ReferenceUpstreamHealth}
	rt.upstream = &cfg
	rt.proxy = gateway.NewAllowlistedGatewayProxy(cfg, rt.sessionStore, rt.revStore)
	rt.proxy.Transport = rt.transport
	return rt, nil
}

// Close releases the owned upstream listener.
func (rt *Runtime) Close() {
	if rt != nil && rt.origin != nil {
		rt.origin.close()
	}
}

func (rt *Runtime) durable() bool { return rt != nil && rt.adapter != nil }

// Session issues a real session through the accepted session manager.
// To prevent session fixation and injection attacks, arbitrary client-supplied session IDs
// are strictly prohibited; session IDs are always securely generated by the authority.
func (rt *Runtime) Session(ctx context.Context, req SessionRequest) SessionResponse {
	out := SessionResponse{
		IssuerMode:      "synthetic_local_demo",
		StaleWindowSecs: int(rt.enforcer.StaleWindow().Seconds()),
		StorageDurable:  rt.durable(),
	}

	// Reject client-supplied session ID to eliminate session fixation and injection.
	if strings.TrimSpace(req.SessionID) != "" {
		out.ErrorCode = auth.ErrCodeInvalidSessionRequest
		out.ErrorMessage = "client-supplied session_id is not permitted; session IDs must be generated by the authority"
		return out
	}

	subjectID := strings.TrimSpace(req.SubjectID)
	if subjectID == "" {
		subjectID = ReferenceSubjectID
	}
	roles := req.Roles
	if len(roles) == 0 {
		roles = []string{"operator"}
	}
	res, err := rt.sessionMgr.CreateSession(ctx, auth.CreateSessionRequest{
		SubjectID:  subjectID,
		Issuer:     ReferenceIssuer,
		Roles:      roles,
		OwnerScope: ReferenceOwnerScope,
		ClientIP:   "127.0.0.1",
		UserAgent:  "policyhelix-reference-workflow",
		SessionID:  "", // Always empty so CreateSession generates a fresh cryptographically random ID
		TTL:        referenceSessionTTL,
		ServerCredentials: auth.ServerCredentials{
			Custom: map[string]string{"issuer_mode": "synthetic_local_demo"},
		},
	})
	if err != nil || res == nil || !res.Valid || res.Session == nil {
		out.ErrorCode = auth.ErrCodeInvalidSessionRequest
		out.ErrorMessage = "failed to issue a local reference session"
		if err != nil {
			out.ErrorMessage = err.Error()
		}
		return out
	}
	out.Valid = true
	out.SessionID = res.Session.SessionID
	out.SubjectID = res.Session.SubjectID
	out.Issuer = res.Session.Issuer
	out.Roles = res.Session.Roles
	out.OwnerScope = res.Session.OwnerScope
	out.SessionEpoch = res.Session.SessionEpoch
	out.ExpiresAt = res.Session.ExpiresAt.UTC().Format(time.RFC3339)
	out.SetCookiePresent = res.SetCookieHeader != ""
	rt.mu.Lock()
	rt.lastSessionID = res.Session.SessionID
	rt.mu.Unlock()
	return out
}

// BuildBundle builds and signs the workflow bundle at the next monotonic revision.
func (rt *Runtime) BuildBundle(expired bool) (policy.LocalPolicyBundle, string, error) {
	now := time.Now().UTC()
	highest := rt.keys.HighestRevisionLocked()
	revision := highest + 1
	if revision < 1 {
		revision = 1
	}
	issued := now.Add(-1 * time.Minute)
	expires := now.Add(24 * time.Hour)
	if expired {
		issued = now.Add(-48 * time.Hour)
		expires = now.Add(-1 * time.Hour)
	}
	bundle, err := bundles.BuildDeterministicBundle(bundles.BundleBuildSpec{
		SchemaVersion: "1",
		BundleID:      fmt.Sprintf("bundle-reference-v%d", revision),
		Package:       "policyhelix.authz",
		Issuer:        ReferenceBundleIssuer,
		SignerKeyID:   ReferenceSignerKeyID,
		SeedHex:       referenceSigningSeedHex,
		Revision:      revision,
		IssuedAt:      issued.Format(time.RFC3339),
		ExpiresAt:     expires.Format(time.RFC3339),
		RegoModule:    referenceRegoModule,
		Routes: []policy.RouteRule{
			{
				Pattern:              "/api/v1/analytics/*",
				Action:               "read",
				Classification:       policy.ResourceClassPrivate,
				AllowUnauthenticated: false,
				RequiredRoles:        []string{"operator"},
				Description:          "Owned synthetic analytics report requires a normalized operator identity",
			},
		},
		Rules: []policy.PolicyRule{
			{
				ID:            fmt.Sprintf("rule-reference-analytics-v%d", revision),
				Effect:        "allow",
				PathPattern:   "/api/v1/analytics/*",
				Actions:       []string{"read"},
				Roles:         []string{"operator"},
				ResourceClass: policy.ResourceClassPrivate,
			},
		},
	})
	if err != nil {
		return policy.LocalPolicyBundle{}, "reference-signing-key", err
	}
	return bundle, referenceSigningSeedHex, nil
}

// ActivateBundle builds, signs and atomically activates the next reference bundle.
func (rt *Runtime) ActivateBundle(ctx context.Context, expired bool) BundleResponse {
	res := BundleResponse{Status: bundles.ActivationStatusRejected, MonotonicRevision: true}
	before := rt.keys.State()
	bundle, _, err := rt.BuildBundle(expired)
	if err != nil {
		res.ErrorCode = bundles.ErrCodeSigningFailed
		res.Message = err.Error()
		res.State = rt.keys.State()
		return res
	}
	res.BundleID = bundle.BundleID
	res.Revision = bundle.Revision
	res.HighestRevision = before.HighestRevision
	res.Digest = bundle.Digest
	res.Signature = bundle.Signature
	res.SignatureVerified = bundle.SignatureVerified
	res.IssuedAt = bundle.IssuedAt
	res.ExpiresAt = bundle.ExpiresAt

	identity := storage.CallerIdentity{
		SubjectID:                ReferenceSubjectID,
		Issuer:                   ReferenceIssuer,
		Roles:                    []string{"operator"},
		Authenticated:            true,
		SessionEpoch:             time.Now().UTC().Unix(),
		UntrustedHeadersStripped: true,
		ProviderState:            "verified",
	}
	opID := fmt.Sprintf("op-reference-activate-%d", time.Now().UTC().UnixNano())
	activation := rt.keys.ActivateBundle(ctx, bundles.ActivationRequest{
		SchemaVersion: bundles.ActivationSchemaVersion,
		OperationID:   opID,
		Identity:      identity,
		Bundle:        bundle,
	}, time.Now().UTC().Format(time.RFC3339))

	res.Status = activation.Status
	res.Active = activation.Active
	res.Replayed = activation.Replayed
	res.Durable = activation.Durable
	res.ErrorCode = activation.ErrorCode
	res.Message = activation.Message
	res.Accepted = activation.Active && activation.ErrorCode == ""
	res.ActiveBundleRetained = before.Active
	res.State = rt.keys.State()
	res.HighestRevision = res.State.HighestRevision
	return res
}

// CheckAccess runs the accepted bounded revocation/scope access check for a session.
func (rt *Runtime) CheckAccess(ctx context.Context, sessionID string) *auth.AccessCheckResult {
	res, err := rt.enforcer.CheckAccess(ctx, auth.AccessCheckRequest{
		RequestID:                fmt.Sprintf("ref-%d", time.Now().UTC().UnixNano()),
		SessionID:                sessionID,
		ClientIP:                 "127.0.0.1",
		UserAgent:                "policyhelix-reference-workflow",
		UntrustedHeadersStripped: true,
		TargetOwnerScope:         ReferenceOwnerScope,
		RequestedPath:            ReferenceUpstreamPath,
		RequestedProvider:        gateway.DefaultAllowlistedUpstreamID,
		ResourceClassification:   string(policy.ResourceClassPrivate),
	})
	if err != nil {
		return &auth.AccessCheckResult{
			Valid:               false,
			Status:              "denied",
			ErrorCode:           auth.ErrCodeProviderUnavailable,
			ErrorMessage:        err.Error(),
			SideEffectsExecuted: false,
		}
	}
	return res
}

// ProxyRequest performs the live proxy path: bounded access check, allowlisted proxy, then the
// active bundle policy authority. Every denied path reports no forwarded request and no side effect.
func (rt *Runtime) ProxyRequest(ctx context.Context, req ProxyRequest) ProxyResponse {
	path := strings.TrimSpace(req.Path)
	if path == "" {
		path = ReferenceUpstreamPath
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	classification := strings.TrimSpace(req.Classification)
	if classification == "" {
		classification = string(policy.ResourceClassPrivate)
	}

	res := ProxyResponse{StatusCode: http.StatusForbidden}
	// Public routes intentionally skip the private access check; private routes never do.
	access := &auth.AccessCheckResult{Allow: true, Valid: true, Status: "public_route", SideEffectsExecuted: false}
	if !strings.EqualFold(classification, string(policy.ResourceClassPublic)) {
		access = rt.CheckAccess(ctx, req.SessionID)
	}
	res.AccessCheck = access
	if access == nil || !access.Allow {
		res.Allow = false
		res.Valid = false
		res.StatusCode = http.StatusForbidden
		if access != nil {
			res.ErrorCode = access.ErrorCode
			res.ErrorMessage = access.ErrorMessage
		}
		return res
	}

	proxyReq := gateway.ProxyRequest{
		RequestID:                fmt.Sprintf("ref-%d", time.Now().UTC().UnixNano()),
		TargetUpstreamID:         gateway.DefaultAllowlistedUpstreamID,
		Method:                   method,
		Path:                     path,
		Headers:                  map[string]string{"X-Request-Id": fmt.Sprintf("ref-%d", time.Now().UTC().UnixNano())},
		SessionID:                req.SessionID,
		ClientIP:                 "127.0.0.1",
		UserAgent:                "policyhelix-reference-workflow",
		UntrustedHeadersStripped: true,
		ForgedHeaders:            req.ForgedHeaders,
		ResourceClassification:   classification,
		TargetOwnerScope:         ReferenceOwnerScope,
		ProviderState:            req.ProviderState,
		DecisionEngineState:      req.DecisionState,
	}
	pRes, err := rt.proxy.EvaluateProxyRequest(ctx, proxyReq)
	if err != nil {
		res.ErrorCode = gateway.ErrCodeOriginUnreachable
		res.ErrorMessage = err.Error()
		return res
	}
	if pRes == nil {
		res.ErrorCode = gateway.ErrCodeUnauthenticated
		res.ErrorMessage = "proxy produced no result"
		return res
	}
	// Public health routes intentionally bypass policy authority; everything else must pass it.
	gateway.EnforcePolicyAuthority(ctx, rt.keys, proxyReq, pRes, time.Now().UTC(), "")
	res.Proxy = pRes
	res.Allow = pRes.Allow
	res.Valid = pRes.Valid
	res.Forwarded = pRes.ForwardedToUpstream
	res.StatusCode = pRes.StatusCode
	res.ErrorCode = pRes.ErrorCode
	res.ErrorMessage = pRes.ErrorMessage
	res.UpstreamStatus = pRes.UpstreamStatusCode
	res.UpstreamBody = pRes.UpstreamResponseBody
	res.StrippedHeaders = pRes.StrippedHeaders
	res.InjectedHeaders = pRes.DownstreamInjectedHeaders
	if pRes.BundleDecision != nil {
		res.Decision = pRes.BundleDecision
	}
	return res
}

// SpoofAndDirectOrigin proves forged identity headers and direct origin access both fail closed.
func (rt *Runtime) SpoofAndDirectOrigin(ctx context.Context, req ProxyRequest) SpoofResponse {
	spoofReq := req
	spoofReq.ForgedHeaders = map[string]string{"X-Remote-User": "admin"}
	if spoofReq.Path == "" {
		spoofReq.Path = ReferenceUpstreamPath
	}
	spoofed := rt.ProxyRequest(ctx, spoofReq)
	out := SpoofResponse{
		SpoofedAllow:     spoofed.Allow,
		SpoofedErrorCode: spoofed.ErrorCode,
		SpoofedError:     spoofed.ErrorMessage,
		SpoofedForwarded: spoofed.Forwarded,
		SpoofedStripped:  spoofed.StrippedHeaders,
	}
	direct := gateway.ProbeDirectOrigin(ctx, *rt.upstream, rt.transport, ReferenceUpstreamPath)
	out.Direct = &direct
	out.DirectBlocked = direct.Blocked
	out.DirectStatus = direct.StatusCode
	out.DirectBody = direct.UpstreamBody
	return out
}

// RevokeSession revokes a session and proves the next request is denied.
func (rt *Runtime) RevokeSession(ctx context.Context, sessionID string) RevokeResponse {
	out := RevokeResponse{
		SessionID:           sessionID,
		MaxStaleSeconds:     int(rt.enforcer.StaleWindow().Seconds()),
		SideEffectsExecuted: false,
	}
	if strings.TrimSpace(sessionID) == "" {
		out.ErrorCode = auth.ErrCodeInvalidRevocationRequest
		out.ErrorMessage = "session_id is required"
		return out
	}
	event, err := rt.enforcer.RevokeSession(ctx, sessionID, "operator_revoked_reference_session", "reference-workflow", time.Now().UTC())
	if err != nil {
		out.ErrorCode = auth.ErrCodeInvalidRevocationRequest
		out.ErrorMessage = err.Error()
		return out
	}
	if event != nil {
		out.RevokedAt = event.RevokedAt.UTC().Format(time.RFC3339)
		out.Reason = event.Reason
	}
	out.Revoked = true

	check := rt.CheckAccess(ctx, sessionID)
	if check != nil {
		out.StoppedWithinBound = check.StoppedWithinBound
		out.ElapsedSinceRevoke = check.ElapsedSinceRevoke
		out.SubsequentAllow = check.Allow
		out.SubsequentErrorCode = check.ErrorCode
		out.SubsequentMessage = check.ErrorMessage
		out.SideEffectsExecuted = check.SideEffectsExecuted
	}
	if out.SubsequentAllow {
		out.Revoked = false
		out.ErrorCode = auth.ErrCodeStaleWindowExceeded
		out.ErrorMessage = "revoked session was still allowed; revocation bound not enforced"
	}
	return out
}

// SimulateOutage proves decision-engine, identity-provider and expired-bundle fail-closed behavior.
func (rt *Runtime) SimulateOutage(ctx context.Context, sessionID string) OutageResponse {
	var out OutageResponse
	decision := rt.ProxyRequest(ctx, ProxyRequest{
		SessionID:     sessionID,
		Path:          ReferenceUpstreamPath,
		DecisionState: "outage",
	})
	out.DecisionOutageAllow = decision.Allow
	out.DecisionOutageCode = decision.ErrorCode
	out.DecisionOutageMessage = decision.ErrorMessage

	idp := rt.ProxyRequest(ctx, ProxyRequest{
		SessionID:     sessionID,
		Path:          ReferenceUpstreamPath,
		ProviderState: "unavailable",
	})
	out.IdPOutageAllow = idp.Allow
	out.IdPOutageCode = idp.ErrorCode

	before := rt.keys.State()
	expired := rt.ActivateBundle(ctx, true)
	out.ExpiredBundleAccepted = expired.Accepted || (expired.Active && expired.ErrorCode == "")
	out.ExpiredBundleErrorCode = expired.ErrorCode
	out.ExpiredBundleMessage = expired.Message
	after := rt.keys.State()
	out.ActiveBundleRetained = before.Active && after.Active && before.ActiveRevision == after.ActiveRevision
	out.ActiveRevision = after.ActiveRevision

	publicProbe := rt.ProxyRequest(ctx, ProxyRequest{Path: ReferenceUpstreamHealth, Classification: "public", Method: http.MethodGet})
	out.PublicHealthStillOK = publicProbe.Allow || publicProbe.StatusCode == http.StatusOK
	return out
}

// State returns the durable restart/restore projection for the browser and clone smoke proof.
func (rt *Runtime) State(ctx context.Context) StateResponse {
	state := rt.keys.State()
	out := StateResponse{
		Status:             state.Status,
		Ready:              state.Valid,
		Engine:             EngineName,
		Version:            EngineVersion,
		StorageDurable:     rt.durable(),
		StorageRevision:    state.StorageRevision,
		HighestRevision:    state.HighestRevision,
		TrustedKeyIDs:      state.TrustedKeyIDs,
		IssuerMode:         "synthetic_local_demo",
		StaleWindowSeconds: int(rt.enforcer.StaleWindow().Seconds()),
		CheckedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	if rt.adapter != nil {
		if manifest, sErr := rt.adapter.GetManifest(); sErr == nil && manifest != nil {
			out.StorageRevision = manifest.Revision
		}
	}
	active, ok := rt.keys.ActiveBundle()
	if ok {
		remaining := int64(0)
		if exp, err := time.Parse(time.RFC3339, active.ExpiresAt); err == nil {
			remaining = int64(time.Until(exp).Seconds())
		}
		out.ActiveBundle = &BundleSummary{
			BundleID:      active.BundleID,
			Revision:      active.Revision,
			Digest:        active.Digest,
			SignerKeyID:   active.SignerKeyID,
			IssuedAt:      active.IssuedAt,
			ExpiresAt:     active.ExpiresAt,
			RemainingSecs: remaining,
		}
	}
	if sessions, err := rt.sessionStore.ListSessionsForSubject(ctx, ReferenceSubjectID); err == nil {
		out.SessionCount = len(sessions)
		revoked := make([]string, 0)
		for _, s := range sessions {
			if rec, _ := rt.revStore.GetSessionRevocation(ctx, s.SessionID); rec != nil {
				revoked = append(revoked, s.SessionID)
			}
		}
		out.RevokedSessionIDs = revoked
	}
	out.Upstream = gateway.ProbeUpstream(ctx, *rt.upstream, rt.transport)
	out.Providers = rt.ReadinessProviders(ctx, true)
	return out
}

// ReadinessProviders returns real provider checks for readiness and diagnostics. Explicit
// simulated states are handled by the existing readiness fixtures; this function only reports
// runtime-observed truth.
func (rt *Runtime) ReadinessProviders(ctx context.Context, probeUpstream bool) []gateway.ProviderReadiness {
	out := make([]gateway.ProviderReadiness, 0, 3)

	opa := EvaluatorSelfTest(ctx)
	out = append(out, gateway.ProviderReadiness{
		Ready:        opa.Ready,
		Status:       statusFromProbe(opa),
		Verification: opa.Verification,
		LatencyMs:    opa.LatencyMs,
		ErrorCode:    opa.ErrorCode,
		ErrorMessage: opa.Message,
	})

	idp := rt.SessionStoreProbe(ctx)
	out = append(out, gateway.ProviderReadiness{
		Ready:        idp.Ready,
		Status:       statusFromProbe(idp),
		Verification: idp.Verification,
		LatencyMs:    idp.LatencyMs,
		ErrorCode:    idp.ErrorCode,
		ErrorMessage: idp.Message,
	})

	upstreamProbe := gateway.ProviderProbe{Ready: false, Verification: "http_probe", ErrorCode: gateway.ErrCodeUpstreamUnavailable, Message: "upstream probe disabled"}
	if probeUpstream {
		p := gateway.ProbeUpstream(ctx, *rt.upstream, rt.transport)
		upstreamProbe = gateway.ProviderProbe{
			Ready:        p.Ready,
			Verification: p.Verification,
			LatencyMs:    int64(p.LatencyMs),
			ErrorCode:    p.ErrorCode,
			Message:      p.Message,
		}
	}
	out = append(out, gateway.ProviderReadiness{
		Ready:        upstreamProbe.Ready,
		Status:       statusFromProbe(upstreamProbe),
		Verification: upstreamProbe.Verification,
		LatencyMs:    upstreamProbe.LatencyMs,
		ErrorCode:    upstreamProbe.ErrorCode,
		ErrorMessage: upstreamProbe.Message,
	})
	return out
}

func statusFromProbe(p gateway.ProviderProbe) string {
	if p.Ready {
		return "connected"
	}
	return "offline"
}

// SessionStoreProbe verifies the configured session store is accessible and readable
// without executing any mutating writes or deletes on disk.
func (rt *Runtime) SessionStoreProbe(ctx context.Context) gateway.ProviderProbe {
	start := time.Now()
	latency := func() int64 { return int64(time.Since(start).Microseconds()) / 1000 }

	if rt == nil || rt.sessionStore == nil {
		return gateway.ProviderProbe{
			Verification: "synthetic_local_demo",
			LatencyMs:    latency(),
			ErrorCode:    gateway.ErrCodeIdPUnavailable,
			Message:      "session store unavailable",
		}
	}

	if rt.adapter != nil {
		if _, sErr := rt.adapter.GetManifest(); sErr != nil {
			return gateway.ProviderProbe{
				Verification: "synthetic_local_demo",
				LatencyMs:    latency(),
				ErrorCode:    gateway.ErrCodeIdPUnavailable,
				Message:      fmt.Sprintf("session store adapter check failed: %s", sErr.Message),
			}
		}
	} else {
		if _, err := rt.sessionStore.ListSessionsForSubject(ctx, "__probe__"); err != nil {
			return gateway.ProviderProbe{
				Verification: "synthetic_local_demo",
				LatencyMs:    latency(),
				ErrorCode:    gateway.ErrCodeIdPUnavailable,
				Message:      fmt.Sprintf("session store check failed: %v", err),
			}
		}
	}

	return gateway.ProviderProbe{
		Ready:        true,
		Verification: "synthetic_local_demo",
		LatencyMs:    latency(),
	}
}

// EvaluatorSelfTest executes a real signed bundle through the accepted evaluator. It is the
// provider readiness check for the embedded policy engine, not a configured-state assumption.
func EvaluatorSelfTest(ctx context.Context) gateway.ProviderProbe {
	start := time.Now()
	latency := func() int64 { return int64(time.Since(start).Microseconds()) / 1000 }
	now := time.Now().UTC()
	bundle, err := bundles.BuildDeterministicBundle(bundles.BundleBuildSpec{
		SchemaVersion: "1",
		BundleID:      "bundle-reference-selftest",
		Package:       "policyhelix.authz",
		Issuer:        ReferenceBundleIssuer,
		SignerKeyID:   "ed25519-reference-selftest",
		SeedHex:       referenceSelfTestSeedHex,
		Revision:      1,
		IssuedAt:      now.Add(-1 * time.Minute).Format(time.RFC3339),
		ExpiresAt:     now.Add(5 * time.Minute).Format(time.RFC3339),
		RegoModule:    referenceRegoModule,
		Routes: []policy.RouteRule{
			{Pattern: ReferenceUpstreamPath, Action: "read", Classification: policy.ResourceClassPrivate, RequiredRoles: []string{"operator"}},
		},
		Rules: []policy.PolicyRule{
			{
				ID:            "rule-reference-selftest",
				Effect:        "allow",
				PathPattern:   ReferenceUpstreamPath,
				Actions:       []string{"read"},
				Roles:         []string{"operator"},
				ResourceClass: policy.ResourceClassPrivate,
			},
		},
	})
	if err != nil {
		return gateway.ProviderProbe{Verification: "embedded_selftest", LatencyMs: latency(), ErrorCode: gateway.ErrCodeOPAUnavailable, Message: err.Error()}
	}
	evaluator := policy.NewBundleEvaluator([]string{ReferenceBundleIssuer}, []string{"ed25519-reference-selftest"})
	if err := evaluator.LoadBundle(bundle, now); err != nil {
		return gateway.ProviderProbe{Verification: "embedded_selftest", LatencyMs: latency(), ErrorCode: gateway.ErrCodeOPAUnavailable, Message: err.Message}
	}
	decision := evaluator.Evaluate(ctx, policy.BundleEvalInput{
		Path:   ReferenceUpstreamPath,
		Action: "read",
		Subject: policy.SubjectIdentity{
			ID:            "usr-selftest",
			Issuer:        ReferenceIssuer,
			Roles:         []string{"operator"},
			Authenticated: true,
			SessionEpoch:  1,
		},
		DeadlineMS: 50,
	})
	if !decision.Allow {
		code := gateway.ErrCodeOPAUnavailable
		message := "evaluator rejected a valid self-test decision"
		if decision.Error != nil && decision.Error.Code != "" {
			code = decision.Error.Code
			message = decision.Error.Message
		}
		return gateway.ProviderProbe{Verification: "embedded_selftest", LatencyMs: latency(), ErrorCode: code, Message: message}
	}
	return gateway.ProviderProbe{Ready: true, Verification: "embedded_selftest", LatencyMs: latency()}
}

// ReferenceProviderProbes projects the live checks into the readiness probe map.
func (rt *Runtime) ReferenceProviderProbes(ctx context.Context) map[string]gateway.ProviderProbe {
	providers := rt.ReadinessProviders(ctx, true)
	return map[string]gateway.ProviderProbe{
		"local_opa":                {Ready: providers[0].Ready, Verification: providers[0].Verification, LatencyMs: providers[0].LatencyMs, ErrorCode: providers[0].ErrorCode, Message: providers[0].ErrorMessage},
		"self_hosted_keycloak":     {Ready: providers[1].Ready, Verification: providers[1].Verification, LatencyMs: providers[1].LatencyMs, ErrorCode: providers[1].ErrorCode, Message: providers[1].ErrorMessage},
		"owned_synthetic_upstream": {Ready: providers[2].Ready, Verification: providers[2].Verification, LatencyMs: providers[2].LatencyMs, ErrorCode: providers[2].ErrorCode, Message: providers[2].ErrorMessage},
	}
}

// referenceFixturePath resolves a repository-relative fixture reference without allowing traversal.
func referenceFixturePath(ref string) (string, bool) {
	if ref == "" || filepath.IsAbs(ref) || strings.Contains(ref, "..") || strings.Contains(ref, "\\") {
		return "", false
	}
	if !strings.HasPrefix(ref, "tests/fixtures/policyhelix/") || !strings.HasSuffix(ref, ".json") {
		return "", false
	}
	candidates := []string{ref, filepath.Join("..", "..", ref)}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, true
		}
	}
	return "", false
}

// SimulateFixture evaluates the fixture's synthetic identity and action against the active bundle.
// The fixture supplies the expectation; the live evaluator supplies the observed decision.
func (rt *Runtime) SimulateFixture(ctx context.Context, req SimulateRequest) SimulateResponse {
	ref := strings.TrimSpace(req.FixtureRef)
	if ref == "" {
		ref = "tests/fixtures/policyhelix/C01/positive-decision.json"
	}
	out := SimulateResponse{FixtureRef: ref}
	path, ok := referenceFixturePath(ref)
	if !ok {
		out.ErrorCode = policy.ErrCodeMalformedFixture
		out.ErrorMessage = "fixture reference must be a JSON file inside tests/fixtures/policyhelix"
		return out
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		out.ErrorCode = policy.ErrCodeMalformedFixture
		out.ErrorMessage = err.Error()
		return out
	}
	var fixture struct {
		FixtureID string `json:"fixture_id"`
		Input     struct {
			Subject struct {
				ID           string   `json:"id"`
				Issuer       string   `json:"issuer"`
				Roles        []string `json:"roles"`
				SessionEpoch int64    `json:"session_epoch"`
			} `json:"subject"`
			Action string `json:"action"`
		} `json:"input"`
		ExpectedDecision struct {
			Allow bool `json:"allow"`
		} `json:"expected_decision"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		out.ErrorCode = policy.ErrCodeMalformedFixture
		out.ErrorMessage = err.Error()
		return out
	}
	out.FixtureID = fixture.FixtureID
	expected := fixture.ExpectedDecision.Allow
	out.ExpectedAllow = &expected

	evalPath := strings.TrimSpace(req.Path)
	if evalPath == "" {
		evalPath = ReferenceUpstreamPath
	}
	action := strings.TrimSpace(fixture.Input.Action)
	if action == "" {
		action = "read"
	}
	input := policy.BundleEvalInput{
		Path:   evalPath,
		Action: action,
		Subject: policy.SubjectIdentity{
			ID:            fixture.Input.Subject.ID,
			Issuer:        fixture.Input.Subject.Issuer,
			Roles:         fixture.Input.Subject.Roles,
			Authenticated: true,
			SessionEpoch:  fixture.Input.Subject.SessionEpoch,
		},
		ResourceID: evalPath,
		DeadlineMS: 200,
	}

	var decision policy.BundleDecision
	if _, active := rt.keys.ActiveBundle(); active {
		decision = rt.keys.Evaluate(ctx, input)
	} else {
		// Simulator semantics: evaluate the signed candidate offline before any activation.
		candidate, _, err := rt.BuildBundle(false)
		if err != nil {
			out.ErrorCode = policy.ErrCodeMalformedFixture
			out.ErrorMessage = err.Error()
			return out
		}
		evaluator := policy.NewBundleEvaluator([]string{ReferenceBundleIssuer}, []string{ReferenceSignerKeyID})
		if bErr := evaluator.LoadBundle(candidate, time.Now().UTC()); bErr != nil {
			out.ErrorCode = bErr.Code
			out.ErrorMessage = bErr.Message
			return out
		}
		decision = evaluator.Evaluate(ctx, input)
	}
	out.Decision = &decision
	out.ObservedAllow = decision.Allow
	out.ObservedReasons = decision.Reasons
	out.ExpectedMatched = decision.Allow == expected
	if decision.Error != nil {
		out.ErrorCode = decision.Error.Code
		out.ErrorMessage = decision.Error.Message
	}
	return out
}

func writeReferenceJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func referenceMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeReferenceJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	return false
}

func decodeReferenceBody(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, referenceMaxRequestBody))
	if err != nil {
		writeReferenceJSON(w, http.StatusBadRequest, map[string]string{"error": gateway.ErrCodeMalformedHeader, "message": "request body read error or exceeds 1 MiB"})
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return true
	}
	if err := json.Unmarshal(body, target); err != nil {
		writeReferenceJSON(w, http.StatusBadRequest, map[string]string{"error": gateway.ErrCodeMalformedHeader, "message": fmt.Sprintf("malformed JSON: %v", err)})
		return false
	}
	return true
}

// RegisterRoutes wires the live reference workflow endpoints. When no live runtime is
// configured the endpoints fail closed with an explicit error instead of placeholder success.
func RegisterRoutes(mux *http.ServeMux, rt *Runtime) {
	unavailable := func(w http.ResponseWriter) {
		msg := "The reference workflow requires the durable local engine runtime; start it with npm start."
		writeReferenceJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"status":        "unavailable",
			"ready":         false,
			"error":         "REFERENCE_RUNTIME_UNAVAILABLE",
			"error_code":    "REFERENCE_RUNTIME_UNAVAILABLE",
			"message":       msg,
			"error_message": msg,
		})
	}

	mux.HandleFunc("/api/v1/reference/state", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodGet) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		writeReferenceJSON(w, http.StatusOK, rt.State(r.Context()))
	})

	mux.HandleFunc("/api/v1/reference/simulate", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodPost) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		var req SimulateRequest
		if !decodeReferenceBody(w, r, &req) {
			return
		}
		res := rt.SimulateFixture(r.Context(), req)
		status := http.StatusOK
		if res.ErrorCode != "" || !res.ExpectedMatched {
			status = http.StatusUnprocessableEntity
		}
		writeReferenceJSON(w, status, res)
	})

	mux.HandleFunc("/api/v1/reference/session", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodPost) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		var req SessionRequest
		if !decodeReferenceBody(w, r, &req) {
			return
		}
		res := rt.Session(r.Context(), req)
		status := http.StatusOK
		if !res.Valid {
			status = http.StatusUnprocessableEntity
		}
		writeReferenceJSON(w, status, res)
	})

	mux.HandleFunc("/api/v1/reference/bundle", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodPost) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		var req BundleRequest
		if !decodeReferenceBody(w, r, &req) {
			return
		}
		res := rt.ActivateBundle(r.Context(), req.Expired)
		status := http.StatusOK
		if !res.Accepted && !req.Expired {
			status = http.StatusUnprocessableEntity
		}
		writeReferenceJSON(w, status, res)
	})

	mux.HandleFunc("/api/v1/reference/proxy", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodPost) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		var req ProxyRequest
		if !decodeReferenceBody(w, r, &req) {
			return
		}
		res := rt.ProxyRequest(r.Context(), req)
		status := http.StatusOK
		if !res.Allow {
			status = http.StatusForbidden
			if res.StatusCode == http.StatusServiceUnavailable {
				status = http.StatusServiceUnavailable
			}
		}
		writeReferenceJSON(w, status, res)
	})

	mux.HandleFunc("/api/v1/reference/spoof", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodPost) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		var req ProxyRequest
		if !decodeReferenceBody(w, r, &req) {
			return
		}
		res := rt.SpoofAndDirectOrigin(r.Context(), req)
		status := http.StatusOK
		if res.SpoofedAllow || !res.DirectBlocked {
			status = http.StatusUnprocessableEntity
		}
		writeReferenceJSON(w, status, res)
	})

	mux.HandleFunc("/api/v1/reference/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodPost) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		var req ProxyRequest
		if !decodeReferenceBody(w, r, &req) {
			return
		}
		res := rt.RevokeSession(r.Context(), req.SessionID)
		status := http.StatusOK
		if res.ErrorCode != "" {
			status = http.StatusUnprocessableEntity
		}
		writeReferenceJSON(w, status, res)
	})

	mux.HandleFunc("/api/v1/reference/outage", func(w http.ResponseWriter, r *http.Request) {
		if !referenceMethod(w, r, http.MethodPost) {
			return
		}
		if rt == nil {
			unavailable(w)
			return
		}
		var req ProxyRequest
		if !decodeReferenceBody(w, r, &req) {
			return
		}
		writeReferenceJSON(w, http.StatusOK, rt.SimulateOutage(r.Context(), req.SessionID))
	})
}
