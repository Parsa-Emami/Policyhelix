package auth

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

// Typed error codes for OIDC validation and security invariants (Requirement F07).
const (
	ErrCodeWrongIssuer              = "WRONG_ISSUER"
	ErrCodeWrongAudience            = "WRONG_AUDIENCE"
	ErrCodeNonceReplay              = "NONCE_REPLAY"
	ErrCodeNonceMismatch            = "NONCE_MISMATCH"
	ErrCodeMissingNonce             = "MISSING_NONCE"
	ErrCodeInvalidCallbackState     = "INVALID_CALLBACK_STATE"
	ErrCodeStateExpired             = "STATE_EXPIRED"
	ErrCodeStateReplayed            = "STATE_REPLAYED"
	ErrCodeExpiredToken             = "EXPIRED_TOKEN"
	ErrCodeTokenNotYetValid         = "TOKEN_NOT_YET_VALID"
	ErrCodeInvalidTokenSignature    = "INVALID_TOKEN_SIGNATURE"
	ErrCodeUntrustedSigner          = "UNTRUSTED_OR_MISSING_SIGNER"
	ErrCodeUnauthenticatedIdentity  = "UNAUTHENTICATED_IDENTITY"
	ErrCodeForgedHeader             = "FORGED_HEADER_REJECTED"
	ErrCodeScopeViolation           = "SCOPE_VIOLATION"
	ErrCodeProviderUnavailable      = "PROVIDER_UNAVAILABLE"
	ErrCodePrivateFailClosed        = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrCodeMalformedToken           = "MALFORMED_TOKEN"
	ErrCodeInvalidValidationRequest = "INVALID_VALIDATION_REQUEST"
)

// Supported token signing algorithms.
const (
	AlgRS256 = "RS256"
	AlgEdDSA = "EdDSA"
	AlgHS256 = "HS256"
)

// Audience supports single-string or slice-of-strings JSON unmarshaling.
type Audience []string

// UnmarshalJSON unmarshals either a JSON string or an array of strings into Audience.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		*a = multiple
		return nil
	}
	return errors.New("aud claim must be a string or array of strings")
}

// MarshalJSON marshals Audience to JSON.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Contains checks if the expected audience is present.
func (a Audience) Contains(target string) bool {
	for _, aud := range a {
		if aud == target {
			return true
		}
	}
	return false
}

// IDTokenClaims holds standard OpenID Connect ID Token claims.
type IDTokenClaims struct {
	Issuer         string                         `json:"iss"`
	Subject        string                         `json:"sub"`
	Audience       Audience                       `json:"aud"`
	ExpiresAt      int64                          `json:"exp"`
	NotBefore      int64                          `json:"nbf,omitempty"`
	IssuedAt       int64                          `json:"iat,omitempty"`
	Nonce          string                         `json:"nonce,omitempty"`
	Email          string                         `json:"email,omitempty"`
	Roles          []string                       `json:"roles,omitempty"`
	RealmAccess    *RealmAccessRoles              `json:"realm_access,omitempty"`
	ResourceAccess map[string]ResourceAccessRoles `json:"resource_access,omitempty"`
	OwnerScope     string                         `json:"owner_scope,omitempty"`
	TenantID       string                         `json:"tenant_id,omitempty"`
}

type RealmAccessRoles struct {
	Roles []string `json:"roles"`
}

type ResourceAccessRoles struct {
	Roles []string `json:"roles"`
}

// NormalizedRoles extracts and deduplicates roles across standard, realm, and resource claims.
func (c *IDTokenClaims) NormalizedRoles() []string {
	roleSet := make(map[string]struct{})
	for _, r := range c.Roles {
		trimmed := strings.TrimSpace(r)
		if trimmed != "" {
			roleSet[trimmed] = struct{}{}
		}
	}
	if c.RealmAccess != nil {
		for _, r := range c.RealmAccess.Roles {
			trimmed := strings.TrimSpace(r)
			if trimmed != "" {
				roleSet[trimmed] = struct{}{}
			}
		}
	}
	if c.ResourceAccess != nil {
		for _, res := range c.ResourceAccess {
			for _, r := range res.Roles {
				trimmed := strings.TrimSpace(r)
				if trimmed != "" {
					roleSet[trimmed] = struct{}{}
				}
			}
		}
	}
	result := make([]string, 0, len(roleSet))
	for r := range roleSet {
		result = append(result, r)
	}
	sort.Strings(result)
	return result
}

// LoginState models an active, single-use authentication request state with bounded TTL.
type LoginState struct {
	StateToken    string     `json:"state_token"`
	Nonce         string     `json:"nonce"`
	Issuer        string     `json:"issuer"`
	ClientID      string     `json:"client_id"`
	RedirectURI   string     `json:"redirect_uri"`
	OwnerScope    string     `json:"owner_scope,omitempty"`
	CodeVerifier  string     `json:"code_verifier,omitempty"`
	CodeChallenge string     `json:"code_challenge,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Consumed      bool       `json:"consumed"`
	ConsumedAt    *time.Time `json:"consumed_at,omitempty"`
}

// LoginStateOptions specifies inputs when beginning an OIDC login flow.
type LoginStateOptions struct {
	Issuer       string
	ClientID     string
	RedirectURI  string
	OwnerScope   string
	StateToken   string // Optional: deterministic override for testing
	Nonce        string // Optional: deterministic override for testing
	TTL          time.Duration
	WithPKCE     bool
	CodeVerifier string // Optional: override for testing
}

// StateManager manages thread-safe storage, validation and single-use consumption of login states.
type StateManager struct {
	mu     sync.Mutex
	states map[string]*LoginState
}

// NewStateManager constructs a new in-memory StateManager.
func NewStateManager() *StateManager {
	return &StateManager{
		states: make(map[string]*LoginState),
	}
}

// BeginLogin creates and records a new login state.
func (m *StateManager) BeginLogin(opts LoginStateOptions, now time.Time) (*LoginState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stateToken := opts.StateToken
	if stateToken == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("failed to generate random state token: %w", err)
		}
		stateToken = hex.EncodeToString(buf)
	}

	nonce := opts.Nonce
	if nonce == "" {
		buf := make([]byte, 24)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("failed to generate random nonce: %w", err)
		}
		nonce = hex.EncodeToString(buf)
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	var codeVerifier, codeChallenge string
	if opts.WithPKCE {
		if opts.CodeVerifier != "" {
			codeVerifier = opts.CodeVerifier
		} else {
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err != nil {
				return nil, fmt.Errorf("failed to generate PKCE verifier: %w", err)
			}
			codeVerifier = base64.RawURLEncoding.EncodeToString(buf)
		}
		h := sha256.Sum256([]byte(codeVerifier))
		codeChallenge = base64.RawURLEncoding.EncodeToString(h[:])
	}

	state := &LoginState{
		StateToken:    stateToken,
		Nonce:         nonce,
		Issuer:        opts.Issuer,
		ClientID:      opts.ClientID,
		RedirectURI:   opts.RedirectURI,
		OwnerScope:    opts.OwnerScope,
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		CreatedAt:     now.UTC(),
		ExpiresAt:     now.Add(ttl).UTC(),
		Consumed:      false,
	}

	m.states[stateToken] = state
	return state, nil
}

// StoreState inserts or overrides a state (useful for test fixtures).
func (m *StateManager) StoreState(s *LoginState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.states[s.StateToken] = s
}

// ConsumeState retrieves and atomically consumes a login state, validating expiration and replay.
func (m *StateManager) ConsumeState(stateToken string, now time.Time) (*LoginState, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if strings.TrimSpace(stateToken) == "" {
		return nil, ErrCodeInvalidCallbackState, errors.New("state token is empty")
	}

	state, ok := m.states[stateToken]
	if !ok {
		return nil, ErrCodeInvalidCallbackState, fmt.Errorf("state token '%s' not found", stateToken)
	}

	if state.Consumed {
		return nil, ErrCodeStateReplayed, fmt.Errorf("state token '%s' was already consumed", stateToken)
	}

	if !now.Before(state.ExpiresAt) {
		return nil, ErrCodeStateExpired, fmt.Errorf("state token expired at %s (evaluated at %s)", state.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	state.Consumed = true
	cTime := now.UTC()
	state.ConsumedAt = &cTime

	return state, "", nil
}

// NonceTracker provides thread-safe single-use nonce tracking to prevent replay attacks.
type NonceTracker struct {
	mu     sync.Mutex
	nonces map[string]time.Time
}

// NewNonceTracker constructs an in-memory NonceTracker.
func NewNonceTracker() *NonceTracker {
	return &NonceTracker{
		nonces: make(map[string]time.Time),
	}
}

// ConsumeNonce checks whether a nonce was already consumed; if not, marks it consumed.
func (t *NonceTracker) ConsumeNonce(nonce string, now time.Time) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return ErrCodeMissingNonce, errors.New("nonce is empty")
	}

	if _, exists := t.nonces[trimmed]; exists {
		return ErrCodeNonceReplay, fmt.Errorf("nonce '%s' has already been consumed (replay detected)", trimmed)
	}

	t.nonces[trimmed] = now.UTC()
	return "", nil
}

// PreloadNonce marks a nonce as already consumed (used for negative replay fixtures).
func (t *NonceTracker) PreloadNonce(nonce string, consumedAt time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nonces[strings.TrimSpace(nonce)] = consumedAt.UTC()
}

// TrustedKey describes a trusted verification key.
type TrustedKey struct {
	KeyID            string            `json:"kid"`
	Issuer           string            `json:"issuer"`
	Algorithm        string            `json:"alg"` // RS256, EdDSA, HS256
	PublicKeyPEM     string            `json:"public_key_pem,omitempty"`
	PublicKeyHex     string            `json:"public_key_hex,omitempty"`
	SecretHex        string            `json:"secret_hex,omitempty"`
	Ed25519PublicKey ed25519.PublicKey `json:"-"`
	RSAPublicKey     *rsa.PublicKey    `json:"-"`
	HMACSecret       []byte            `json:"-"`
}

// KeySet manages a collection of trusted verification keys.
type KeySet struct {
	mu   sync.RWMutex
	keys map[string]*TrustedKey
}

// NewKeySet initializes an empty KeySet.
func NewKeySet() *KeySet {
	return &KeySet{
		keys: make(map[string]*TrustedKey),
	}
}

// AddKey registers a TrustedKey into the KeySet.
func (ks *KeySet) AddKey(k TrustedKey) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	keyCopy := k

	switch k.Algorithm {
	case AlgEdDSA:
		if len(k.Ed25519PublicKey) == 0 && k.PublicKeyHex != "" {
			raw, err := hex.DecodeString(k.PublicKeyHex)
			if err != nil {
				return fmt.Errorf("invalid hex for Ed25519 key '%s': %w", k.KeyID, err)
			}
			if len(raw) != ed25519.PublicKeySize {
				return fmt.Errorf("ed25519 public key '%s' must be 32 bytes, got %d", k.KeyID, len(raw))
			}
			keyCopy.Ed25519PublicKey = ed25519.PublicKey(raw)
		}
	case AlgRS256:
		if keyCopy.RSAPublicKey == nil && k.PublicKeyPEM != "" {
			block, _ := pem.Decode([]byte(k.PublicKeyPEM))
			if block == nil {
				return fmt.Errorf("invalid PEM for RSA key '%s'", k.KeyID)
			}
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				// Try PKCS#1
				rsaPub, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
				if err2 != nil {
					return fmt.Errorf("failed to parse RSA public key '%s': %v / %v", k.KeyID, err, err2)
				}
				keyCopy.RSAPublicKey = rsaPub
			} else {
				rsaPub, ok := pub.(*rsa.PublicKey)
				if !ok {
					return fmt.Errorf("key '%s' in PEM is not an RSA public key", k.KeyID)
				}
				keyCopy.RSAPublicKey = rsaPub
			}
		}
	case AlgHS256:
		if len(keyCopy.HMACSecret) == 0 && k.SecretHex != "" {
			raw, err := hex.DecodeString(k.SecretHex)
			if err != nil {
				return fmt.Errorf("invalid hex for HMAC secret '%s': %w", k.KeyID, err)
			}
			keyCopy.HMACSecret = raw
		}
	default:
		return fmt.Errorf("unsupported algorithm '%s' for key '%s'", k.Algorithm, k.KeyID)
	}

	ks.keys[k.KeyID] = &keyCopy
	return nil
}

// LookupKey returns a trusted key by ID.
func (ks *KeySet) LookupKey(kid string) (*TrustedKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	k, ok := ks.keys[kid]
	return k, ok
}

// OIDCConfig holds the identity provider and token validation parameters.
type OIDCConfig struct {
	Issuer            string        `json:"issuer"`
	ClientID          string        `json:"client_id"`
	AllowedAlgorithms []string      `json:"allowed_algorithms"`
	ClockSkewLeeway   time.Duration `json:"clock_skew_leeway,omitempty"`
	DefaultStateTTL   time.Duration `json:"default_state_ttl,omitempty"`
	RequireNonce      bool          `json:"require_nonce"`
	KeySet            *KeySet       `json:"-"`
}

// JWTHeader represents the header of a signed JWT.
type JWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

// CallbackValidationRequest contains the parameters for validating an OIDC callback and ID token.
type CallbackValidationRequest struct {
	StateToken               string `json:"state_token"`
	RawIDToken               string `json:"raw_id_token"`
	EvaluationTime           string `json:"evaluation_time,omitempty"`
	UntrustedHeadersStripped bool   `json:"untrusted_headers_stripped"`
	TargetOwnerScope         string `json:"target_owner_scope,omitempty"`
	Action                   string `json:"action,omitempty"`
	ResourceClassification   string `json:"resource_classification,omitempty"`
	ProviderUnavailable      bool   `json:"provider_unavailable,omitempty"`
}

// ValidationResult is the typed outcome of an OIDC token and callback validation.
type ValidationResult struct {
	Valid              bool                   `json:"valid"`
	ErrorCode          string                 `json:"error_code,omitempty"`
	ErrorMessage       string                 `json:"error_message,omitempty"`
	Claims             *IDTokenClaims         `json:"claims,omitempty"`
	Identity           storage.CallerIdentity `json:"identity"`
	Subject            policy.SubjectIdentity `json:"subject"`
	SessionEpoch       int64                  `json:"session_epoch"`
	AuthorizedForScope bool                   `json:"authorized_for_scope"`
}

// OIDCValidator validates login states, nonces, and cryptographic tokens.
type OIDCValidator struct {
	config       OIDCConfig
	stateManager *StateManager
	nonceTracker *NonceTracker
}

// NewOIDCValidator constructs a new OIDCValidator instance.
func NewOIDCValidator(cfg OIDCConfig, stateMgr *StateManager, nonceTracker *NonceTracker) *OIDCValidator {
	if stateMgr == nil {
		stateMgr = NewStateManager()
	}
	if nonceTracker == nil {
		nonceTracker = NewNonceTracker()
	}
	if len(cfg.AllowedAlgorithms) == 0 {
		cfg.AllowedAlgorithms = []string{AlgRS256, AlgEdDSA, AlgHS256}
	}
	return &OIDCValidator{
		config:       cfg,
		stateManager: stateMgr,
		nonceTracker: nonceTracker,
	}
}

// StateManager returns the underlying state manager.
func (v *OIDCValidator) StateManager() *StateManager {
	return v.stateManager
}

// NonceTracker returns the underlying nonce tracker.
func (v *OIDCValidator) NonceTracker() *NonceTracker {
	return v.nonceTracker
}

// ParseAndVerifyToken parses and cryptographically verifies a compact JWT.
func (v *OIDCValidator) ParseAndVerifyToken(rawToken string, evalTime time.Time) (*IDTokenClaims, string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, ErrCodeMalformedToken, errors.New("compact JWT must contain exactly three parts separated by dots")
	}

	// 1. Decode and validate header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrCodeMalformedToken, fmt.Errorf("failed to decode JWT header base64url: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrCodeMalformedToken, fmt.Errorf("failed to parse JWT header JSON: %w", err)
	}

	// Reject alg: none unconditionally
	if strings.EqualFold(header.Algorithm, "none") || header.Algorithm == "" {
		return nil, ErrCodeUntrustedSigner, errors.New("algorithm 'none' or empty algorithm is forbidden")
	}

	// Check against allowed algorithms
	algAllowed := false
	for _, allowed := range v.config.AllowedAlgorithms {
		if header.Algorithm == allowed {
			algAllowed = true
			break
		}
	}
	if !algAllowed {
		return nil, ErrCodeUntrustedSigner, fmt.Errorf("algorithm '%s' is not in allowed list %v", header.Algorithm, v.config.AllowedAlgorithms)
	}

	// 2. Decode signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrCodeInvalidTokenSignature, fmt.Errorf("failed to decode signature base64url: %w", err)
	}

	// 3. Lookup trusted key
	if v.config.KeySet == nil {
		return nil, ErrCodeUntrustedSigner, errors.New("no trusted KeySet configured on validator")
	}
	trustedKey, ok := v.config.KeySet.LookupKey(header.KeyID)
	if !ok {
		return nil, ErrCodeUntrustedSigner, fmt.Errorf("untrusted signer key_id '%s'", header.KeyID)
	}

	if trustedKey.Algorithm != header.Algorithm {
		return nil, ErrCodeUntrustedSigner, fmt.Errorf("key '%s' algorithm '%s' does not match token header algorithm '%s'", header.KeyID, trustedKey.Algorithm, header.Algorithm)
	}

	// 4. Verify signature cryptographically
	signingInput := parts[0] + "." + parts[1]
	switch header.Algorithm {
	case AlgRS256:
		if trustedKey.RSAPublicKey == nil {
			return nil, ErrCodeUntrustedSigner, fmt.Errorf("RSA public key is nil for kid '%s'", header.KeyID)
		}
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(trustedKey.RSAPublicKey, crypto.SHA256, digest[:], sigBytes); err != nil {
			return nil, ErrCodeInvalidTokenSignature, fmt.Errorf("RSA signature verification failed: %v", err)
		}
	case AlgEdDSA:
		if len(trustedKey.Ed25519PublicKey) != ed25519.PublicKeySize {
			return nil, ErrCodeUntrustedSigner, fmt.Errorf("invalid Ed25519 public key size for kid '%s'", header.KeyID)
		}
		if !ed25519.Verify(trustedKey.Ed25519PublicKey, []byte(signingInput), sigBytes) {
			return nil, ErrCodeInvalidTokenSignature, errors.New("Ed25519 signature verification failed")
		}
	case AlgHS256:
		if len(trustedKey.HMACSecret) == 0 {
			return nil, ErrCodeUntrustedSigner, fmt.Errorf("HMAC secret is empty for kid '%s'", header.KeyID)
		}
		mac := hmac.New(sha256.New, trustedKey.HMACSecret)
		mac.Write([]byte(signingInput))
		expectedSig := mac.Sum(nil)
		if !hmac.Equal(sigBytes, expectedSig) {
			return nil, ErrCodeInvalidTokenSignature, errors.New("HMAC-SHA256 signature verification failed")
		}
	default:
		return nil, ErrCodeUntrustedSigner, fmt.Errorf("unsupported signature algorithm '%s'", header.Algorithm)
	}

	// 5. Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrCodeMalformedToken, fmt.Errorf("failed to decode payload base64url: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrCodeMalformedToken, fmt.Errorf("failed to parse claims JSON: %w", err)
	}

	// 6. Validate Claims
	// A. Issuer
	if v.config.Issuer != "" && claims.Issuer != v.config.Issuer {
		return nil, ErrCodeWrongIssuer, fmt.Errorf("wrong issuer: expected '%s', got '%s'", v.config.Issuer, claims.Issuer)
	}

	// B. Audience
	if v.config.ClientID != "" && !claims.Audience.Contains(v.config.ClientID) {
		return nil, ErrCodeWrongAudience, fmt.Errorf("wrong audience: token aud %v does not contain expected client_id '%s'", claims.Audience, v.config.ClientID)
	}

	// C. Expiration
	nowUnix := evalTime.Unix()
	leeway := int64(v.config.ClockSkewLeeway / time.Second)
	if claims.ExpiresAt <= (nowUnix - leeway) {
		return nil, ErrCodeExpiredToken, fmt.Errorf("token expired at %s (evaluated at %s)", time.Unix(claims.ExpiresAt, 0).UTC().Format(time.RFC3339), evalTime.Format(time.RFC3339))
	}

	// D. Not Before
	if claims.NotBefore > 0 && claims.NotBefore > (nowUnix+leeway) {
		return nil, ErrCodeTokenNotYetValid, fmt.Errorf("token not valid until %s (evaluated at %s)", time.Unix(claims.NotBefore, 0).UTC().Format(time.RFC3339), evalTime.Format(time.RFC3339))
	}

	// E. Subject must not be empty
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, ErrCodeUnauthenticatedIdentity, errors.New("token subject (sub) claim is missing or empty")
	}

	return &claims, "", nil
}

// ValidateCallback executes full OIDC callback validation.
func (v *OIDCValidator) ValidateCallback(ctx context.Context, req CallbackValidationRequest) (*ValidationResult, error) {
	res := &ValidationResult{
		Valid: false,
		Identity: storage.CallerIdentity{
			Authenticated:            false,
			UntrustedHeadersStripped: req.UntrustedHeadersStripped,
		},
		Subject: policy.SubjectIdentity{
			Authenticated: false,
		},
	}

	evalTime := time.Now().UTC()
	if req.EvaluationTime != "" {
		parsed, err := time.Parse(time.RFC3339, req.EvaluationTime)
		if err != nil {
			res.ErrorCode = ErrCodeInvalidValidationRequest
			res.ErrorMessage = fmt.Sprintf("invalid evaluation_time format: %v", err)
			return res, nil
		}
		evalTime = parsed.UTC()
	}

	// Invariant 1: Provider outage fails closed
	if req.ProviderUnavailable {
		res.ErrorCode = ErrCodeProviderUnavailable
		res.ErrorMessage = "identity provider is unreachable or returned service outage; failing closed"
		res.Identity.ProviderState = "unavailable"
		return res, nil
	}

	// Invariant 2: Untrusted headers must be stripped at gateway boundary
	if !req.UntrustedHeadersStripped {
		res.ErrorCode = ErrCodeForgedHeader
		res.ErrorMessage = "untrusted gateway headers were not stripped; rejecting forged request"
		return res, nil
	}

	// Step 1: Validate and consume State token
	state, stateErrCode, stateErr := v.stateManager.ConsumeState(req.StateToken, evalTime)
	if stateErr != nil {
		res.ErrorCode = stateErrCode
		res.ErrorMessage = stateErr.Error()
		if req.ResourceClassification == "private" || req.ResourceClassification == "restricted" {
			res.ErrorCode = ErrCodePrivateFailClosed
		}
		return res, nil
	}

	// Step 2: Parse and verify token signature and claims
	claims, tokErrCode, tokErr := v.ParseAndVerifyToken(req.RawIDToken, evalTime)
	if tokErr != nil {
		res.ErrorCode = tokErrCode
		res.ErrorMessage = tokErr.Error()
		if req.ResourceClassification == "private" || req.ResourceClassification == "restricted" {
			// Retain specific error unless general authentication failure
			if tokErrCode == ErrCodeUnauthenticatedIdentity || tokErrCode == ErrCodeInvalidTokenSignature {
				res.ErrorCode = ErrCodePrivateFailClosed
			}
		}
		return res, nil
	}
	res.Claims = claims

	// Step 3: Validate Nonce against state and enforce single-use (replay prevention)
	if state.Nonce != "" || v.config.RequireNonce {
		if claims.Nonce == "" {
			res.ErrorCode = ErrCodeMissingNonce
			res.ErrorMessage = "token is missing required nonce claim"
			return res, nil
		}
		if state.Nonce != "" && claims.Nonce != state.Nonce {
			res.ErrorCode = ErrCodeNonceMismatch
			res.ErrorMessage = fmt.Sprintf("nonce mismatch: token has '%s', expected '%s'", claims.Nonce, state.Nonce)
			return res, nil
		}

		// Check nonce replay
		if nErrCode, nErr := v.nonceTracker.ConsumeNonce(claims.Nonce, evalTime); nErr != nil {
			res.ErrorCode = nErrCode
			res.ErrorMessage = nErr.Error()
			return res, nil
		}
	}

	// Step 4: Extract and normalize roles
	normalizedRoles := claims.NormalizedRoles()
	hasAdmin := false
	for _, r := range normalizedRoles {
		if r == "admin" || r == "platform_admin" {
			hasAdmin = true
			break
		}
	}

	// Step 5: Scope & Authorization validation
	effectiveOwnerScope := claims.OwnerScope
	if effectiveOwnerScope == "" {
		effectiveOwnerScope = claims.Subject
	}

	targetScope := strings.TrimSpace(req.TargetOwnerScope)
	if targetScope != "" && targetScope != "policyhelix" {
		if !hasAdmin && targetScope != effectiveOwnerScope && targetScope != claims.Subject {
			res.ErrorCode = ErrCodeScopeViolation
			res.ErrorMessage = fmt.Sprintf("subject '%s' with owner_scope '%s' is not authorized for target scope '%s'", claims.Subject, effectiveOwnerScope, targetScope)
			res.AuthorizedForScope = false
			return res, nil
		}
	}
	res.AuthorizedForScope = true

	// Step 6: Construct normalized CallerIdentity & SubjectIdentity
	sessionEpoch := claims.IssuedAt
	if sessionEpoch <= 0 {
		sessionEpoch = evalTime.Unix()
	}

	res.Valid = true
	res.SessionEpoch = sessionEpoch
	res.Identity = storage.CallerIdentity{
		SubjectID:                claims.Subject,
		Issuer:                   claims.Issuer,
		Roles:                    normalizedRoles,
		Authenticated:            true,
		SessionEpoch:             sessionEpoch,
		UntrustedHeadersStripped: true,
		ProviderState:            "verified",
	}
	res.Subject = policy.SubjectIdentity{
		ID:            claims.Subject,
		Issuer:        claims.Issuer,
		Roles:         normalizedRoles,
		Authenticated: true,
		SessionEpoch:  sessionEpoch,
	}

	return res, nil
}

// GenerateSyntheticRSAKeyPair generates a deterministic-friendly RSA key pair for testing.
func GenerateSyntheticRSAKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

// GenerateSyntheticEd25519KeyPair generates an Ed25519 key pair for testing.
func GenerateSyntheticEd25519KeyPair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// ExportRSAPublicKeyPEM exports an RSA public key to PKIX PEM string.
func ExportRSAPublicKeyPEM(pub *rsa.PublicKey) (string, error) {
	bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// SignJWT constructs a signed compact JWT for tests and fixtures.
func SignJWT(header JWTHeader, claims IDTokenClaims, signingKey interface{}) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	hB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	cB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := hB64 + "." + cB64

	var sig []byte
	switch header.Algorithm {
	case AlgRS256:
		priv, ok := signingKey.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("signingKey must be *rsa.PrivateKey for RS256")
		}
		digest := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign with RSA: %w", err)
		}
	case AlgEdDSA:
		priv, ok := signingKey.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("signingKey must be ed25519.PrivateKey for EdDSA")
		}
		sig = ed25519.Sign(priv, []byte(signingInput))
	case AlgHS256:
		secret, ok := signingKey.([]byte)
		if !ok {
			return "", errors.New("signingKey must be []byte for HS256")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case "none":
		return signingInput + ".", nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", header.Algorithm)
	}

	sB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sB64, nil
}

// ParseBigInt helper for parsing standard big ints if needed.
func ParseBigInt(s string) *big.Int {
	b, _ := new(big.Int).SetString(s, 10)
	return b
}
