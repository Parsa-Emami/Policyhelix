package bundles

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
)

// Typed error codes for bundle building, signing, and verification (Requirement F04).
const (
	ErrCodeInvalidBundleSpec     = "INVALID_BUNDLE_SPEC"
	ErrCodeSigningFailed         = "BUNDLE_SIGNING_FAILED"
	ErrCodeVerificationFailed    = "BUNDLE_VERIFICATION_FAILED"
	ErrCodeUntrustedSigner       = "UNTRUSTED_OR_MISSING_SIGNER"
	ErrCodeTamperedBundle        = "TAMPERED_BUNDLE_DIGEST"
	ErrCodeStaleOrReplayedRev    = "STALE_OR_REPLAYED_REVISION"
	ErrCodeExpiredBundle         = "EXPIRED_POLICY_BUNDLE"
	ErrCodePrivateFailClosed     = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrCodeMalformedFixture      = "MALFORMED_FIXTURE"
)

// BundleBuildSpec contains the declarative specification for generating a signed deterministic policy bundle.
type BundleBuildSpec struct {
	SchemaVersion string               `json:"schema_version"`
	BundleID      string               `json:"bundle_id"`
	Package       string               `json:"package"`
	Issuer        string               `json:"issuer"`
	SignerKeyID   string               `json:"signer_key_id"`
	PrivateKeyHex string               `json:"private_key_hex,omitempty"` // 64-byte Ed25519 private key (or 32-byte seed)
	SeedHex       string               `json:"seed_hex,omitempty"`        // 32-byte seed for deterministic key derivation
	Revision      int64                `json:"revision"`
	IssuedAt      string               `json:"issued_at"`
	ExpiresAt     string               `json:"expires_at"`
	RegoModule    string               `json:"rego_module"`
	Routes        []policy.RouteRule   `json:"routes"`
	Rules         []policy.PolicyRule  `json:"rules"`
}

// TrustedKey describes a trusted Ed25519 public key and its authorized issuer.
type TrustedKey struct {
	SignerKeyID  string `json:"signer_key_id"`
	Issuer       string `json:"issuer"`
	PublicKeyHex string `json:"public_key_hex"`
}

// Keyring manages trusted Ed25519 verification keys.
type Keyring struct {
	keys map[string]TrustedKey // key: signerKeyID
}

// NewKeyring constructs a Keyring from a list of TrustedKeys.
func NewKeyring(keys ...TrustedKey) *Keyring {
	kr := &Keyring{
		keys: make(map[string]TrustedKey, len(keys)),
	}
	for _, k := range keys {
		kr.keys[k.SignerKeyID] = k
	}
	return kr
}

// DeriveKeyPairFromSeed deterministically derives an Ed25519 keypair from a 32-byte seed.
func DeriveKeyPairFromSeed(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("invalid seed length: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

// DeriveKeyPairFromSeedHex decodes a hex string seed and derives the Ed25519 keypair.
func DeriveKeyPairFromSeedHex(seedHex string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid hex seed: %w", err)
	}
	return DeriveKeyPairFromSeed(raw)
}

// CanonicalSigningPayload returns the exact deterministic byte sequence that is cryptographically signed.
// Format: "policyhelix:bundle:v1\n<canonical-digest>\n<issuer>\n<signer_key_id>\n<revision>\n<issued_at>\n<expires_at>"
func CanonicalSigningPayload(canonicalDigest, issuer, signerKeyID string, revision int64, issuedAt, expiresAt string) []byte {
	msg := fmt.Sprintf("policyhelix:bundle:v1\n%s\n%s\n%s\n%d\n%s\n%s",
		canonicalDigest,
		strings.TrimSpace(issuer),
		strings.TrimSpace(signerKeyID),
		revision,
		strings.TrimSpace(issuedAt),
		strings.TrimSpace(expiresAt),
	)
	return []byte(msg)
}

// BuildDeterministicBundle creates an Ed25519-signed LocalPolicyBundle according to the specification.
// Validates structural bounds, timestamps, canonical content digest, and signs deterministically.
func BuildDeterministicBundle(spec BundleBuildSpec) (policy.LocalPolicyBundle, error) {
	if spec.SchemaVersion == "" {
		spec.SchemaVersion = "1"
	}
	if spec.SchemaVersion != "1" {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: unsupported schema_version '%s'", ErrCodeInvalidBundleSpec, spec.SchemaVersion)
	}
	if strings.TrimSpace(spec.BundleID) == "" || strings.TrimSpace(spec.Package) == "" {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: bundle_id and package must not be empty", ErrCodeInvalidBundleSpec)
	}
	if strings.TrimSpace(spec.Issuer) == "" || strings.TrimSpace(spec.SignerKeyID) == "" {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: issuer and signer_key_id must not be empty", ErrCodeInvalidBundleSpec)
	}
	if spec.Revision < 1 {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: revision must be >= 1", ErrCodeInvalidBundleSpec)
	}

	// Validate RFC3339 timestamps
	issuedAtTime, err := time.Parse(time.RFC3339, spec.IssuedAt)
	if err != nil {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: issued_at must be valid RFC3339: %w", ErrCodeInvalidBundleSpec, err)
	}
	expiresAtTime, err := time.Parse(time.RFC3339, spec.ExpiresAt)
	if err != nil {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: expires_at must be valid RFC3339: %w", ErrCodeInvalidBundleSpec, err)
	}
	if !expiresAtTime.After(issuedAtTime) {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: expires_at must be after issued_at", ErrCodeInvalidBundleSpec)
	}

	// Resolve Ed25519 private key
	var privKey ed25519.PrivateKey
	if strings.TrimSpace(spec.SeedHex) != "" {
		_, priv, err := DeriveKeyPairFromSeedHex(spec.SeedHex)
		if err != nil {
			return policy.LocalPolicyBundle{}, fmt.Errorf("%s: invalid seed_hex: %w", ErrCodeSigningFailed, err)
		}
		privKey = priv
	} else if strings.TrimSpace(spec.PrivateKeyHex) != "" {
		keyBytes, err := hex.DecodeString(strings.TrimSpace(spec.PrivateKeyHex))
		if err != nil {
			return policy.LocalPolicyBundle{}, fmt.Errorf("%s: invalid private_key_hex: %w", ErrCodeSigningFailed, err)
		}
		if len(keyBytes) == ed25519.SeedSize {
			privKey = ed25519.NewKeyFromSeed(keyBytes)
		} else if len(keyBytes) == ed25519.PrivateKeySize {
			privKey = ed25519.PrivateKey(keyBytes)
		} else {
			return policy.LocalPolicyBundle{}, fmt.Errorf("%s: invalid private key length: expected 32 or 64 bytes, got %d", ErrCodeSigningFailed, len(keyBytes))
		}
	} else {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: either seed_hex or private_key_hex is required to sign bundle", ErrCodeSigningFailed)
	}

	// Construct preliminary bundle to calculate canonical content digest
	bundle := policy.LocalPolicyBundle{
		SchemaVersion:     spec.SchemaVersion,
		BundleID:          strings.TrimSpace(spec.BundleID),
		Package:           strings.TrimSpace(spec.Package),
		Issuer:            strings.TrimSpace(spec.Issuer),
		SignerKeyID:       strings.TrimSpace(spec.SignerKeyID),
		Revision:          spec.Revision,
		IssuedAt:          spec.IssuedAt,
		ExpiresAt:         spec.ExpiresAt,
		RegoModule:        spec.RegoModule,
		Routes:            spec.Routes,
		Rules:             spec.Rules,
		SignatureVerified: false,
	}

	digest := policy.ComputeCanonicalBundleDigest(bundle)
	if digest == "" {
		return policy.LocalPolicyBundle{}, fmt.Errorf("%s: failed to compute canonical bundle digest", ErrCodeInvalidBundleSpec)
	}
	bundle.Digest = digest

	// Compute Ed25519 signature over canonical signing payload
	signingPayload := CanonicalSigningPayload(digest, bundle.Issuer, bundle.SignerKeyID, bundle.Revision, bundle.IssuedAt, bundle.ExpiresAt)
	sigBytes := ed25519.Sign(privKey, signingPayload)
	bundle.Signature = "ed25519:" + hex.EncodeToString(sigBytes)
	bundle.SignatureVerified = true

	return bundle, nil
}

// VerifyBundleSignature checks the cryptographic Ed25519 signature of the bundle against trusted keys.
func VerifyBundleSignature(bundle policy.LocalPolicyBundle, keyring *Keyring) error {
	if keyring == nil || len(keyring.keys) == 0 {
		return fmt.Errorf("%s: no trusted keys configured in keyring", ErrCodeUntrustedSigner)
	}

	trustedKey, ok := keyring.keys[bundle.SignerKeyID]
	if !ok {
		return fmt.Errorf("%s: signer_key_id '%s' is not in trusted keyring", ErrCodeUntrustedSigner, bundle.SignerKeyID)
	}

	if trustedKey.Issuer != "" && trustedKey.Issuer != bundle.Issuer {
		return fmt.Errorf("%s: bundle issuer '%s' does not match trusted key issuer '%s'", ErrCodeUntrustedSigner, bundle.Issuer, trustedKey.Issuer)
	}

	pubBytes, err := hex.DecodeString(strings.TrimSpace(trustedKey.PublicKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("%s: malformed trusted public key for '%s'", ErrCodeUntrustedSigner, bundle.SignerKeyID)
	}
	pubKey := ed25519.PublicKey(pubBytes)

	if !strings.HasPrefix(bundle.Signature, "ed25519:") {
		return fmt.Errorf("%s: unsupported or missing signature algorithm prefix in '%s'", ErrCodeVerificationFailed, bundle.Signature)
	}

	sigHex := strings.TrimPrefix(bundle.Signature, "ed25519:")
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%s: malformed signature bytes in bundle", ErrCodeVerificationFailed)
	}

	// Verify content digest integrity first (detects single-byte changes)
	computedDigest := policy.ComputeCanonicalBundleDigest(bundle)
	if computedDigest != bundle.Digest {
		return fmt.Errorf("%s: declared digest %s does not match canonical %s", ErrCodeTamperedBundle, bundle.Digest, computedDigest)
	}

	signingPayload := CanonicalSigningPayload(bundle.Digest, bundle.Issuer, bundle.SignerKeyID, bundle.Revision, bundle.IssuedAt, bundle.ExpiresAt)
	if !ed25519.Verify(pubKey, signingPayload, sigBytes) {
		return fmt.Errorf("%s: cryptographic signature verification failed for signer '%s'", ErrCodeVerificationFailed, bundle.SignerKeyID)
	}

	return nil
}

// BundleAuthorityManager oversees bundle acceptance, monotonic revision progression,
// and fail-closed evaluation integration.
type BundleAuthorityManager struct {
	keyring         *Keyring
	evaluator       *policy.BundleEvaluator
	highestRevision int64
	activeBundle    *policy.LocalPolicyBundle
}

// NewBundleAuthorityManager creates an authority manager with a trusted keyring.
func NewBundleAuthorityManager(keyring *Keyring) *BundleAuthorityManager {
	trustedIssuers := make([]string, 0, len(keyring.keys))
	trustedSigners := make([]string, 0, len(keyring.keys))
	for signerID, tk := range keyring.keys {
		trustedSigners = append(trustedSigners, signerID)
		if tk.Issuer != "" {
			trustedIssuers = append(trustedIssuers, tk.Issuer)
		}
	}
	evaluator := policy.NewBundleEvaluator(trustedIssuers, trustedSigners)
	return &BundleAuthorityManager{
		keyring:   keyring,
		evaluator: evaluator,
	}
}

// IngestBundle validates and activates a bundle, strictly rejecting tampered, untrusted,
// expired, or stale/replayed bundles, and preserving previous valid authority on error.
func (bam *BundleAuthorityManager) IngestBundle(b policy.LocalPolicyBundle, evalTime time.Time) error {
	if evalTime.IsZero() {
		evalTime = time.Now().UTC()
	}

	// 1. Verify cryptographic signature & digest integrity
	if err := VerifyBundleSignature(b, bam.keyring); err != nil {
		return err
	}

	// 2. Enforce monotonic revision: strictly greater than highest accepted revision
	if bam.highestRevision > 0 && b.Revision <= bam.highestRevision {
		return fmt.Errorf("%s: candidate revision %d is not strictly greater than active accepted revision %d",
			ErrCodeStaleOrReplayedRev, b.Revision, bam.highestRevision)
	}

	// 3. Load into evaluator (validates syntax, routes, rules, validity window)
	bErr := bam.evaluator.LoadBundle(b, evalTime)
	if bErr != nil {
		return fmt.Errorf("%s: %s", bErr.Code, bErr.Message)
	}

	bCopy := b
	bam.activeBundle = &bCopy
	bam.highestRevision = b.Revision
	return nil
}

// ActiveBundle returns the currently accepted authoritative bundle and whether one is loaded.
func (bam *BundleAuthorityManager) ActiveBundle() (policy.LocalPolicyBundle, bool) {
	if bam.activeBundle == nil {
		return policy.LocalPolicyBundle{}, false
	}
	return *bam.activeBundle, true
}

// HighestRevision returns the highest accepted monotonic revision.
func (bam *BundleAuthorityManager) HighestRevision() int64 {
	return bam.highestRevision
}

// Evaluate performs an authorization check against the active policy authority.
func (bam *BundleAuthorityManager) Evaluate(ctx context.Context, input policy.BundleEvalInput) policy.BundleDecision {
	return bam.evaluator.Evaluate(ctx, input)
}

// BundleFixture defines a test fixture structure for C10 bundle verification scenarios.
type BundleFixture struct {
	FixtureID       string                  `json:"fixture_id"`
	CommitID        string                  `json:"commit_id,omitempty"`
	Description     string                  `json:"description,omitempty"`
	TrustedKeys     []TrustedKey            `json:"trusted_keys"`
	BuildSpec       *BundleBuildSpec        `json:"build_spec,omitempty"`
	PreloadBundle   *policy.LocalPolicyBundle `json:"preload_bundle,omitempty"`
	CandidateBundle *policy.LocalPolicyBundle `json:"candidate_bundle,omitempty"`
	TamperAction    string                  `json:"tamper_action,omitempty"` // e.g. "modify_rego_byte", "modify_signature_byte"
	Input           policy.BundleEvalInput  `json:"input"`
	Expected        struct {
		BuildSuccess      bool   `json:"build_success"`
		IngestSuccess     bool   `json:"ingest_success"`
		ErrorCode         string `json:"error_code,omitempty"`
		Allow             bool   `json:"allow"`
		ReasonCode        string `json:"reason_code,omitempty"`
		RetainedRevision  int64  `json:"retained_revision,omitempty"`
		Issuer            string `json:"issuer,omitempty"`
		Revision          int64  `json:"revision,omitempty"`
		DigestNotEmpty    bool   `json:"digest_not_empty,omitempty"`
		ValidityWindowOk  bool   `json:"validity_window_ok,omitempty"`
	} `json:"expected"`
}

// RunBundleFixture executes a C10 BundleFixture and asserts acceptance and negative criteria.
func RunBundleFixture(ctx context.Context, fx BundleFixture) (bool, string, error) {
	keyring := NewKeyring(fx.TrustedKeys...)
	bam := NewBundleAuthorityManager(keyring)

	evalTime := time.Now().UTC()
	if fx.Input.EvalTime != "" {
		if t, err := time.Parse(time.RFC3339, fx.Input.EvalTime); err == nil {
			evalTime = t
		}
	}

	// 1. Preload baseline bundle if specified
	if fx.PreloadBundle != nil {
		if err := bam.IngestBundle(*fx.PreloadBundle, evalTime); err != nil {
			return false, "", fmt.Errorf("preload bundle ingestion failed: %w", err)
		}
	}

	var candidate policy.LocalPolicyBundle
	if fx.BuildSpec != nil {
		built, err := BuildDeterministicBundle(*fx.BuildSpec)
		if err != nil {
			if !fx.Expected.BuildSuccess {
				return true, "", nil
			}
			return false, "", fmt.Errorf("build failed unexpectedly: %w", err)
		}
		candidate = built
	} else if fx.CandidateBundle != nil {
		candidate = *fx.CandidateBundle
	}

	// Apply simulated tampering if requested
	switch fx.TamperAction {
	case "modify_rego_byte":
		candidate.RegoModule += "\n# tampered"
	case "modify_signature_byte":
		if strings.HasPrefix(candidate.Signature, "ed25519:") {
			sigHex := strings.TrimPrefix(candidate.Signature, "ed25519:")
			if len(sigHex) > 2 {
				// flip last character
				last := sigHex[len(sigHex)-1]
				replacement := "a"
				if last == 'a' {
					replacement = "b"
				}
				candidate.Signature = "ed25519:" + sigHex[:len(sigHex)-1] + replacement
			}
		}
	case "modify_digest_byte":
		candidate.Digest += "0"
	}

	// Verify required acceptance attributes
	if fx.Expected.Issuer != "" && candidate.Issuer != fx.Expected.Issuer {
		return false, "", fmt.Errorf("bundle issuer mismatch: expected %s, got %s", fx.Expected.Issuer, candidate.Issuer)
	}
	if fx.Expected.Revision > 0 && candidate.Revision != fx.Expected.Revision {
		return false, "", fmt.Errorf("bundle revision mismatch: expected %d, got %d", fx.Expected.Revision, candidate.Revision)
	}
	if fx.Expected.DigestNotEmpty && !strings.HasPrefix(candidate.Digest, "sha256:") {
		return false, "", fmt.Errorf("bundle digest format mismatch: %s", candidate.Digest)
	}
	if fx.Expected.ValidityWindowOk {
		if candidate.IssuedAt == "" || candidate.ExpiresAt == "" {
			return false, "", errors.New("validity window missing issued_at or expires_at")
		}
	}

	// Ingest candidate bundle
	err := bam.IngestBundle(candidate, evalTime)
	if err != nil {
		if fx.Expected.IngestSuccess {
			return false, "", fmt.Errorf("expected ingest success, but failed: %w", err)
		}
		if fx.Expected.ErrorCode != "" && !strings.Contains(err.Error(), fx.Expected.ErrorCode) {
			return false, "", fmt.Errorf("expected error code %s, got: %v", fx.Expected.ErrorCode, err)
		}
		if fx.Expected.RetainedRevision > 0 && bam.HighestRevision() != fx.Expected.RetainedRevision {
			return false, "", fmt.Errorf("expected retained revision %d, got %d", fx.Expected.RetainedRevision, bam.HighestRevision())
		}
		// Ingest failure matched expected
		return true, candidate.Digest, nil
	}

	if !fx.Expected.IngestSuccess {
		return false, candidate.Digest, fmt.Errorf("expected ingest failure with code %s, but succeeded", fx.Expected.ErrorCode)
	}

	// Evaluate authorization input against the active authority
	decision := bam.Evaluate(ctx, fx.Input)
	if decision.Allow != fx.Expected.Allow {
		return false, candidate.Digest, fmt.Errorf("expected allow=%v, got %v (reasons=%v)", fx.Expected.Allow, decision.Allow, decision.Reasons)
	}
	if fx.Expected.ReasonCode != "" {
		found := false
		for _, r := range decision.Reasons {
			if r == fx.Expected.ReasonCode {
				found = true
				break
			}
		}
		if !found {
			return false, candidate.Digest, fmt.Errorf("expected reason code %s in reasons %v", fx.Expected.ReasonCode, decision.Reasons)
		}
	}

	return true, candidate.Digest, nil
}
