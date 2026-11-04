package bundles

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/parsa-emami/policyhelix/internal/policy"
)

// ErrCodeInvalidVerificationRequest marks a malformed verification request rather than a bundle rejection (Requirement F05).
const ErrCodeInvalidVerificationRequest = "INVALID_VERIFICATION_REQUEST"

// Verification status values returned by VerifyBundle.
const (
	VerificationStatusVerified = "verified"
	VerificationStatusRejected = "rejected"
)

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

// TrustedKeys returns the configured trust anchors in deterministic key-ID order.
func (k *Keyring) TrustedKeys() []TrustedKey {
	if k == nil {
		return []TrustedKey{}
	}
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]TrustedKey, 0, len(ids))
	for _, id := range ids {
		out = append(out, k.keys[id])
	}
	return out
}

// NewEvaluator constructs a bounded bundle evaluator whose trusted issuer and signer sets match this keyring.
func (k *Keyring) NewEvaluator() *policy.BundleEvaluator {
	trustedIssuers := make([]string, 0, len(k.keys))
	trustedSigners := make([]string, 0, len(k.keys))
	if k != nil {
		for signerID, tk := range k.keys {
			trustedSigners = append(trustedSigners, signerID)
			if tk.Issuer != "" {
				trustedIssuers = append(trustedIssuers, tk.Issuer)
			}
		}
	}
	return policy.NewBundleEvaluator(trustedIssuers, trustedSigners)
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

// BundleVerificationRequest is the versioned input for verifying bundle trust and freshness before ingestion.
type BundleVerificationRequest struct {
	SchemaVersion   string                   `json:"schema_version"`
	TrustedKeys     []TrustedKey             `json:"trusted_keys"`
	Bundle          policy.LocalPolicyBundle `json:"bundle"`
	EvaluationTime  string                   `json:"evaluation_time,omitempty"`
	MinimumRevision int64                    `json:"minimum_revision,omitempty"`
}

// BundleVerification is the typed verification outcome. A rejected bundle never reports Verified=true.
type BundleVerification struct {
	SchemaVersion string `json:"schema_version"`
	Verified      bool   `json:"verified"`
	Status        string `json:"status"`
	ErrorCode     string `json:"error_code,omitempty"`
	Message       string `json:"message,omitempty"`
	BundleID      string `json:"bundle_id,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
	SignerKeyID   string `json:"signer_key_id,omitempty"`
	Revision      int64  `json:"revision,omitempty"`
	Digest        string `json:"digest,omitempty"`
	IssuedAt      string `json:"issued_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	CheckedAt     string `json:"checked_at,omitempty"`
}

type verificationFailure struct {
	code    string
	message string
}

func rejectedVerification(v BundleVerification, failure *verificationFailure) BundleVerification {
	v.Verified = false
	v.Status = VerificationStatusRejected
	v.ErrorCode = failure.code
	v.Message = failure.message
	return v
}

// VerifyBundle verifies cryptographic trust evidence and freshness before a bundle may be ingested.
// It is stateless: the caller supplies the trusted keyring and the accepted-authority revision floor.
func VerifyBundle(req BundleVerificationRequest) BundleVerification {
	schemaVersion := strings.TrimSpace(req.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = "1"
	}

	v := BundleVerification{
		SchemaVersion: schemaVersion,
		Status:        VerificationStatusRejected,
		BundleID:      strings.TrimSpace(req.Bundle.BundleID),
		Issuer:        strings.TrimSpace(req.Bundle.Issuer),
		SignerKeyID:   strings.TrimSpace(req.Bundle.SignerKeyID),
		Revision:      req.Bundle.Revision,
		Digest:        strings.TrimSpace(req.Bundle.Digest),
		IssuedAt:      strings.TrimSpace(req.Bundle.IssuedAt),
		ExpiresAt:     strings.TrimSpace(req.Bundle.ExpiresAt),
	}

	if schemaVersion != "1" {
		return rejectedVerification(v, &verificationFailure{
			code:    ErrCodeInvalidVerificationRequest,
			message: fmt.Sprintf("unsupported verification schema_version '%s'; expected '1'", schemaVersion),
		})
	}
	if req.MinimumRevision < 0 {
		return rejectedVerification(v, &verificationFailure{
			code:    ErrCodeInvalidVerificationRequest,
			message: "minimum_revision must be zero or greater",
		})
	}

	evalTime := time.Now().UTC()
	if strings.TrimSpace(req.EvaluationTime) != "" {
		parsed, err := time.Parse(time.RFC3339, req.EvaluationTime)
		if err != nil {
			return rejectedVerification(v, &verificationFailure{
				code:    ErrCodeInvalidVerificationRequest,
				message: fmt.Sprintf("evaluation_time must be valid RFC3339: %v", err),
			})
		}
		evalTime = parsed.UTC()
	}
	v.CheckedAt = evalTime.Format(time.RFC3339)

	return verifyAt(req.Bundle, NewKeyring(req.TrustedKeys...), evalTime, req.MinimumRevision, v)
}

// verifyAt is the single trust and freshness gate shared by standalone verification and bundle ingestion.
// Any failure rejects the candidate without mutating accepted authority.
func verifyAt(b policy.LocalPolicyBundle, keyring *Keyring, evalTime time.Time, minimumRevision int64, v BundleVerification) BundleVerification {
	v.CheckedAt = evalTime.UTC().Format(time.RFC3339)

	if strings.TrimSpace(b.SchemaVersion) != "1" {
		return rejectedVerification(v, &verificationFailure{
			code:    ErrCodeInvalidBundleSpec,
			message: fmt.Sprintf("unsupported bundle schema_version '%s'; expected '1'", b.SchemaVersion),
		})
	}

	if failure := verifyTrustEvidence(b, keyring); failure != nil {
		return rejectedVerification(v, failure)
	}
	if failure := verifyFreshness(b, evalTime, minimumRevision); failure != nil {
		return rejectedVerification(v, failure)
	}

	v.Verified = true
	v.Status = VerificationStatusVerified
	v.ErrorCode = ""
	v.Message = ""
	v.BundleID = strings.TrimSpace(b.BundleID)
	v.Issuer = strings.TrimSpace(b.Issuer)
	v.SignerKeyID = strings.TrimSpace(b.SignerKeyID)
	v.Revision = b.Revision
	v.Digest = strings.TrimSpace(b.Digest)
	v.IssuedAt = strings.TrimSpace(b.IssuedAt)
	v.ExpiresAt = strings.TrimSpace(b.ExpiresAt)
	return v
}

// verifyTrustEvidence checks signature presence, signer trust, digest integrity and the Ed25519 signature.
func verifyTrustEvidence(bundle policy.LocalPolicyBundle, keyring *Keyring) *verificationFailure {
	if keyring == nil || len(keyring.keys) == 0 {
		return &verificationFailure{
			code:    ErrCodeUntrustedSigner,
			message: "no trusted keys configured in keyring",
		}
	}

	if strings.TrimSpace(bundle.Signature) == "" || !bundle.SignatureVerified ||
		strings.TrimSpace(bundle.SignerKeyID) == "" || strings.TrimSpace(bundle.Issuer) == "" {
		return &verificationFailure{
			code:    ErrCodeUntrustedSigner,
			message: "bundle is missing cryptographic signature evidence or signer verification",
		}
	}

	trustedKey, ok := keyring.keys[bundle.SignerKeyID]
	if !ok {
		return &verificationFailure{
			code:    ErrCodeUntrustedSigner,
			message: fmt.Sprintf("signer_key_id '%s' is not in trusted keyring", bundle.SignerKeyID),
		}
	}
	if trustedKey.Issuer != "" && trustedKey.Issuer != bundle.Issuer {
		return &verificationFailure{
			code:    ErrCodeUntrustedSigner,
			message: fmt.Sprintf("bundle issuer '%s' does not match trusted key issuer '%s'", bundle.Issuer, trustedKey.Issuer),
		}
	}

	pubBytes, err := hex.DecodeString(strings.TrimSpace(trustedKey.PublicKeyHex))
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return &verificationFailure{
			code:    ErrCodeUntrustedSigner,
			message: fmt.Sprintf("malformed trusted public key for '%s'", bundle.SignerKeyID),
		}
	}
	pubKey := ed25519.PublicKey(pubBytes)

	if !strings.HasPrefix(bundle.Signature, "ed25519:") {
		return &verificationFailure{
			code:    ErrCodeVerificationFailed,
			message: "unsupported or missing signature algorithm prefix",
		}
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(bundle.Signature, "ed25519:"))
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return &verificationFailure{
			code:    ErrCodeVerificationFailed,
			message: "malformed signature bytes in bundle",
		}
	}

	computedDigest := policy.ComputeCanonicalBundleDigest(bundle)
	if computedDigest == "" || computedDigest != bundle.Digest {
		return &verificationFailure{
			code:    ErrCodeTamperedBundle,
			message: fmt.Sprintf("declared digest %s does not match canonical %s", bundle.Digest, computedDigest),
		}
	}

	signingPayload := CanonicalSigningPayload(bundle.Digest, bundle.Issuer, bundle.SignerKeyID, bundle.Revision, bundle.IssuedAt, bundle.ExpiresAt)
	if !ed25519.Verify(pubKey, signingPayload, sigBytes) {
		return &verificationFailure{
			code:    ErrCodeVerificationFailed,
			message: fmt.Sprintf("cryptographic signature verification failed for signer '%s'", bundle.SignerKeyID),
		}
	}

	return nil
}

// verifyFreshness checks validity window, expiration and monotonic revision against the accepted floor.
func verifyFreshness(bundle policy.LocalPolicyBundle, evalTime time.Time, minimumRevision int64) *verificationFailure {
	if bundle.Revision < 1 {
		return &verificationFailure{
			code:    ErrCodeInvalidBundleSpec,
			message: "bundle revision must be a positive integer >= 1",
		}
	}
	if strings.TrimSpace(bundle.IssuedAt) == "" || strings.TrimSpace(bundle.ExpiresAt) == "" {
		return &verificationFailure{
			code:    ErrCodeInvalidBundleSpec,
			message: "bundle validity window requires issued_at and expires_at",
		}
	}

	issuedAt, err := time.Parse(time.RFC3339, bundle.IssuedAt)
	if err != nil {
		return &verificationFailure{
			code:    ErrCodeInvalidBundleSpec,
			message: fmt.Sprintf("bundle issued_at must be valid RFC3339: %v", err),
		}
	}
	expiresAt, err := time.Parse(time.RFC3339, bundle.ExpiresAt)
	if err != nil {
		return &verificationFailure{
			code:    ErrCodeInvalidBundleSpec,
			message: fmt.Sprintf("bundle expires_at must be valid RFC3339: %v", err),
		}
	}
	if !expiresAt.After(issuedAt) {
		return &verificationFailure{
			code:    ErrCodeInvalidBundleSpec,
			message: "bundle expires_at must be strictly after issued_at",
		}
	}

	if evalTime.Before(issuedAt) {
		return &verificationFailure{
			code:    ErrCodeExpiredBundle,
			message: fmt.Sprintf("bundle '%s' is not yet valid at %s (issued_at %s)", bundle.BundleID, evalTime.UTC().Format(time.RFC3339), bundle.IssuedAt),
		}
	}
	if !evalTime.Before(expiresAt) {
		return &verificationFailure{
			code:    ErrCodeExpiredBundle,
			message: fmt.Sprintf("bundle '%s' expired at %s (evaluation_time %s)", bundle.BundleID, bundle.ExpiresAt, evalTime.UTC().Format(time.RFC3339)),
		}
	}

	if minimumRevision > 0 && bundle.Revision <= minimumRevision {
		return &verificationFailure{
			code:    ErrCodeStaleOrReplayedRev,
			message: fmt.Sprintf("candidate revision %d is not strictly greater than accepted revision %d", bundle.Revision, minimumRevision),
		}
	}

	return nil
}

// VerifyBundleSignature checks the cryptographic Ed25519 signature of the bundle against trusted keys.
// It verifies trust evidence only; callers that ingest policy authority must use VerifyBundle or
// BundleAuthorityManager so freshness and monotonic revision are enforced too.
func VerifyBundleSignature(bundle policy.LocalPolicyBundle, keyring *Keyring) error {
	if failure := verifyTrustEvidence(bundle, keyring); failure != nil {
		return fmt.Errorf("%s: %s", failure.code, failure.message)
	}
	return nil
}
