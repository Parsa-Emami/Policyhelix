package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
)

const (
	c13FixtureDir  = "fixtures/policyhelix/C13"
	c13EvalTime    = "2026-11-04T12:00:00Z"
	c13TestIssuer  = "https://auth.policyhelix.local/realms/policyhelix"
	c13TestClient  = "policyhelix-web"
	c13TestRSAKey  = "rsa-keycloak-2026"
	c13TestEdKey   = "ed25519-oidc-2026"
	c13TestHMACKey = "hmac-oidc-2026"
)

type c13Expected struct {
	Valid              bool     `json:"valid"`
	Authenticated      bool     `json:"authenticated"`
	ErrorCode          string   `json:"error_code,omitempty"`
	SubjectID          string   `json:"subject_id,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	Roles              []string `json:"roles,omitempty"`
	AuthorizedForScope bool     `json:"authorized_for_scope"`
}

type c13FixtureFile struct {
	FixtureID     string                         `json:"fixture_id"`
	CommitID      string                         `json:"commit_id"`
	Description   string                         `json:"description"`
	SchemaVersion string                         `json:"schema_version"`
	Config        auth.OIDCConfig                `json:"config"`
	TrustedKeys   []auth.TrustedKey              `json:"trusted_keys"`
	PreloadState  *auth.LoginState               `json:"preload_state,omitempty"`
	PreloadNonces []string                       `json:"preload_nonces,omitempty"`
	Callback      auth.CallbackValidationRequest `json:"callback"`
	Expected      c13Expected                    `json:"expected"`
}

func TestC13_FixturesSuite(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c13FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C13 manifest: %v", err)
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
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("failed to unmarshal C13 manifest: %v", err)
	}
	if manifest.CommitID != "C13" {
		t.Fatalf("expected commit_id C13, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) != 13 {
		t.Fatalf("expected 13 C13 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c13FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", base, err)
		}
		sum := sha256.Sum256(raw)
		if actual := hex.EncodeToString(sum[:]); actual != entry.SHA256 {
			t.Fatalf("fixture %s SHA-256 mismatch: manifest=%s actual=%s", base, entry.SHA256, actual)
		}
		if entry.License != "Apache-2.0" {
			t.Fatalf("fixture %s has unexpected license %s", base, entry.License)
		}
		if entry.Type == "cli" {
			continue
		}

		var fx c13FixtureFile
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", base, err)
		}
		if fx.CommitID != "C13" || fx.FixtureID != entry.FixtureID {
			t.Fatalf("fixture identity mismatch for %s: %+v", base, fx)
		}

		t.Run(entry.FixtureID, func(t *testing.T) {
			runC13Fixture(t, fx)
		})
	}
}

func runC13Fixture(t *testing.T, fx c13FixtureFile) {
	t.Helper()

	keySet := auth.NewKeySet()
	for _, tk := range fx.TrustedKeys {
		if err := keySet.AddKey(tk); err != nil {
			t.Fatalf("failed to add trusted key %s: %v", tk.KeyID, err)
		}
	}
	cfg := fx.Config
	cfg.KeySet = keySet

	stateMgr := auth.NewStateManager()
	if fx.PreloadState != nil {
		stateMgr.StoreState(fx.PreloadState)
	}

	nonceTracker := auth.NewNonceTracker()
	for _, nonce := range fx.PreloadNonces {
		nonceTracker.PreloadNonce(nonce, time.Now())
	}

	validator := auth.NewOIDCValidator(cfg, stateMgr, nonceTracker)
	res, err := validator.ValidateCallback(context.Background(), fx.Callback)
	if err != nil {
		t.Fatalf("unexpected validator error: %v", err)
	}

	if res.Valid != fx.Expected.Valid {
		t.Fatalf("expected valid=%v, got %v (error: %s / %s)", fx.Expected.Valid, res.Valid, res.ErrorCode, res.ErrorMessage)
	}

	if fx.Expected.ErrorCode != "" && res.ErrorCode != fx.Expected.ErrorCode {
		t.Fatalf("expected error_code %s, got %s (message: %s)", fx.Expected.ErrorCode, res.ErrorCode, res.ErrorMessage)
	}

	if fx.Expected.Valid {
		if !res.Identity.Authenticated {
			t.Fatalf("expected identity.authenticated=true")
		}
		if !res.Identity.UntrustedHeadersStripped {
			t.Fatalf("expected untrusted_headers_stripped=true")
		}
		if fx.Expected.SubjectID != "" && res.Identity.SubjectID != fx.Expected.SubjectID {
			t.Fatalf("expected subject_id %s, got %s", fx.Expected.SubjectID, res.Identity.SubjectID)
		}
		if fx.Expected.Issuer != "" && res.Identity.Issuer != fx.Expected.Issuer {
			t.Fatalf("expected issuer %s, got %s", fx.Expected.Issuer, res.Identity.Issuer)
		}
	} else {
		if res.Identity.Authenticated {
			t.Fatalf("expected unauthenticated identity on failure")
		}
	}
}

func TestC13_AcceptanceCriteria(t *testing.T) {
	// Acceptance requirement F07:
	// "Wrong issuer/audience, nonce replay, invalid callback state and expired token fail."

	priv, pub, err := auth.GenerateSyntheticRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubPEM, err := auth.ExportRSAPublicKeyPEM(pub)
	if err != nil {
		t.Fatalf("failed to export RSA pub PEM: %v", err)
	}

	keySet := auth.NewKeySet()
	_ = keySet.AddKey(auth.TrustedKey{
		KeyID:        c13TestRSAKey,
		Issuer:       c13TestIssuer,
		Algorithm:    auth.AlgRS256,
		PublicKeyPEM: pubPEM,
	})

	cfg := auth.OIDCConfig{
		Issuer:            c13TestIssuer,
		ClientID:          c13TestClient,
		AllowedAlgorithms: []string{auth.AlgRS256},
		RequireNonce:      true,
		KeySet:            keySet,
	}

	evalTime, _ := time.Parse(time.RFC3339, c13EvalTime)

	setupValidator := func() (*auth.OIDCValidator, *auth.LoginState) {
		sm := auth.NewStateManager()
		nt := auth.NewNonceTracker()
		st, _ := sm.BeginLogin(auth.LoginStateOptions{
			Issuer:      c13TestIssuer,
			ClientID:    c13TestClient,
			RedirectURI: "https://app.local/callback",
			TTL:         10 * time.Minute,
		}, evalTime.Add(-2*time.Minute))
		return auth.NewOIDCValidator(cfg, sm, nt), st
	}

	// 1. Wrong issuer fails
	t.Run("WrongIssuerFails", func(t *testing.T) {
		val, st := setupValidator()
		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgRS256, Type: "JWT", KeyID: c13TestRSAKey}, auth.IDTokenClaims{
			Issuer:    "https://wrong.issuer.org",
			Subject:   "user-1",
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Add(-1 * time.Minute).Unix(),
			Nonce:     st.Nonce,
		}, priv)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeWrongIssuer {
			t.Fatalf("expected failure with WRONG_ISSUER, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// 2. Wrong audience fails
	t.Run("WrongAudienceFails", func(t *testing.T) {
		val, st := setupValidator()
		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgRS256, Type: "JWT", KeyID: c13TestRSAKey}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "user-1",
			Audience:  auth.Audience{"another-client"},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Add(-1 * time.Minute).Unix(),
			Nonce:     st.Nonce,
		}, priv)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeWrongAudience {
			t.Fatalf("expected failure with WRONG_AUDIENCE, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// 3. Nonce replay fails
	t.Run("NonceReplayFails", func(t *testing.T) {
		val, st := setupValidator()
		// First consumption
		val.NonceTracker().PreloadNonce(st.Nonce, evalTime.Add(-1*time.Minute))

		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgRS256, Type: "JWT", KeyID: c13TestRSAKey}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "user-1",
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Add(-1 * time.Minute).Unix(),
			Nonce:     st.Nonce,
		}, priv)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeNonceReplay {
			t.Fatalf("expected failure with NONCE_REPLAY, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// 4. Invalid callback state fails
	t.Run("InvalidCallbackStateFails", func(t *testing.T) {
		val, _ := setupValidator()
		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgRS256, Type: "JWT", KeyID: c13TestRSAKey}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "user-1",
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Add(-1 * time.Minute).Unix(),
			Nonce:     "some-nonce",
		}, priv)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               "state-non-existent",
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeInvalidCallbackState {
			t.Fatalf("expected failure with INVALID_CALLBACK_STATE, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// 5. Expired token fails
	t.Run("ExpiredTokenFails", func(t *testing.T) {
		val, st := setupValidator()
		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgRS256, Type: "JWT", KeyID: c13TestRSAKey}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "user-1",
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(-10 * time.Minute).Unix(), // Expired
			IssuedAt:  evalTime.Add(-30 * time.Minute).Unix(),
			Nonce:     st.Nonce,
		}, priv)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeExpiredToken {
			t.Fatalf("expected failure with EXPIRED_TOKEN, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})
}

func TestC13_NegativeCases(t *testing.T) {
	priv, pub, err := auth.GenerateSyntheticRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pubPEM, _ := auth.ExportRSAPublicKeyPEM(pub)

	keySet := auth.NewKeySet()
	_ = keySet.AddKey(auth.TrustedKey{
		KeyID:        c13TestRSAKey,
		Issuer:       c13TestIssuer,
		Algorithm:    auth.AlgRS256,
		PublicKeyPEM: pubPEM,
	})

	cfg := auth.OIDCConfig{
		Issuer:            c13TestIssuer,
		ClientID:          c13TestClient,
		AllowedAlgorithms: []string{auth.AlgRS256},
		RequireNonce:      true,
		KeySet:            keySet,
	}

	evalTime, _ := time.Parse(time.RFC3339, c13EvalTime)

	// A. Missing identity / empty subject
	t.Run("MissingSubjectFails", func(t *testing.T) {
		sm := auth.NewStateManager()
		st, _ := sm.BeginLogin(auth.LoginStateOptions{
			Issuer:      c13TestIssuer,
			ClientID:    c13TestClient,
			RedirectURI: "https://app.local/callback",
		}, evalTime)
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgRS256, Type: "JWT", KeyID: c13TestRSAKey}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "", // Empty subject
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Unix(),
			Nonce:     st.Nonce,
		}, priv)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeUnauthenticatedIdentity {
			t.Fatalf("expected UNAUTHENTICATED_IDENTITY, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// B. Forged header alg none fails
	t.Run("ForgedHeaderAlgNoneFails", func(t *testing.T) {
		sm := auth.NewStateManager()
		st, _ := sm.BeginLogin(auth.LoginStateOptions{
			Issuer:      c13TestIssuer,
			ClientID:    c13TestClient,
			RedirectURI: "https://app.local/callback",
		}, evalTime)
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: "none", Type: "JWT"}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "attacker",
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Unix(),
			Nonce:     st.Nonce,
		}, nil)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if res.Valid || (res.ErrorCode != auth.ErrCodeUntrustedSigner && res.ErrorCode != auth.ErrCodeForgedHeader) {
			t.Fatalf("expected rejection for alg:none, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// C. Untrusted headers not stripped fails
	t.Run("UntrustedHeadersNotStrippedFails", func(t *testing.T) {
		sm := auth.NewStateManager()
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               "state-any",
			RawIDToken:               "some.token.here",
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: false, // Forged header leak
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeForgedHeader {
			t.Fatalf("expected FORGED_HEADER_REJECTED, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// D. Provider unavailable fails closed
	t.Run("ProviderUnavailableFailsClosed", func(t *testing.T) {
		sm := auth.NewStateManager()
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               "state-any",
			RawIDToken:               "some.token.here",
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
			ProviderUnavailable:      true,
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeProviderUnavailable {
			t.Fatalf("expected PROVIDER_UNAVAILABLE, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// E. Unrelated owner scope fails
	t.Run("UnrelatedOwnerScopeFails", func(t *testing.T) {
		sm := auth.NewStateManager()
		st, _ := sm.BeginLogin(auth.LoginStateOptions{
			Issuer:      c13TestIssuer,
			ClientID:    c13TestClient,
			RedirectURI: "https://app.local/callback",
			OwnerScope:  "tenant-alpha",
		}, evalTime)
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		tok, _ := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgRS256, Type: "JWT", KeyID: c13TestRSAKey}, auth.IDTokenClaims{
			Issuer:     c13TestIssuer,
			Subject:    "user-alpha",
			Audience:   auth.Audience{c13TestClient},
			ExpiresAt:  evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:   evalTime.Unix(),
			Nonce:      st.Nonce,
			Roles:      []string{"operator"}, // not admin
			OwnerScope: "tenant-alpha",
		}, priv)

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
			TargetOwnerScope:         "tenant-beta", // Attempting cross-scope access
		})
		if res.Valid || res.ErrorCode != auth.ErrCodeScopeViolation {
			t.Fatalf("expected SCOPE_VIOLATION, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})

	// F. Private resource fails closed
	t.Run("PrivateResourceFailsClosed", func(t *testing.T) {
		sm := auth.NewStateManager()
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		res, _ := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               "state-invalid",
			RawIDToken:               "garbage.jwt.token",
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
			ResourceClassification:   "private",
		})
		if res.Valid || res.ErrorCode != auth.ErrCodePrivateFailClosed {
			t.Fatalf("expected PRIVATE_RESOURCE_FAIL_CLOSED, got valid=%v code=%s", res.Valid, res.ErrorCode)
		}
	})
}

func TestC13_MultiAlgorithmSupport(t *testing.T) {
	// Tests EdDSA (Ed25519) and HS256 (HMAC-SHA256)
	evalTime, _ := time.Parse(time.RFC3339, c13EvalTime)

	// 1. Ed25519
	edSeed := make([]byte, 32)
	for i := range edSeed {
		edSeed[i] = byte(i + 1)
	}
	edPriv := ed25519.NewKeyFromSeed(edSeed)
	edPub := edPriv.Public().(ed25519.PublicKey)
	edPubHex := hex.EncodeToString(edPub)

	// 2. HS256
	hmacSecretHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	hmacSecret, _ := hex.DecodeString(hmacSecretHex)

	keySet := auth.NewKeySet()
	_ = keySet.AddKey(auth.TrustedKey{
		KeyID:        c13TestEdKey,
		Issuer:       c13TestIssuer,
		Algorithm:    auth.AlgEdDSA,
		PublicKeyHex: edPubHex,
	})
	_ = keySet.AddKey(auth.TrustedKey{
		KeyID:     c13TestHMACKey,
		Issuer:    c13TestIssuer,
		Algorithm: auth.AlgHS256,
		SecretHex: hmacSecretHex,
	})

	cfg := auth.OIDCConfig{
		Issuer:            c13TestIssuer,
		ClientID:          c13TestClient,
		AllowedAlgorithms: []string{auth.AlgEdDSA, auth.AlgHS256},
		RequireNonce:      true,
		KeySet:            keySet,
	}

	// Verify Ed25519 valid token
	t.Run("Ed25519ValidToken", func(t *testing.T) {
		sm := auth.NewStateManager()
		st, _ := sm.BeginLogin(auth.LoginStateOptions{
			Issuer:      c13TestIssuer,
			ClientID:    c13TestClient,
			RedirectURI: "https://app.local/callback",
		}, evalTime)
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		tok, err := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgEdDSA, Type: "JWT", KeyID: c13TestEdKey}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "ed-user",
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Unix(),
			Nonce:     st.Nonce,
			Roles:     []string{"operator"},
		}, edPriv)
		if err != nil {
			t.Fatalf("failed to sign Ed25519 token: %v", err)
		}

		res, err := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if err != nil || !res.Valid {
			t.Fatalf("expected valid Ed25519 callback, got valid=%v code=%s err=%v", res.Valid, res.ErrorCode, err)
		}
		if res.Identity.SubjectID != "ed-user" {
			t.Fatalf("expected subject ed-user, got %s", res.Identity.SubjectID)
		}
	})

	// Verify HS256 valid token
	t.Run("HS256ValidToken", func(t *testing.T) {
		sm := auth.NewStateManager()
		st, _ := sm.BeginLogin(auth.LoginStateOptions{
			Issuer:      c13TestIssuer,
			ClientID:    c13TestClient,
			RedirectURI: "https://app.local/callback",
		}, evalTime)
		val := auth.NewOIDCValidator(cfg, sm, auth.NewNonceTracker())

		tok, err := auth.SignJWT(auth.JWTHeader{Algorithm: auth.AlgHS256, Type: "JWT", KeyID: c13TestHMACKey}, auth.IDTokenClaims{
			Issuer:    c13TestIssuer,
			Subject:   "hmac-user",
			Audience:  auth.Audience{c13TestClient},
			ExpiresAt: evalTime.Add(1 * time.Hour).Unix(),
			IssuedAt:  evalTime.Unix(),
			Nonce:     st.Nonce,
			Roles:     []string{"auditor"},
		}, hmacSecret)
		if err != nil {
			t.Fatalf("failed to sign HS256 token: %v", err)
		}

		res, err := val.ValidateCallback(context.Background(), auth.CallbackValidationRequest{
			StateToken:               st.StateToken,
			RawIDToken:               tok,
			EvaluationTime:           c13EvalTime,
			UntrustedHeadersStripped: true,
		})
		if err != nil || !res.Valid {
			t.Fatalf("expected valid HS256 callback, got valid=%v code=%s err=%v", res.Valid, res.ErrorCode, err)
		}
		if res.Identity.SubjectID != "hmac-user" {
			t.Fatalf("expected subject hmac-user, got %s", res.Identity.SubjectID)
		}
	})
}

func TestC13_CLIValidation(t *testing.T) {
	validPath, err := filepath.Abs(filepath.Join(c13FixtureDir, "cli-valid-callback.json"))
	if err != nil {
		t.Fatalf("failed to resolve cli-valid-callback: %v", err)
	}
	rejPath, err := filepath.Abs(filepath.Join(c13FixtureDir, "cli-rejected-callback.json"))
	if err != nil {
		t.Fatalf("failed to resolve cli-rejected-callback: %v", err)
	}

	runCLI := func(args ...string) ([]byte, string, error) {
		cmd := exec.Command("go", append([]string{"run", "../cmd/policyhelix"}, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.Bytes(), stderr.String(), err
	}

	// 1. Positive CLI validation
	stdout, stderr, err := runCLI("--validate-oidc", validPath)
	if err != nil {
		t.Fatalf("CLI positive validation failed: %v, stderr: %s", err, stderr)
	}
	var validRes auth.ValidationResult
	if err := json.Unmarshal(stdout, &validRes); err != nil {
		t.Fatalf("failed to parse CLI JSON: %v, raw: %s", err, stdout)
	}
	if !validRes.Valid || validRes.Identity.SubjectID != "user-cli-operator" {
		t.Fatalf("unexpected CLI valid result: %+v", validRes)
	}

	// 2. Negative CLI validation
	stdout, _, err = runCLI("--validate-oidc", rejPath)
	if err == nil {
		t.Fatalf("expected CLI error exit code for rejected fixture, but exited 0")
	}
	var rejRes auth.ValidationResult
	if err := json.Unmarshal(stdout, &rejRes); err != nil {
		t.Fatalf("failed to parse CLI rejected JSON: %v, raw: %s", err, stdout)
	}
	if rejRes.Valid || rejRes.ErrorCode != auth.ErrCodeWrongIssuer {
		t.Fatalf("expected rejected result with WRONG_ISSUER, got %+v", rejRes)
	}
}
