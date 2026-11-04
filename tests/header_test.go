package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/contracts"
	"github.com/parsa-emami/policyhelix/internal/gateway"
)

const (
	c16FixtureDir = "fixtures/policyhelix/C16"
)

type c16FixtureEnvelope struct {
	FixtureID          string                           `json:"fixture_id"`
	CommitID           string                           `json:"commit_id"`
	Description        string                           `json:"description"`
	SchemaVersion      string                           `json:"schema_version"`
	PreloadSessions    []auth.SessionRecord             `json:"preload_sessions,omitempty"`
	PreloadRevocations []auth.RevocationRecord          `json:"preload_revocations,omitempty"`
	Request            gateway.NormalizeIdentityRequest `json:"request"`
	Expected           struct {
		Valid             bool               `json:"valid"`
		Allow             bool               `json:"allow"`
		ErrorCode         string             `json:"error_code,omitempty"`
		StrippedHeaders   []string           `json:"stripped_headers,omitempty"`
		Subject           *contracts.Subject `json:"subject,omitempty"`
		DownstreamHeaders map[string]string  `json:"downstream_headers,omitempty"`
	} `json:"expected"`
}

func TestC16_FixturesSuite(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c16FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C16 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C16 manifest: %v", err)
	}
	if manifest.CommitID != "C16" {
		t.Fatalf("expected commit_id C16, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) < 12 {
		t.Fatalf("expected at least 12 C16 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c16FixtureDir, base))
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", entry.Path, err)
		}

		sum := sha256.Sum256(raw)
		if actual := hex.EncodeToString(sum[:]); actual != entry.SHA256 {
			t.Fatalf("SHA-256 mismatch on %s: manifest=%s computed=%s", entry.Path, entry.SHA256, actual)
		}
		if entry.License != "Apache-2.0" {
			t.Fatalf("unexpected license %s on %s", entry.License, entry.Path)
		}

		// CLI fixtures are tested separately via TestC16_EngineCLINormalize
		if filepath.Base(entry.Path) == "cli-normalize-clean.json" || filepath.Base(entry.Path) == "cli-normalize-rejected.json" {
			continue
		}

		var fixture c16FixtureEnvelope
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", entry.Path, err)
		}

		t.Run(fixture.FixtureID, func(t *testing.T) {
			ctx := context.Background()
			sessStore := auth.NewMemorySessionStore()
			revStore := auth.NewMemoryRevocationStore()

			for _, s := range fixture.PreloadSessions {
				if err := sessStore.SaveSession(ctx, s); err != nil {
					t.Fatalf("failed to preload session %s: %v", s.SessionID, err)
				}
			}
			for _, r := range fixture.PreloadRevocations {
				if r.SessionID != "" {
					if err := revStore.SaveSessionRevocation(ctx, r); err != nil {
						t.Fatalf("failed to preload session revocation %s: %v", r.SessionID, err)
					}
				}
				if r.SubjectID != "" && r.MinRequiredEpoch > 0 {
					if err := revStore.SaveSubjectRevocation(ctx, r); err != nil {
						t.Fatalf("failed to preload subject revocation %s: %v", r.SubjectID, err)
					}
				}
			}

			res, err := gateway.NormalizeSubjectContext(ctx, fixture.Request, sessStore, revStore)
			if err != nil {
				t.Fatalf("NormalizeSubjectContext returned unexpected error: %v", err)
			}
			if res == nil {
				t.Fatal("NormalizeSubjectContext returned nil result")
			}

			if res.Valid != fixture.Expected.Valid {
				t.Errorf("Valid mismatch: expected %v, got %v (err: %s - %s)", fixture.Expected.Valid, res.Valid, res.ErrorCode, res.ErrorMessage)
			}
			if res.Allow != fixture.Expected.Allow {
				t.Errorf("Allow mismatch: expected %v, got %v", fixture.Expected.Allow, res.Allow)
			}
			if fixture.Expected.ErrorCode != "" && res.ErrorCode != fixture.Expected.ErrorCode {
				t.Errorf("ErrorCode mismatch: expected %s, got %s (%s)", fixture.Expected.ErrorCode, res.ErrorCode, res.ErrorMessage)
			}

			if fixture.Expected.StrippedHeaders != nil {
				if len(res.StrippedHeaders) == 0 && len(fixture.Expected.StrippedHeaders) == 0 {
					// both empty
				} else if !reflect.DeepEqual(res.StrippedHeaders, fixture.Expected.StrippedHeaders) {
					t.Errorf("StrippedHeaders mismatch:\nexpected: %v\ngot:      %v", fixture.Expected.StrippedHeaders, res.StrippedHeaders)
				}
			}

			if fixture.Expected.Subject != nil {
				if res.Subject == nil {
					t.Fatalf("expected subject %v, got nil", fixture.Expected.Subject)
				}
				if res.Subject.ID != fixture.Expected.Subject.ID {
					t.Errorf("Subject.ID mismatch: expected %s, got %s", fixture.Expected.Subject.ID, res.Subject.ID)
				}
				if res.Subject.Issuer != fixture.Expected.Subject.Issuer {
					t.Errorf("Subject.Issuer mismatch: expected %s, got %s", fixture.Expected.Subject.Issuer, res.Subject.Issuer)
				}
				if res.Subject.Authenticated != fixture.Expected.Subject.Authenticated {
					t.Errorf("Subject.Authenticated mismatch: expected %v, got %v", fixture.Expected.Subject.Authenticated, res.Subject.Authenticated)
				}
				if !reflect.DeepEqual(res.Subject.Roles, fixture.Expected.Subject.Roles) {
					t.Errorf("Subject.Roles mismatch: expected %v, got %v", fixture.Expected.Subject.Roles, res.Subject.Roles)
				}
			}

			if fixture.Expected.DownstreamHeaders != nil {
				for k, v := range fixture.Expected.DownstreamHeaders {
					if actualVal, ok := res.DownstreamInjectedHeaders[k]; !ok || actualVal != v {
						t.Errorf("Downstream header '%s' mismatch: expected '%s', got '%s'", k, v, actualVal)
					}
				}
			}
		})
	}
}

func TestC16_StripUntrustedHeaders_Unit(t *testing.T) {
	headers := map[string]string{
		"X-User-Id":             "attacker",
		"x-user-id":             "attacker-lower",
		"X-USER-ID":             "attacker-upper",
		"X-Roles":               "admin",
		"X-PolicyHelix-Subject": "spoof",
		"x-policyhelix-custom":  "spoof-custom",
		"X-Forwarded-Host":      "client.local",
		"Authorization":         "Bearer token",
		"Content-Type":          "application/json",
		"Accept":                "application/json",
	}

	sanitized, stripped := gateway.StripUntrustedHeaders(headers)

	// Verify all prohibited and reserved headers are stripped
	for _, key := range stripped {
		if _, exists := sanitized[key]; exists {
			t.Errorf("Stripped header '%s' still present in sanitized output", key)
		}
	}

	expectedStrippedCount := 6
	if len(stripped) != expectedStrippedCount {
		t.Fatalf("expected %d stripped headers, got %d: %v", expectedStrippedCount, len(stripped), stripped)
	}

	// Verify safe headers remain intact
	if sanitized["Content-Type"] != "application/json" {
		t.Errorf("Safe Content-Type header was altered: %s", sanitized["Content-Type"])
	}
	if sanitized["Accept"] != "application/json" {
		t.Errorf("Safe Accept header was altered: %s", sanitized["Accept"])
	}
	if sanitized["Authorization"] != "Bearer token" {
		t.Errorf("Safe Authorization header was altered: %s", sanitized["Authorization"])
	}
}

func TestC16_ConstructTrustedSubject_Integrity(t *testing.T) {
	ctx := context.Background()
	sessStore := auth.NewMemorySessionStore()

	session := auth.SessionRecord{
		SessionID:    "sess-integrity-01",
		SubjectID:    "real-authorized-user",
		Issuer:       "https://auth.policyhelix.local",
		Roles:        []string{"user"},
		OwnerScope:   "tenant-trusted",
		SessionEpoch: 1793793600,
		CreatedAt:    time.Now().Add(-10 * time.Minute),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Status:       "ACTIVE",
	}
	if err := sessStore.SaveSession(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Inbound request attempts to forge identity headers
	req := gateway.NormalizeIdentityRequest{
		RequestID: "req-integrity-01",
		Headers: map[string]string{
			"X-User-Id":             "forged-attacker-identity",
			"X-Roles":               "superadmin,root",
			"X-PolicyHelix-Subject": "attacker-subject",
		},
		SessionID:                session.SessionID,
		UntrustedHeadersStripped: true,
		ResourceClassification:   "private",
		TargetOwnerScope:         "tenant-trusted",
	}

	res, err := gateway.NormalizeSubjectContext(ctx, req, sessStore, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Fatalf("expected valid and allowed, got: %s - %s", res.ErrorCode, res.ErrorMessage)
	}

	// Assert subject values derive strictly from the session record
	if res.Subject.ID != "real-authorized-user" {
		t.Errorf("Subject ID was spoofed: got %s", res.Subject.ID)
	}
	if len(res.Subject.Roles) != 1 || res.Subject.Roles[0] != "user" {
		t.Errorf("Subject roles were spoofed: got %v", res.Subject.Roles)
	}
	if res.DownstreamInjectedHeaders[gateway.HeaderPolicyHelixSubject] != "real-authorized-user" {
		t.Errorf("Downstream subject header was spoofed: got %s", res.DownstreamInjectedHeaders[gateway.HeaderPolicyHelixSubject])
	}
}

func TestC16_GatewayIdentityMiddleware(t *testing.T) {
	sessStore := auth.NewMemorySessionStore()
	session := auth.SessionRecord{
		SessionID:    "sess-middleware-01",
		SubjectID:    "user-middleware",
		Issuer:       "https://auth.policyhelix.local",
		Roles:        []string{"operator"},
		OwnerScope:   "tenant-mid",
		SessionEpoch: 1793793600,
		CreatedAt:    time.Now().Add(-5 * time.Minute),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Status:       "ACTIVE",
	}
	_ = sessStore.SaveSession(context.Background(), session)

	handlerCalled := false
	var observedSubjectHeader string
	var observedForgedHeader string

	downstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		observedSubjectHeader = r.Header.Get(gateway.HeaderPolicyHelixSubject)
		observedForgedHeader = r.Header.Get("X-User-Id")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	middleware := gateway.GatewayIdentityMiddleware(sessStore, nil)
	wrapped := middleware(downstreamHandler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/protected/resource", nil)
	req.Header.Set("X-User-Id", "forged-client-user")
	req.Header.Set("X-PolicyHelix-Subject", "forged-client-sub")
	req.AddCookie(&http.Cookie{
		Name:  "policyhelix_session",
		Value: session.SessionID,
	})

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Fatal("Downstream handler was not invoked")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
	if observedForgedHeader != "" {
		t.Errorf("Client forged header was not stripped: %s", observedForgedHeader)
	}
	if observedSubjectHeader != "user-middleware" {
		t.Errorf("Canonical downstream header was not injected: got '%s'", observedSubjectHeader)
	}
}

func TestC16_EngineCLINormalize(t *testing.T) {
	// Build or locate policyhelix engine binary
	engineBin := filepath.Join("..", "dist", "engine", "policyhelix")
	if _, err := os.Stat(engineBin); err != nil {
		// Try building engine
		buildCmd := exec.Command("go", "build", "-o", filepath.Join("dist", "engine", "policyhelix"), "./cmd/policyhelix")
		buildCmd.Dir = ".."
		if out, bErr := buildCmd.CombinedOutput(); bErr != nil {
			t.Skipf("cannot build policyhelix binary for CLI tests: %v: %s", bErr, string(out))
		}
		engineBin = filepath.Join("..", "dist", "engine", "policyhelix")
	}

	cleanFixture := filepath.Join(c16FixtureDir, "cli-normalize-clean.json")
	cmd := exec.Command(engineBin, "-normalize-identity", cleanFixture)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	if err := cmd.Run(); err != nil {
		t.Fatalf("CLI clean normalize failed: %v: stderr=%s", err, errOut.String())
	}

	var res gateway.NormalizeIdentityResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("failed to parse CLI JSON output: %v, raw: %s", err, out.String())
	}
	if !res.Valid || !res.Allow {
		t.Errorf("CLI clean normalize returned invalid: %v, allow: %v", res.Valid, res.Allow)
	}

	// Negative CLI test: unstripped forged headers
	rejectedFixture := filepath.Join(c16FixtureDir, "cli-normalize-rejected.json")
	negCmd := exec.Command(engineBin, "-normalize-identity", rejectedFixture)
	negErr := negCmd.Run()
	if negErr == nil {
		t.Errorf("expected CLI rejection for unstripped forged headers, but command exited with 0")
	}
}

func TestC16_HTTPHandler(t *testing.T) {
	body := []byte(`{
		"headers": {
			"X-User-Id": "attacker-spoofed",
			"Accept": "application/json"
		},
		"untrusted_headers_stripped": true,
		"resource_classification": "public"
	}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/identity/normalize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var normReq gateway.NormalizeIdentityRequest
		if err := json.NewDecoder(r.Body).Decode(&normReq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		res, err := gateway.NormalizeSubjectContext(r.Context(), normReq, nil, nil)
		if err != nil || !res.Valid || !res.Allow {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(res)
	})

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res gateway.NormalizeIdentityResult
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !res.Valid || !res.Allow {
		t.Errorf("expected valid and allowed, got: %v", res)
	}
	if len(res.StrippedHeaders) != 1 || res.StrippedHeaders[0] != "X-User-Id" {
		t.Errorf("expected X-User-Id to be stripped, got: %v", res.StrippedHeaders)
	}
}
