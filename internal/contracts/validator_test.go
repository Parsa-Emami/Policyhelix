package contracts

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func validPositiveInput() Input {
	return Input{
		SchemaVersion: "1",
		RequestID:     "req-pos-001",
		Subject: Subject{
			ID:            "user_alice",
			Issuer:        "https://idp.local.test/realms/policyhelix",
			Email:         "alice@local.test",
			Roles:         []string{"operator"},
			Authenticated: true,
			SessionEpoch:  1730000000,
		},
		Resource: Resource{
			ID:             "service:analytics/data/report-2026",
			Type:           "dataset",
			Classification: "internal",
		},
		Action: "read",
		Context: RequestContext{
			Protocol:                 "loopback",
			SourceIP:                 "127.0.0.1",
			ClientID:                 "policyhelix-local-web",
			Timestamp:                "2026-11-03T10:00:00Z",
			UntrustedHeadersStripped: true,
		},
		PolicyBundle: PolicyBundleRef{
			Digest:            "sha256:4a5c88e5d2639201f99c235b2e912f2cbe6783965b1287f3b89b1424e12e12e8",
			Revision:          1,
			SignedAt:          "2026-11-03T10:00:00Z",
			SignatureVerified: true,
			ProviderState:     "ready",
		},
		Limits: ExecutionLimits{
			MaxPayloadBytes: 65536,
			DeadlineMS:      200,
		},
	}
}

func TestValidateAndEvaluate_Positive(t *testing.T) {
	in := validPositiveInput()
	raw, _ := json.Marshal(in)

	code, res := ValidateAndEvaluate(context.Background(), raw)
	if code != http.StatusOK {
		t.Fatalf("Expected 200, got %d, err: %+v", code, res.Error)
	}
	if !res.Decision.Allow {
		t.Errorf("Expected allow=true, got allow=false")
	}
	if res.Status != "complete" {
		t.Errorf("Expected status=complete, got %s", res.Status)
	}
	if res.Error != nil {
		t.Errorf("Expected nil error, got %+v", res.Error)
	}
	if !strings.HasPrefix(res.InputDigest, "sha256:") {
		t.Errorf("Expected sha256 prefix on InputDigest, got %s", res.InputDigest)
	}
}

func TestValidateAndEvaluate_UnsupportedVersion(t *testing.T) {
	in := validPositiveInput()
	in.SchemaVersion = "0"
	raw, _ := json.Marshal(in)

	code, res := ValidateAndEvaluate(context.Background(), raw)
	if code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for unsupported version, got %d", code)
	}
	if res.Error == nil || res.Error.Code != ErrUnsupportedVersion {
		t.Errorf("Expected error code %s, got %+v", ErrUnsupportedVersion, res.Error)
	}
	if res.Decision.Allow {
		t.Errorf("Expected allow=false")
	}
}

func TestValidateAndEvaluate_InvalidJSON(t *testing.T) {
	code, res := ValidateAndEvaluate(context.Background(), []byte(`{not valid json`))
	if code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for invalid json, got %d", code)
	}
	if res.Error == nil || res.Error.Code != ErrInvalidJSON {
		t.Errorf("Expected error code %s, got %+v", ErrInvalidJSON, res.Error)
	}
}

func TestValidateAndEvaluate_PayloadTooLarge(t *testing.T) {
	oversized := make([]byte, MaxAllowedPayload+100)
	for i := range oversized {
		oversized[i] = 'a'
	}

	code, res := ValidateAndEvaluate(context.Background(), oversized)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413, got %d", code)
	}
	if res.Error == nil || res.Error.Code != ErrPayloadTooLarge {
		t.Errorf("Expected %s, got %+v", ErrPayloadTooLarge, res.Error)
	}
}

func TestValidateAndEvaluate_SchemaValidationFailed(t *testing.T) {
	in := validPositiveInput()
	in.Action = "invalid_action"
	raw, _ := json.Marshal(in)

	code, res := ValidateAndEvaluate(context.Background(), raw)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("Expected 422, got %d", code)
	}
	if res.Error == nil || res.Error.Code != ErrSchemaValidationFailed {
		t.Errorf("Expected %s, got %+v", ErrSchemaValidationFailed, res.Error)
	}
}

func TestValidateAndEvaluate_UnauthenticatedPrivateFailClosed(t *testing.T) {
	in := validPositiveInput()
	in.Resource.Classification = "private"
	in.Subject.Authenticated = false
	raw, _ := json.Marshal(in)

	code, res := ValidateAndEvaluate(context.Background(), raw)
	if code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", code)
	}
	if res.Decision.Allow {
		t.Errorf("Expected allow=false for unauthenticated private access")
	}
	if res.Error == nil || res.Error.Code != ErrUnauthenticatedIdentity {
		t.Errorf("Expected %s, got %+v", ErrUnauthenticatedIdentity, res.Error)
	}
}

func TestValidateAndEvaluate_ProviderUnavailable(t *testing.T) {
	in := validPositiveInput()
	in.PolicyBundle.ProviderState = "unavailable"
	raw, _ := json.Marshal(in)

	code, res := ValidateAndEvaluate(context.Background(), raw)
	if code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", code)
	}
	if res.Decision.Allow {
		t.Errorf("Expected allow=false for unavailable provider")
	}
	if res.Error == nil || res.Error.Code != ErrProviderUnavailable {
		t.Errorf("Expected %s, got %+v", ErrProviderUnavailable, res.Error)
	}
}

func TestValidateAndEvaluate_UnsignedBundle(t *testing.T) {
	in := validPositiveInput()
	in.PolicyBundle.SignatureVerified = false
	raw, _ := json.Marshal(in)

	code, res := ValidateAndEvaluate(context.Background(), raw)
	if code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", code)
	}
	if res.Decision.Allow {
		t.Errorf("Expected allow=false for unsigned bundle")
	}
	if res.Error == nil || res.Error.Code != ErrStaleOrUnsignedBundle {
		t.Errorf("Expected %s, got %+v", ErrStaleOrUnsignedBundle, res.Error)
	}
}

func TestValidateAndEvaluate_CancellationAndTimeout(t *testing.T) {
	// Simulated cancellation
	inCancel := validPositiveInput()
	inCancel.Limits.DeadlineMS = 100
	inCancel.Limits.CancelAfterMS = 10
	rawCancel, _ := json.Marshal(inCancel)

	code, res := ValidateAndEvaluate(context.Background(), rawCancel)
	if code != 499 {
		t.Fatalf("Expected 499 for cancelled request, got %d", code)
	}
	if res.Status != "cancelled" || res.Decision.Allow {
		t.Errorf("Expected cancelled status and allow=false, got: %+v", res)
	}
	if res.Error == nil || res.Error.Code != ErrRequestCancelled {
		t.Errorf("Expected %s, got %+v", ErrRequestCancelled, res.Error)
	}

	// External context already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inPre := validPositiveInput()
	rawPre, _ := json.Marshal(inPre)

	code, res = ValidateAndEvaluate(ctx, rawPre)
	if code != 499 {
		t.Fatalf("Expected 499 for pre-cancelled context, got %d", code)
	}
}

func TestValidateAndEvaluate_RestartInvariance(t *testing.T) {
	in := validPositiveInput()
	raw, _ := json.Marshal(in)

	code1, res1 := ValidateAndEvaluate(context.Background(), raw)
	time.Sleep(20 * time.Millisecond)
	code2, res2 := ValidateAndEvaluate(context.Background(), raw)

	if code1 != code2 {
		t.Fatalf("Status codes differ: %d != %d", code1, code2)
	}
	if res1.Decision.Allow != res2.Decision.Allow || res1.InputDigest != res2.InputDigest {
		t.Fatalf("Results differ across restarts: res1=%+v, res2=%+v", res1, res2)
	}
}
