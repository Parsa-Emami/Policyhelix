package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyGatewayProof_ValidToken(t *testing.T) {
	secret := "test-secret-12345"
	requestID := "req-abc-001"
	subjectID := "usr-alice"
	now := time.Now().Unix()

	proof := GenerateGatewayProof(secret, requestID, subjectID, now)
	if !VerifyGatewayProof(secret, proof, requestID, subjectID, 5*time.Minute) {
		t.Fatalf("expected valid proof to be accepted")
	}
}

func TestVerifyGatewayProof_EmptyInputs(t *testing.T) {
	if VerifyGatewayProof("", "t=100,sig=abc", "req", "sub", 5*time.Minute) {
		t.Errorf("expected empty secret to be rejected")
	}
	if VerifyGatewayProof("secret", "", "req", "sub", 5*time.Minute) {
		t.Errorf("expected empty proof to be rejected")
	}
}

func TestVerifyGatewayProof_BackdoorRejection(t *testing.T) {
	secret := "production-secret-xyz"

	// 1. Raw secret supplied as proof
	if VerifyGatewayProof(secret, secret, "req-1", "usr-1", 5*time.Minute) {
		t.Errorf("CRITICAL SECURITY VULNERABILITY: raw secret accepted as proof token")
	}

	// 2. Fake prefix bypass strings
	fakeTokens := []string{
		"verified-gateway-token",
		"verified-gateway-token-bypass",
		"verified-gateway-token:admin",
	}
	for _, fake := range fakeTokens {
		if VerifyGatewayProof(secret, fake, "req-1", "usr-1", 5*time.Minute) {
			t.Errorf("CRITICAL SECURITY VULNERABILITY: fake prefix token %q accepted", fake)
		}
	}
}

func TestVerifyGatewayProof_Expiration(t *testing.T) {
	secret := "test-secret-12345"
	requestID := "req-expire-001"
	subjectID := "usr-bob"

	// 1. Token older than maxAge (10 minutes ago, maxAge is 1 minute)
	oldTs := time.Now().Add(-10 * time.Minute).Unix()
	oldProof := GenerateGatewayProof(secret, requestID, subjectID, oldTs)
	if VerifyGatewayProof(secret, oldProof, requestID, subjectID, 1*time.Minute) {
		t.Errorf("expired proof token was accepted")
	}

	// 2. Token too far into the future (future clock skew > 60s)
	futureTs := time.Now().Add(5 * time.Minute).Unix()
	futureProof := GenerateGatewayProof(secret, requestID, subjectID, futureTs)
	if VerifyGatewayProof(secret, futureProof, requestID, subjectID, 1*time.Minute) {
		t.Errorf("future timestamp (>60s skew) proof token was accepted")
	}

	// 3. Token within clock skew tolerance (30s into the future)
	toleratedFutureTs := time.Now().Add(30 * time.Second).Unix()
	toleratedProof := GenerateGatewayProof(secret, requestID, subjectID, toleratedFutureTs)
	if !VerifyGatewayProof(secret, toleratedProof, requestID, subjectID, 1*time.Minute) {
		t.Errorf("tolerated future timestamp (<=60s) proof token should be accepted")
	}
}

func TestVerifyGatewayProof_Tampering(t *testing.T) {
	secret := "test-secret-12345"
	requestID := "req-tamper-001"
	subjectID := "usr-carol"
	ts := time.Now().Unix()

	proof := GenerateGatewayProof(secret, requestID, subjectID, ts)

	// Tampered request ID
	if VerifyGatewayProof(secret, proof, "req-attacker-controlled", subjectID, 5*time.Minute) {
		t.Errorf("tampered requestID was accepted")
	}

	// Tampered subject ID
	if VerifyGatewayProof(secret, proof, requestID, "usr-attacker", 5*time.Minute) {
		t.Errorf("tampered subjectID was accepted")
	}

	// Tampered secret
	if VerifyGatewayProof("wrong-secret", proof, requestID, subjectID, 5*time.Minute) {
		t.Errorf("proof verified with wrong secret")
	}

	// Tampered signature byte
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s:%s:%d", requestID, subjectID, ts)))
	tamperedSig := hex.EncodeToString(mac.Sum(nil))
	tamperedSigBytes := []byte(tamperedSig)
	if tamperedSigBytes[0] == 'a' {
		tamperedSigBytes[0] = 'b'
	} else {
		tamperedSigBytes[0] = 'a'
	}
	tamperedProof := fmt.Sprintf("t=%d,sig=%s", ts, string(tamperedSigBytes))
	if VerifyGatewayProof(secret, tamperedProof, requestID, subjectID, 5*time.Minute) {
		t.Errorf("tampered signature was accepted")
	}
}

func TestVerifyGatewayProof_MalformedFormatting(t *testing.T) {
	secret := "test-secret-12345"

	malformed := []string{
		"invalid-format",
		"t=notanumber,sig=abcdef",
		"t=12345extra,sig=abcdef",
		"t=123junk456,sig=abcdef",
		"t=12345",
		"sig=abcdef",
		"t=0,sig=abcdef",
		"t=-100,sig=abcdef",
		"t=123,sig=",
		"t=123,sig=abc,extra=bad",
		",",
		"t=123,other=value",
	}

	for _, token := range malformed {
		if VerifyGatewayProof(secret, token, "req-1", "usr-1", 5*time.Minute) {
			t.Errorf("malformed token %q was accepted", token)
		}
	}
}

func TestProtectedOriginMiddleware(t *testing.T) {
	secret := "test-mw-secret"

	nextCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"upstream":"ok"}`))
	})

	protected := ProtectedOriginMiddleware(secret)(handler)

	// Case 1: Missing proof
	req1 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	rec1 := httptest.NewRecorder()
	nextCalled = false
	protected.ServeHTTP(rec1, req1)
	if nextCalled || rec1.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when proof missing, got code %d, nextCalled %v", rec1.Code, nextCalled)
	}

	// Case 2: Backdoor bypass attempt with raw secret
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req2.Header.Set(HeaderGatewayProof, secret)
	rec2 := httptest.NewRecorder()
	nextCalled = false
	protected.ServeHTTP(rec2, req2)
	if nextCalled || rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when proof is raw secret, got code %d, nextCalled %v", rec2.Code, nextCalled)
	}

	// Case 3: Valid proof token
	now := time.Now().Unix()
	validProof := GenerateGatewayProof(secret, "req-99", "usr-mw-alice", now)
	req3 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req3.Header.Set(HeaderGatewayProof, validProof)
	req3.Header.Set("X-Request-Id", "req-99")
	req3.Header.Set(HeaderPolicyHelixSubject, "usr-mw-alice")
	rec3 := httptest.NewRecorder()
	nextCalled = false
	protected.ServeHTTP(rec3, req3)
	if !nextCalled || rec3.Code != http.StatusOK {
		t.Fatalf("expected 200 when valid proof provided, got code %d, nextCalled %v", rec3.Code, nextCalled)
	}
}
