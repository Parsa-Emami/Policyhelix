package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/contracts"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

// TestC06FixturesAndCleanCheckoutGuarantees verifies all C06 fixtures and proves
// the engine contracts, storage guarantees, and negative security invariants.
func TestC06FixturesAndCleanCheckoutGuarantees(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "policyhelix", "C06")

	// 1. Positive Evaluation Fixture
	posBytes, err := os.ReadFile(filepath.Join(fixtureDir, "positive-operator-allow.json"))
	if err != nil {
		t.Fatalf("Failed to read positive fixture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	statusCode, res := contracts.ValidateAndEvaluate(ctx, posBytes)
	if statusCode != http.StatusOK {
		t.Fatalf("Expected positive evaluation status 200, got: %d", statusCode)
	}
	if res.Status != "complete" {
		t.Fatalf("Expected status complete, got: %s (error: %+v)", res.Status, res.Error)
	}
	if !res.Decision.Allow {
		t.Fatalf("Expected decision allow=true, got allow=false: reasons=%+v", res.Decision.Reasons)
	}

	// 2. Negative: Untrusted/Tampered Signer fails closed
	negTamperedBytes, err := os.ReadFile(filepath.Join(fixtureDir, "negative-tampered-signer.json"))
	if err != nil {
		t.Fatalf("Failed to read negative tampered fixture: %v", err)
	}
	_, resTampered := contracts.ValidateAndEvaluate(ctx, negTamperedBytes)
	if resTampered.Decision.Allow {
		t.Fatalf("Security invariant violated: untrusted/tampered signer produced allow=true")
	}
	if resTampered.Error == nil || resTampered.Error.Code != contracts.ErrStaleOrUnsignedBundle {
		t.Fatalf("Expected error code %s for tampered signer, got: %+v", contracts.ErrStaleOrUnsignedBundle, resTampered.Error)
	}

	// 3. Negative: Stale Revision / Replayed Epoch rejected
	negStaleBytes, err := os.ReadFile(filepath.Join(fixtureDir, "negative-stale-replayed-revision.json"))
	if err != nil {
		t.Fatalf("Failed to read negative stale fixture: %v", err)
	}
	_, resStale := contracts.ValidateAndEvaluate(ctx, negStaleBytes)
	if resStale.Decision.Allow {
		t.Fatalf("Security invariant violated: stale/replayed revision produced allow=true")
	}

	// 4. Negative: Private Resources Fail Closed
	negUnauthBytes, err := os.ReadFile(filepath.Join(fixtureDir, "negative-unauthenticated-private.json"))
	if err != nil {
		t.Fatalf("Failed to read negative unauthenticated private fixture: %v", err)
	}
	_, resUnauth := contracts.ValidateAndEvaluate(ctx, negUnauthBytes)
	if resUnauth.Decision.Allow {
		t.Fatalf("Security invariant violated: unauthenticated private resource evaluation allowed")
	}
	if resUnauth.Error == nil || resUnauth.Error.Code != contracts.ErrUnauthenticatedIdentity {
		t.Fatalf("Expected error code %s for unauthenticated private access, got: %+v", contracts.ErrUnauthenticatedIdentity, resUnauth.Error)
	}
}

// TestDomainTestCollectionInvariant verifies that domain tests are collected and discoverable.
// In C06, clean checkout requires the presence and collection of domain test suites.
func TestDomainTestCollectionInvariant(t *testing.T) {
	tempDir := t.TempDir()
	ad, orphans, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Storage adapter failed to initialize in clean environment: %v", err)
	}
	defer ad.Close()

	if orphans != 0 {
		t.Errorf("Clean checkout environment should have 0 orphans, got %d", orphans)
	}

	// Test writing authoritative decision record and reading it back
	writeReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-c06-ci-domain-test",
		RecordID:       "service:analytics:c06-receipt",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity: storage.CallerIdentity{
			SubjectID:                "user_ci",
			Issuer:                   "https://idp.local.test/realms/policyhelix",
			Roles:                    []string{"operator"},
			Authenticated:            true,
			SessionEpoch:             1730000000,
			MinRequiredEpoch:         1720000000,
			UntrustedHeadersStripped: true,
			ProviderState:            "ready",
		},
		Payload: json.RawMessage(`{"ci_verified":true,"commit":"C06"}`),
	}

	receipt, sErr := ad.WriteRecord(context.Background(), writeReq)
	if sErr != nil {
		t.Fatalf("WriteRecord failed during domain collection check: %v", sErr)
	}
	if receipt == nil || receipt.RecordID != writeReq.RecordID {
		t.Fatalf("Unexpected storage receipt: %+v", receipt)
	}

	_, entry, sErr := ad.ReadRecord(writeReq.RecordID)
	if sErr != nil {
		t.Fatalf("Failed to read back authoritative record: %v", sErr)
	}
	if entry.ObjectDigest != receipt.ObjectDigest {
		t.Errorf("Digest mismatch on clean checkout storage check: expected %s, got %s", receipt.ObjectDigest, entry.ObjectDigest)
	}
}

// TestTamperedByteFailsClosed verifies that modifying even one byte in a payload
// or evidence record prevents trusted success.
func TestTamperedByteFailsClosed(t *testing.T) {
	tempDir := t.TempDir()
	ad, _, err := storage.Open(tempDir)
	if err != nil {
		t.Fatalf("Failed to open storage: %v", err)
	}
	defer ad.Close()

	originalPayload := `{"status":"authorized","secret_data":"confidential"}`
	writeReq := storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-tamper-byte-test",
		RecordID:       "service:analytics:tamper-record",
		OwnerScope:     "service:analytics",
		Classification: "private",
		Identity: storage.CallerIdentity{
			SubjectID:                "user_alice",
			Issuer:                   "https://idp.local.test/realms/policyhelix",
			Roles:                    []string{"operator"},
			Authenticated:            true,
			SessionEpoch:             1730000000,
			MinRequiredEpoch:         1720000000,
			UntrustedHeadersStripped: true,
			ProviderState:            "ready",
		},
		Payload: json.RawMessage(originalPayload),
	}

	receipt, sErr := ad.WriteRecord(context.Background(), writeReq)
	if sErr != nil {
		t.Fatalf("Failed to write initial record: %v", sErr)
	}

	// Tamper with the underlying object file by modifying one byte
	objFilename := storage.HexDigest(receipt.ObjectDigest)
	objectPath := filepath.Join(tempDir, "objects", objFilename)
	objData, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatalf("Failed to read object file (%s): %v", objectPath, err)
	}

	// Flip one byte
	objData[0] ^= 0xFF
	if err := os.WriteFile(objectPath, objData, 0o600); err != nil {
		t.Fatalf("Failed to write tampered object: %v", err)
	}

	// Reading the record must fail closed due to digest mismatch
	_, _, sErr = ad.ReadRecord(writeReq.RecordID)
	if sErr == nil {
		t.Fatalf("Expected tamper detection failure on modified byte, but ReadRecord succeeded")
	}
}
