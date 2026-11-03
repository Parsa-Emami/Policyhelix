package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/storage"
)

func validWriteRequest(opID, recordID string, payload string) storage.WriteRequest {
	return storage.WriteRequest{
		SchemaVersion:  "1",
		OperationID:    opID,
		RecordID:       recordID,
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
		Payload: json.RawMessage(payload),
	}
}

func TestAuthoritativeWriteAndAtomicVisibleState(t *testing.T) {
	dir := t.TempDir()
	ad, orphans, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("Failed to open storage adapter: %v", err)
	}
	defer ad.Close()
	if orphans != 0 {
		t.Errorf("Expected 0 orphans on clean dir, got %d", orphans)
	}

	req := validWriteRequest("op-c05-001", "service:analytics:bundle-rev-1", `{"bundle_revision":1,"digest":"sha256:4a5c88e5d2639201f99c235b2e912f2cbe6783965b1287f3b89b1424e12e12e8"}`)
	receipt, sErr := ad.WriteRecord(context.Background(), req)
	if sErr != nil {
		t.Fatalf("WriteRecord failed: %v", sErr)
	}
	if receipt.Revision != 1 || receipt.Replayed {
		t.Errorf("Expected revision=1 and replayed=false, got %+v", receipt)
	}

	// Read back and verify content integrity
	data, entry, readErr := ad.ReadRecord("service:analytics:bundle-rev-1")
	if readErr != nil {
		t.Fatalf("ReadRecord failed: %v", readErr)
	}
	if string(data) != string(req.Payload) {
		t.Errorf("Payload mismatch: got %s, want %s", string(data), string(req.Payload))
	}
	if entry.Revision != 1 || entry.OperationID != "op-c05-001" {
		t.Errorf("Unexpected entry metadata: %+v", entry)
	}
}

func TestIdempotencyReplayAndConflictRejection(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer ad.Close()

	req := validWriteRequest("op-idem-100", "service:analytics:epoch-state", `{"session_epoch":1730000500}`)
	r1, sErr := ad.WriteRecord(context.Background(), req)
	if sErr != nil {
		t.Fatalf("First write failed: %v", sErr)
	}
	if r1.Replayed || r1.Revision != 1 {
		t.Fatalf("Unexpected first receipt: %+v", r1)
	}

	// Replay identical operation_id and payload
	r2, sErr := ad.WriteRecord(context.Background(), req)
	if sErr != nil {
		t.Fatalf("Idempotent replay failed: %v", sErr)
	}
	if !r2.Replayed || r2.Revision != 1 || r2.ObjectDigest != r1.ObjectDigest {
		t.Errorf("Expected replayed=true with identical revision 1 and digest, got %+v", r2)
	}

	// Reuse same operation_id with modified payload -> must fail loudly with OPERATION_ID_CONFLICT
	conflictReq := validWriteRequest("op-idem-100", "service:analytics:epoch-state", `{"session_epoch":9999999999}`)
	_, conflictErr := ad.WriteRecord(context.Background(), conflictReq)
	if conflictErr == nil || conflictErr.Code != storage.ErrOperationConflict {
		t.Fatalf("Expected %s on conflicting operation_id reuse, got %+v", storage.ErrOperationConflict, conflictErr)
	}
}

func TestSingleWriterLockContention(t *testing.T) {
	dir := t.TempDir()
	ad1, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("First Open failed: %v", err)
	}
	defer ad1.Close()

	// Second concurrent open on same directory must fail with SINGLE_WRITER_LOCK_BUSY
	_, _, err2 := storage.Open(dir)
	if err2 == nil {
		t.Fatalf("Expected second Open to fail due to single-writer lock contention")
	}
	sErr, ok := err2.(*storage.StorageError)
	if !ok || sErr.Code != storage.ErrLockContention {
		t.Errorf("Expected %s, got %v", storage.ErrLockContention, err2)
	}
}

func TestInterruptedStagingAndDiskFullRecovery(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Commit initial valid record (revision 1)
	req1 := validWriteRequest("op-rec-1", "service:analytics:policy-v1", `{"version":1}`)
	if _, sErr := ad.WriteRecord(context.Background(), req1); sErr != nil {
		t.Fatalf("Initial write failed: %v", sErr)
	}

	// 1. Simulate disk full on second write
	ad.Faults.SimulateDiskFull = true
	req2 := validWriteRequest("op-rec-2", "service:analytics:policy-v2", `{"version":2}`)
	_, diskErr := ad.WriteRecord(context.Background(), req2)
	if diskErr == nil || diskErr.Code != storage.ErrDiskFullOrWriteFailed {
		t.Fatalf("Expected %s, got %+v", storage.ErrDiskFullOrWriteFailed, diskErr)
	}
	ad.Faults.SimulateDiskFull = false

	// 2. Simulate interrupted write after staging (leaves orphan staging file)
	ad.Faults.InterruptAfterStaging = true
	_, intErr := ad.WriteRecord(context.Background(), req2)
	if intErr == nil || intErr.Code != storage.ErrInterruptedWrite {
		t.Fatalf("Expected %s, got %+v", storage.ErrInterruptedWrite, intErr)
	}
	ad.Faults.InterruptAfterStaging = false

	// Close and reopen adapter -> ReconcileStartup must purge orphan staging file and preserve revision 1
	_ = ad.Close()

	adRecovered, orphansCleaned, reopenErr := storage.Open(dir)
	if reopenErr != nil {
		t.Fatalf("Recovery Open failed: %v", reopenErr)
	}
	defer adRecovered.Close()

	if orphansCleaned < 1 {
		t.Errorf("Expected at least 1 orphan staging file cleaned on startup, got %d", orphansCleaned)
	}

	manifest, mErr := adRecovered.GetManifest()
	if mErr != nil {
		t.Fatalf("GetManifest failed: %v", mErr)
	}
	if manifest.Revision != 1 {
		t.Errorf("Expected revision to remain 1 after interrupted write, got %d", manifest.Revision)
	}

	// Retry req2 after recovery -> must succeed cleanly as revision 2
	r2, retryErr := adRecovered.WriteRecord(context.Background(), req2)
	if retryErr != nil {
		t.Fatalf("Retry write after recovery failed: %v", retryErr)
	}
	if r2.Revision != 2 || r2.Replayed {
		t.Errorf("Expected revision 2 on retry after uncommitted interruption, got %+v", r2)
	}
}

func TestNegativeSecurityInvariantsFailBeforeSideEffects(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer ad.Close()

	// 1. Unauthenticated identity
	unauth := validWriteRequest("op-neg-1", "service:analytics:sec-1", `{"data":"secret"}`)
	unauth.Identity.Authenticated = false
	if _, sErr := ad.WriteRecord(context.Background(), unauth); sErr == nil || sErr.Code != storage.ErrUnauthenticatedIdentity {
		t.Errorf("Expected %s, got %+v", storage.ErrUnauthenticatedIdentity, sErr)
	}

	// 2. Expired / revoked session epoch
	expired := validWriteRequest("op-neg-2", "service:analytics:sec-1", `{"data":"secret"}`)
	expired.Identity.SessionEpoch = 1710000000
	expired.Identity.MinRequiredEpoch = 1720000000
	if _, sErr := ad.WriteRecord(context.Background(), expired); sErr == nil || sErr.Code != storage.ErrExpiredSession {
		t.Errorf("Expected %s, got %+v", storage.ErrExpiredSession, sErr)
	}

	// 3. Forged header (untrusted headers not stripped)
	forged := validWriteRequest("op-neg-3", "service:analytics:sec-1", `{"data":"secret"}`)
	forged.Identity.UntrustedHeadersStripped = false
	if _, sErr := ad.WriteRecord(context.Background(), forged); sErr == nil || sErr.Code != storage.ErrForgedHeader {
		t.Errorf("Expected %s, got %+v", storage.ErrForgedHeader, sErr)
	}

	// 4. Unrelated owner / object scope violation
	wrongScope := validWriteRequest("op-neg-4", "tenant_other:secret-record", `{"data":"secret"}`)
	wrongScope.OwnerScope = "service:analytics"
	if _, sErr := ad.WriteRecord(context.Background(), wrongScope); sErr == nil || sErr.Code != storage.ErrScopeViolation {
		t.Errorf("Expected %s, got %+v", storage.ErrScopeViolation, sErr)
	}

	// 5. Unavailable identity provider fails closed
	outage := validWriteRequest("op-neg-5", "service:analytics:sec-1", `{"data":"secret"}`)
	outage.Identity.ProviderState = "unavailable"
	if _, sErr := ad.WriteRecord(context.Background(), outage); sErr == nil || sErr.Code != storage.ErrProviderUnavailable {
		t.Errorf("Expected %s, got %+v", storage.ErrProviderUnavailable, sErr)
	}

	// Verify zero side effects occurred in manifest or objects directory
	m, _ := ad.GetManifest()
	if m.Revision != 0 || len(m.Records) != 0 || len(m.Operations) != 0 {
		t.Errorf("Expected zero committed state after rejected security requests, got %+v", m)
	}
}

func TestTamperedObjectDetectionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	req := validWriteRequest("op-tamper-1", "service:analytics:important", `{"integrity":"intact"}`)
	receipt, sErr := ad.WriteRecord(context.Background(), req)
	if sErr != nil {
		t.Fatalf("Write failed: %v", sErr)
	}

	// Corrupt the underlying object file on disk
	objPath := filepath.Join(dir, storage.ObjectsDirName, storage.HexDigest(receipt.ObjectDigest))
	if writeErr := os.WriteFile(objPath, []byte(`{"integrity":"corrupted"}`), 0600); writeErr != nil {
		t.Fatalf("Failed to corrupt object file: %v", writeErr)
	}

	// Reading corrupted record must fail closed with CORRUPT_OR_MISSING_OBJECT
	_, _, readErr := ad.ReadRecord("service:analytics:important")
	if readErr == nil || readErr.Code != storage.ErrCorruptState {
		t.Fatalf("Expected %s on tampered object read, got %+v", storage.ErrCorruptState, readErr)
	}
	_ = ad.Close()

	// Reopening corrupted store must fail startup reconciliation
	_, _, reopenErr := storage.Open(dir)
	if reopenErr == nil {
		t.Fatalf("Expected Open to fail startup reconciliation when object digest is tampered")
	}
}

func TestC05FixturesIntegration(t *testing.T) {
	fixtureDir := filepath.Join("..", "tests", "fixtures", "policyhelix", "C05")
	if _, err := os.Stat(fixtureDir); os.IsNotExist(err) {
		fixtureDir = filepath.Join("fixtures", "policyhelix", "C05")
	}

	dir := t.TempDir()
	ad, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer ad.Close()

	// 1. Positive fixture
	posBytes, err := os.ReadFile(filepath.Join(fixtureDir, "positive-authoritative-write.json"))
	if err != nil {
		t.Fatalf("Failed to read positive fixture: %v", err)
	}
	var posReq storage.WriteRequest
	if err := json.Unmarshal(posBytes, &posReq); err != nil {
		t.Fatalf("Unmarshal positive fixture: %v", err)
	}
	rec, sErr := ad.WriteRecord(context.Background(), posReq)
	if sErr != nil || rec.Revision != 1 {
		t.Fatalf("Expected positive fixture to commit revision 1, got rec=%+v, err=%+v", rec, sErr)
	}

	// 2. Negative replayed conflict fixture
	confBytes, err := os.ReadFile(filepath.Join(fixtureDir, "negative-replayed-conflict.json"))
	if err != nil {
		t.Fatalf("Failed to read conflict fixture: %v", err)
	}
	var confReq storage.WriteRequest
	if err := json.Unmarshal(confBytes, &confReq); err != nil {
		t.Fatalf("Unmarshal conflict fixture: %v", err)
	}
	_, confErr := ad.WriteRecord(context.Background(), confReq)
	if confErr == nil || confErr.Code != storage.ErrOperationConflict {
		t.Fatalf("Expected %s for conflict fixture, got %+v", storage.ErrOperationConflict, confErr)
	}

	// 3. Negative unauthenticated / forged write fixture
	unauthBytes, err := os.ReadFile(filepath.Join(fixtureDir, "negative-unauthenticated-write.json"))
	if err != nil {
		t.Fatalf("Failed to read unauth fixture: %v", err)
	}
	var unauthReq storage.WriteRequest
	if err := json.Unmarshal(unauthBytes, &unauthReq); err != nil {
		t.Fatalf("Unmarshal unauth fixture: %v", err)
	}
	_, unauthErr := ad.WriteRecord(context.Background(), unauthReq)
	if unauthErr == nil || unauthErr.Code != storage.ErrUnauthenticatedIdentity {
		t.Fatalf("Expected %s for unauth fixture, got %+v", storage.ErrUnauthenticatedIdentity, unauthErr)
	}

	// 4. Negative scope / provider violation fixture
	scopeBytes, err := os.ReadFile(filepath.Join(fixtureDir, "negative-scope-or-provider-violation.json"))
	if err != nil {
		t.Fatalf("Failed to read scope fixture: %v", err)
	}
	var scopeReq storage.WriteRequest
	if err := json.Unmarshal(scopeBytes, &scopeReq); err != nil {
		t.Fatalf("Unmarshal scope fixture: %v", err)
	}
	_, scopeErr := ad.WriteRecord(context.Background(), scopeReq)
	if scopeErr == nil || scopeErr.Code != storage.ErrScopeViolation {
		t.Fatalf("Expected %s for scope violation fixture, got %+v", storage.ErrScopeViolation, scopeErr)
	}
}
