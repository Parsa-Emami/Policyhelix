package storage

import (
	"context"
	"encoding/json"
	"testing"
)

func TestStorageAdapterUnit(t *testing.T) {
	dir := t.TempDir()
	ad, orphans, err := Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer ad.Close()
	if orphans != 0 {
		t.Errorf("Expected 0 orphans, got %d", orphans)
	}

	req := WriteRequest{
		SchemaVersion:  "1",
		OperationID:    "op-unit-01",
		RecordID:       "policyhelix:unit-record",
		OwnerScope:     "policyhelix",
		Classification: "private",
		Identity: CallerIdentity{
			SubjectID:                "user_alice",
			Issuer:                   "https://idp.local.test/realms/policyhelix",
			Roles:                    []string{"operator"},
			Authenticated:            true,
			SessionEpoch:             1730000000,
			UntrustedHeadersStripped: true,
			ProviderState:            "ready",
		},
		Payload: json.RawMessage(`{"unit":true}`),
	}

	rec, sErr := ad.WriteRecord(context.Background(), req)
	if sErr != nil {
		t.Fatalf("WriteRecord failed: %v", sErr)
	}
	if rec.Revision != 1 || rec.Replayed {
		t.Errorf("Unexpected receipt: %+v", rec)
	}
}
