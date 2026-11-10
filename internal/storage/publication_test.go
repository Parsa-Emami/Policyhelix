package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

var c40Request = WriteRequest{
	SchemaVersion: "1", OperationID: "c40-update", RecordID: "policyhelix:c40",
	OwnerScope: "policyhelix", Classification: "private", Payload: []byte(`{"decision":"deny"}`),
	Identity: CallerIdentity{
		SubjectID: "user_alice", Issuer: "https://idp.local.test/realms/policyhelix", Roles: []string{"operator"},
		Authenticated: true, SessionEpoch: 1730000000, UntrustedHeadersStripped: true, ProviderState: "ready",
	},
}

func TestC40WriterProcess(t *testing.T) {
	root := os.Getenv("POLICYHELIX_C40_STORE")
	if root == "" {
		return
	}
	afterPublication, err := strconv.ParseBool(os.Getenv("POLICYHELIX_C40_AFTER_PUBLICATION"))
	if err != nil {
		t.Fatal(err)
	}
	adapter, _, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	adapter.writeBoundary = func(published bool) {
		if published == afterPublication {
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				t.Fatal(err)
			}
		}
	}
	receipt, writeError := adapter.WriteRecord(context.Background(), c40Request)
	t.Fatalf("write returned before SIGKILL: %+v %v", receipt, writeError)
}

func TestC40ManifestCrashAndReplay(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run("published_"+strconv.FormatBool(published), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			root := t.TempDir()
			adapter, _, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			initial := c40Request
			initial.OperationID = "c40-seed"
			initial.Payload = []byte(`{"decision":"allow"}`)
			if _, writeError := adapter.WriteRecord(ctx, initial); writeError != nil {
				t.Fatal(writeError)
			}
			adapter.Close()

			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestC40WriterProcess$")
			child.Env = append(os.Environ(), "POLICYHELIX_C40_STORE="+root, "POLICYHELIX_C40_AFTER_PUBLICATION="+strconv.FormatBool(published))
			output, err := child.CombinedOutput()
			var stopped *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &stopped) || stopped.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("writer did not receive SIGKILL: %v %s", err, output)
			}
			reopened, _, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			expected, revision := initial.Payload, int64(1)
			if published {
				expected, revision = c40Request.Payload, 2
			}
			data, record, readError := reopened.ReadRecord(initial.RecordID)
			if readError != nil || record == nil || record.Revision != revision || !bytes.Equal(data, expected) {
				t.Fatalf("unexpected authoritative state: %s %+v %v", data, record, readError)
			}
			receipt, writeError := reopened.WriteRecord(ctx, c40Request)
			if writeError != nil || receipt == nil || receipt.Replayed != published || receipt.Revision != 2 {
				t.Fatalf("unexpected retry: %+v %v", receipt, writeError)
			}
			oversized := c40Request
			oversized.OperationID = "c40-oversized"
			oversized.Payload = append(append([]byte{'"'}, bytes.Repeat([]byte("x"), MaxPayloadBytes)...), '"')
			if _, writeError := reopened.WriteRecord(ctx, oversized); writeError == nil || writeError.Code != ErrPayloadTooLarge || writeError.Retryable {
				t.Fatalf("expected a terminal quota error: %v", writeError)
			}
			data, record, readError = reopened.ReadRecord(initial.RecordID)
			if readError != nil || record == nil || record.Revision != 2 || !bytes.Equal(data, c40Request.Payload) {
				t.Fatalf("quota rejection altered committed state: %s %+v %v", data, record, readError)
			}
		})
	}
}
