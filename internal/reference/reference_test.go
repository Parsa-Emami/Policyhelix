package reference

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := make(map[string]string)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		content, rErr := os.ReadFile(path)
		if rErr != nil {
			return rErr
		}
		files[rel] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("failed to snapshot dir: %v", err)
	}
	return files
}

func TestSessionStoreProbeIsReadOnly(t *testing.T) {
	tmpDir := t.TempDir()
	ad, _, err := storage.Open(tmpDir)
	if err != nil {
		t.Fatalf("failed to open storage adapter: %v", err)
	}
	defer ad.Close()

	trusted, err := TrustedKey()
	if err != nil {
		t.Fatalf("failed to get trusted key: %v", err)
	}
	keyMgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(trusted))

	rt, err := NewRuntime(ad, tmpDir, keyMgr)
	if err != nil {
		t.Fatalf("failed to initialize runtime: %v", err)
	}
	defer rt.Close()

	// Initial probe: must succeed and remain read-only
	probe := rt.SessionStoreProbe(context.Background())
	if !probe.Ready {
		t.Fatalf("expected probe to be ready, got %+v", probe)
	}

	snapBefore := snapshotDir(t, tmpDir)

	// Run multiple probes in succession
	for i := 0; i < 10; i++ {
		p := rt.SessionStoreProbe(context.Background())
		if !p.Ready {
			t.Fatalf("probe %d failed: %+v", i, p)
		}
	}

	snapAfter := snapshotDir(t, tmpDir)

	if len(snapBefore) != len(snapAfter) {
		t.Fatalf("readiness probe modified file count: before %d, after %d", len(snapBefore), len(snapAfter))
	}
	for k, vBefore := range snapBefore {
		vAfter, exists := snapAfter[k]
		if !exists {
			t.Fatalf("file %s deleted by readiness probe", k)
		}
		if vBefore != vAfter {
			t.Fatalf("file %s mutated by readiness probe", k)
		}
	}
}

func TestSessionStoreProbeMemoryFallback(t *testing.T) {
	rt, err := NewRuntime(nil, "", nil)
	if err != nil {
		t.Fatalf("failed to initialize in-memory runtime: %v", err)
	}
	defer rt.Close()

	probe := rt.SessionStoreProbe(context.Background())
	if !probe.Ready {
		t.Fatalf("expected probe to be ready on memory fallback, got %+v", probe)
	}
}

func TestSessionIssuanceSecurityRejectsClientSuppliedID(t *testing.T) {
	tmpDir := t.TempDir()
	ad, _, err := storage.Open(tmpDir)
	if err != nil {
		t.Fatalf("failed to open storage adapter: %v", err)
	}
	defer ad.Close()

	trusted, err := TrustedKey()
	if err != nil {
		t.Fatalf("failed to get trusted key: %v", err)
	}
	keyMgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(trusted))

	rt, err := NewRuntime(ad, tmpDir, keyMgr)
	if err != nil {
		t.Fatalf("failed to initialize runtime: %v", err)
	}
	defer rt.Close()

	// Malicious candidate IDs: arbitrary token, path traversal, hex spoof
	candidates := []string{
		"attacker-chosen-session-id",
		"../../../../etc/passwd",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	for _, cand := range candidates {
		res := rt.Session(context.Background(), SessionRequest{
			SessionID: cand,
		})
		if res.Valid {
			t.Fatalf("expected session issuance with client-supplied ID %q to be rejected", cand)
		}
		if res.ErrorCode != auth.ErrCodeInvalidSessionRequest {
			t.Fatalf("expected error code %s for %q, got %s", auth.ErrCodeInvalidSessionRequest, cand, res.ErrorCode)
		}
	}

	// Normal issuance without client session_id must succeed and generate a secure ID
	okRes := rt.Session(context.Background(), SessionRequest{})
	if !okRes.Valid || okRes.SessionID == "" {
		t.Fatalf("expected valid session with authority-generated ID, got %+v", okRes)
	}
	if len(okRes.SessionID) != 64 {
		t.Fatalf("expected 64-hex-char cryptographically secure ID, got %s (len %d)", okRes.SessionID, len(okRes.SessionID))
	}
}

func TestSessionIssuanceConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	ad, _, err := storage.Open(tmpDir)
	if err != nil {
		t.Fatalf("failed to open storage adapter: %v", err)
	}
	defer ad.Close()

	trusted, err := TrustedKey()
	if err != nil {
		t.Fatalf("failed to get trusted key: %v", err)
	}
	keyMgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(trusted))

	rt, err := NewRuntime(ad, tmpDir, keyMgr)
	if err != nil {
		t.Fatalf("failed to initialize runtime: %v", err)
	}
	defer rt.Close()

	const count = 20
	type result struct {
		id  string
		err error
	}
	ch := make(chan result, count)

	for i := 0; i < count; i++ {
		go func() {
			res := rt.Session(context.Background(), SessionRequest{})
			if !res.Valid || res.SessionID == "" {
				ch <- result{err: os.ErrInvalid}
				return
			}
			ch <- result{id: res.SessionID}
		}()
	}

	seen := make(map[string]bool)
	for i := 0; i < count; i++ {
		r := <-ch
		if r.err != nil {
			t.Fatalf("concurrent session issuance failed: %v", r.err)
		}
		if len(r.id) != 64 {
			t.Fatalf("invalid session ID length: %s", r.id)
		}
		if seen[r.id] {
			t.Fatalf("duplicate session ID generated under concurrency: %s", r.id)
		}
		seen[r.id] = true
	}
}

func TestEvaluatorSelfTest(t *testing.T) {
	probe := EvaluatorSelfTest(context.Background())
	if !probe.Ready {
		t.Fatalf("evaluator self-test failed: %+v", probe)
	}
}
