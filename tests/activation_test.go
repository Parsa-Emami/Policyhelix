package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/policy"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

const (
	c12EvalTime   = "2026-11-03T12:00:00Z"
	c12FixtureDir = "fixtures/policyhelix/C12"
)

type c12ActivationStep struct {
	OperationID string                   `json:"operation_id"`
	Identity    storage.CallerIdentity   `json:"identity"`
	Bundle      policy.LocalPolicyBundle `json:"bundle"`
}

type c12Expected struct {
	FirstStatus           string `json:"first_status,omitempty"`
	Status                string `json:"status,omitempty"`
	Durable               bool   `json:"durable"`
	Replayed              bool   `json:"replayed"`
	Revision              int64  `json:"revision"`
	StateRevision         int64  `json:"state_revision"`
	HighestRevision       int64  `json:"highest_revision"`
	StorageRevisionStable bool   `json:"storage_revision_stable,omitempty"`
	RestoreStatus         string `json:"restore_status"`
	Active                bool   `json:"active"`
	Allow                 bool   `json:"allow"`
	ErrorCode             string `json:"error_code,omitempty"`
	DecisionErrorCode     string `json:"decision_error_code,omitempty"`
	PolicyDigest          string `json:"policy_digest,omitempty"`
}

type c12FixtureFile struct {
	FixtureID      string                  `json:"fixture_id"`
	CommitID       string                  `json:"commit_id"`
	Description    string                  `json:"description"`
	SchemaVersion  string                  `json:"schema_version"`
	TrustedKeys    []bundles.TrustedKey    `json:"trusted_keys"`
	EvaluationTime string                  `json:"evaluation_time"`
	Preload        *c12ActivationStep      `json:"preload,omitempty"`
	Activation     *c12ActivationStep      `json:"activation,omitempty"`
	Replays        int                     `json:"replays,omitempty"`
	Evaluation     *policy.BundleEvalInput `json:"evaluation,omitempty"`
	Expected       c12Expected             `json:"expected"`
}

type c12CountingStore struct {
	inner   bundles.ActivationStore
	commits int
}

func (s *c12CountingStore) CommitActivation(ctx context.Context, record bundles.ActivationRecord, identity storage.CallerIdentity) (*bundles.ActivationCommit, error) {
	s.commits++
	return s.inner.CommitActivation(ctx, record, identity)
}

func (s *c12CountingStore) LoadActivation() (*bundles.StoredActivation, error) {
	return s.inner.LoadActivation()
}

func c12Clock() func() time.Time {
	fixed := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return fixed }
}

func c12ClockAt(t *testing.T, value string) func() time.Time {
	t.Helper()
	if strings.TrimSpace(value) == "" {
		return c12Clock()
	}
	fixed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("invalid fixture evaluation_time %q: %v", value, err)
	}
	return func() time.Time { return fixed.UTC() }
}

func c12Keyring(t *testing.T) *bundles.Keyring {
	t.Helper()
	keyring, _ := getTestKeyring(t)
	return keyring
}

func c12OpenManager(t *testing.T, dir string) (*storage.Adapter, *bundles.ActivationManager) {
	t.Helper()
	adapter, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	manager := bundles.NewActivationManager(bundles.NewStorageActivationStore(adapter), c12Keyring(t))
	manager.Now = c12Clock()
	return adapter, manager
}

func c12BuildBundle(t *testing.T, revision int64, bundleID, expiresAt string) policy.LocalPolicyBundle {
	t.Helper()
	spec := standardBuildSpec()
	spec.BundleID = bundleID
	spec.Revision = revision
	spec.ExpiresAt = expiresAt
	bundle, err := bundles.BuildDeterministicBundle(spec)
	if err != nil {
		t.Fatalf("BuildDeterministicBundle failed: %v", err)
	}
	return bundle
}

func c12OperatorIdentity() storage.CallerIdentity {
	return storage.CallerIdentity{
		SubjectID:                "operator-1",
		Issuer:                   testIssuer,
		Roles:                    []string{"operator"},
		Authenticated:            true,
		SessionEpoch:             1720000000,
		MinRequiredEpoch:         1710000000,
		UntrustedHeadersStripped: true,
		ProviderState:            "available",
	}
}

func c12UnauthenticatedIdentity() storage.CallerIdentity {
	return storage.CallerIdentity{
		SubjectID:                "anonymous",
		Issuer:                   testIssuer,
		Roles:                    []string{"operator"},
		Authenticated:            false,
		SessionEpoch:             1720000000,
		UntrustedHeadersStripped: true,
		ProviderState:            "available",
	}
}

func c12Request(operationID string, identity storage.CallerIdentity, bundle policy.LocalPolicyBundle) bundles.ActivationRequest {
	return bundles.ActivationRequest{
		SchemaVersion: bundles.ActivationSchemaVersion,
		OperationID:   operationID,
		Identity:      identity,
		Bundle:        bundle,
	}
}

func c12AuthorizedInput(requestID string) policy.BundleEvalInput {
	return policy.BundleEvalInput{
		RequestID:  requestID,
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   c12EvalTime,
		Subject: policy.SubjectIdentity{
			ID:            "operator-1",
			Issuer:        testIssuer,
			Roles:         []string{"operator"},
			Authenticated: true,
		},
	}
}

func c12UnauthorizedPrivateInput(requestID string) policy.BundleEvalInput {
	return policy.BundleEvalInput{
		RequestID:  requestID,
		Path:       "/api/v1/analytics/reports",
		Action:     "read",
		DeadlineMS: 50,
		EvalTime:   c12EvalTime,
		Subject:    policy.SubjectIdentity{},
	}
}

func c12DecisionErrorCode(decision policy.BundleDecision) string {
	if decision.Error == nil {
		return ""
	}
	return decision.Error.Code
}

func c12AssertActivated(t *testing.T, result bundles.ActivationResult, revision int64) {
	t.Helper()
	if result.Status != bundles.ActivationStatusActivated {
		t.Fatalf("expected activated, got %+v", result)
	}
	if !result.Durable || result.Replayed {
		t.Fatalf("expected fresh durable activation, got %+v", result)
	}
	if result.Revision != revision || result.HighestRevision != revision || !result.Active {
		t.Fatalf("expected active revision %d, got %+v", revision, result)
	}
}

// TestC12AcceptanceCrashDuringSwitchRetainsPreviousAuthority proves Requirement F06: an interrupted
// activation at the staged-byte or manifest boundary leaves the previous bundle and highest accepted
// revision authoritative, and a restart exposes only that complete state.
func TestC12AcceptanceCrashDuringSwitchRetainsPreviousAuthority(t *testing.T) {
	boundaries := []struct {
		name string
		arm  func(*storage.Adapter)
	}{
		{name: "staged-byte-boundary", arm: func(adapter *storage.Adapter) { adapter.Faults.InterruptAfterStaging = true }},
		{name: "manifest-boundary", arm: func(adapter *storage.Adapter) { adapter.Faults.InterruptBeforeManifest = true }},
	}

	for _, boundary := range boundaries {
		t.Run(boundary.name, func(t *testing.T) {
			dir := t.TempDir()
			ctx := context.Background()

			adapter, manager := c12OpenManager(t, dir)
			rev3 := c12BuildBundle(t, 3, "bundle-analytics-v3", "2026-11-04T10:00:00Z")
			baseline := manager.Activate(ctx, c12Request("c12-crash-baseline-3", c12OperatorIdentity(), rev3))
			c12AssertActivated(t, baseline, 3)
			if baseline.StorageRevision != 1 {
				t.Fatalf("expected first storage revision 1, got %d", baseline.StorageRevision)
			}

			rev4 := c12BuildBundle(t, 4, "bundle-analytics-v4", "2026-11-04T10:00:00Z")
			boundary.arm(adapter)
			interrupted := manager.Activate(ctx, c12Request("c12-crash-candidate-4", c12OperatorIdentity(), rev4))
			if interrupted.Status != bundles.ActivationStatusRejected || interrupted.Durable {
				t.Fatalf("expected rejected, non-durable interrupted switch, got %+v", interrupted)
			}
			if interrupted.ErrorCode != storage.ErrInterruptedWrite {
				t.Fatalf("expected %s, got %s (%s)", storage.ErrInterruptedWrite, interrupted.ErrorCode, interrupted.Message)
			}
			if !interrupted.Active || interrupted.HighestRevision != 3 {
				t.Fatalf("expected previous authority retained, got %+v", interrupted)
			}
			if manager.HighestRevision() != 3 {
				t.Fatalf("in-memory highest revision advanced to %d", manager.HighestRevision())
			}

			if err := adapter.Close(); err != nil {
				t.Fatalf("close failed: %v", err)
			}
			restartedAdapter, restarted := c12OpenManager(t, dir)
			defer restartedAdapter.Close()

			state := restarted.Restore(ctx)
			if state.Status != bundles.ActivationStatusRestored || !state.Active {
				t.Fatalf("expected restored authority after crash, got %+v", state)
			}
			if state.Revision != 3 || state.HighestRevision != 3 || state.Digest != baseline.Digest || state.StorageRevision != 1 {
				t.Fatalf("restart exposed incomplete or newer state: %+v", state)
			}

			decision := restarted.Evaluate(ctx, c12AuthorizedInput("c12-crash-eval"))
			if !decision.Allow || decision.Revision != 3 || decision.PolicyDigest != baseline.Digest {
				t.Fatalf("previous authority did not authorize after restart: %+v", decision)
			}

			retried := restarted.Activate(ctx, c12Request("c12-crash-candidate-4", c12OperatorIdentity(), rev4))
			c12AssertActivated(t, retried, 4)
			if retried.StorageRevision != 2 {
				t.Fatalf("expected exactly one new storage revision, got %d", retried.StorageRevision)
			}

			after := restarted.Restore(ctx)
			if after.Status != bundles.ActivationStatusRestored || after.Revision != 4 || after.HighestRevision != 4 {
				t.Fatalf("expected completed switch to revision 4, got %+v", after)
			}
		})
	}
}

// TestC12ReplayAfterLostAckHasNoDuplicateSideEffect covers the replay and lost-ACK negative case:
// retrying an already committed operation is idempotent, while a delayed old operation can never
// overwrite newer authority.
func TestC12ReplayAfterLostAckHasNoDuplicateSideEffect(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	adapter, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer adapter.Close()

	counting := &c12CountingStore{inner: bundles.NewStorageActivationStore(adapter)}
	manager := bundles.NewActivationManager(counting, c12Keyring(t))
	manager.Now = c12Clock()

	rev3 := c12BuildBundle(t, 3, "bundle-analytics-v3", "2026-11-04T10:00:00Z")
	request := c12Request("c12-replay-3", c12OperatorIdentity(), rev3)
	first := manager.Activate(ctx, request) // the ACK of this call is deliberately discarded
	c12AssertActivated(t, first, 3)
	if counting.commits != 1 {
		t.Fatalf("expected one commit attempt, got %d", counting.commits)
	}

	manifest, sErr := adapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	if manifest.Revision != 1 || len(manifest.Operations) != 1 || len(manifest.Records) != 1 {
		t.Fatalf("expected exactly one committed operation, got %+v", manifest)
	}

	replayed := manager.Activate(ctx, request)
	if replayed.Status != bundles.ActivationStatusReplayed || !replayed.Replayed || !replayed.Durable || !replayed.Active {
		t.Fatalf("expected idempotent replay, got %+v", replayed)
	}
	if replayed.StorageRevision != first.StorageRevision || replayed.Digest != first.Digest || replayed.Revision != 3 {
		t.Fatalf("replay evidence changed: first=%+v replay=%+v", first, replayed)
	}
	if counting.commits != 1 {
		t.Fatalf("replay attempted another durable commit: %d", counting.commits)
	}

	rev4 := c12BuildBundle(t, 4, "bundle-analytics-v4", "2026-11-04T10:00:00Z")
	c12AssertActivated(t, manager.Activate(ctx, c12Request("c12-replay-4", c12OperatorIdentity(), rev4)), 4)
	if counting.commits != 2 {
		t.Fatalf("expected two total commit attempts, got %d", counting.commits)
	}

	delayed := manager.Activate(ctx, request)
	if delayed.Status != bundles.ActivationStatusRejected || delayed.ErrorCode != bundles.ErrCodeStaleOrReplayedRev {
		t.Fatalf("expected delayed operation to be rejected as stale, got %+v", delayed)
	}
	if !delayed.Active || delayed.HighestRevision != 4 {
		t.Fatalf("delayed replay disturbed current authority: %+v", delayed)
	}
	if active, ok := manager.Active(); !ok || active.Revision != 4 {
		t.Fatalf("expected revision 4 to stay active, got ok=%v bundle=%+v", ok, active)
	}

	conflicting := manager.Activate(ctx, c12Request("c12-replay-4", c12OperatorIdentity(), c12BuildBundle(t, 5, "bundle-analytics-v5", "2026-11-04T10:00:00Z")))
	if conflicting.Status != bundles.ActivationStatusRejected || conflicting.ErrorCode != storage.ErrOperationConflict {
		t.Fatalf("expected operation conflict for reused id with different content, got %+v", conflicting)
	}

	manifest, sErr = adapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	if manifest.Revision != 2 || len(manifest.Operations) != 2 {
		t.Fatalf("replay or conflict produced a duplicate side effect: %+v", manifest)
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	restartedAdapter, restarted := c12OpenManager(t, dir)
	defer restartedAdapter.Close()
	state := restarted.Restore(ctx)
	if state.Status != bundles.ActivationStatusRestored || state.Revision != 4 || state.HighestRevision != 4 {
		t.Fatalf("expected revision 4 to survive restart, got %+v", state)
	}
}

type c12FailReadAfterCommitStore struct {
	inner    bundles.ActivationStore
	failNext bool
}

func (s *c12FailReadAfterCommitStore) CommitActivation(ctx context.Context, record bundles.ActivationRecord, identity storage.CallerIdentity) (*bundles.ActivationCommit, error) {
	commit, err := s.inner.CommitActivation(ctx, record, identity)
	if err == nil {
		s.failNext = true
	}
	return commit, err
}

func (s *c12FailReadAfterCommitStore) LoadActivation() (*bundles.StoredActivation, error) {
	if s.failNext {
		s.failNext = false
		return nil, &bundles.ActivationStoreError{Code: bundles.ErrCodeActivationStoreUnavail, Message: "simulated read-back failure after commit", Retryable: true}
	}
	return s.inner.LoadActivation()
}

// TestC12CommitWithoutAckRecoversCompleteNewState covers the lost-acknowledgement window after the
// manifest rename: the caller is told the commit is unconfirmed, but a restart exposes the complete
// new state and a retry of the same operation is idempotent.
func TestC12CommitWithoutAckRecoversCompleteNewState(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	adapter, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}

	flaky := &c12FailReadAfterCommitStore{inner: bundles.NewStorageActivationStore(adapter)}
	manager := bundles.NewActivationManager(flaky, c12Keyring(t))
	manager.Now = c12Clock()

	rev3 := c12BuildBundle(t, 3, "bundle-analytics-v3", "2026-11-04T10:00:00Z")
	request := c12Request("c12-ack-window-3", c12OperatorIdentity(), rev3)
	unconfirmed := manager.Activate(ctx, request)
	if unconfirmed.Status != bundles.ActivationStatusRejected || unconfirmed.Durable || !unconfirmed.Retryable {
		t.Fatalf("expected unconfirmed, retryable outcome, got %+v", unconfirmed)
	}
	if unconfirmed.ErrorCode != bundles.ErrCodeActivationCommitUnconfirm {
		t.Fatalf("expected %s, got %s (%s)", bundles.ErrCodeActivationCommitUnconfirm, unconfirmed.ErrorCode, unconfirmed.Message)
	}

	manifest, sErr := adapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	if manifest.Revision != 1 || len(manifest.Operations) != 1 {
		t.Fatalf("expected one complete durable operation, got %+v", manifest)
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	restartedAdapter, restarted := c12OpenManager(t, dir)
	defer restartedAdapter.Close()
	state := restarted.Restore(ctx)
	if state.Status != bundles.ActivationStatusRestored || state.Revision != 3 || state.HighestRevision != 3 {
		t.Fatalf("restart did not expose the complete committed state: %+v", state)
	}

	replayed := restarted.Activate(ctx, request)
	if replayed.Status != bundles.ActivationStatusReplayed || !replayed.Replayed || !replayed.Durable {
		t.Fatalf("expected idempotent replay of the unacknowledged commit, got %+v", replayed)
	}
	manifest, sErr = restartedAdapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	if manifest.Revision != 1 {
		t.Fatalf("replay after restart created a duplicate side effect: %+v", manifest)
	}
}

// TestC12DiskFullFailsClosedWithoutUnboundedRetry covers the exhausted-disk negative case: one typed
// retryable rejection per attempt, previous authority retained, and a single revision advance on retry.
func TestC12DiskFullFailsClosedWithoutUnboundedRetry(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	adapter, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open failed: %v", err)
	}
	defer adapter.Close()

	counting := &c12CountingStore{inner: bundles.NewStorageActivationStore(adapter)}
	manager := bundles.NewActivationManager(counting, c12Keyring(t))
	manager.Now = c12Clock()

	rev3 := c12BuildBundle(t, 3, "bundle-analytics-v3", "2026-11-04T10:00:00Z")
	c12AssertActivated(t, manager.Activate(ctx, c12Request("c12-disk-baseline-3", c12OperatorIdentity(), rev3)), 3)

	adapter.Faults.SimulateDiskFull = true
	rev4 := c12BuildBundle(t, 4, "bundle-analytics-v4", "2026-11-04T10:00:00Z")
	rejected := manager.Activate(ctx, c12Request("c12-disk-candidate-4", c12OperatorIdentity(), rev4))
	if rejected.Status != bundles.ActivationStatusRejected || rejected.Durable || !rejected.Retryable {
		t.Fatalf("expected typed retryable rejection, got %+v", rejected)
	}
	if rejected.ErrorCode != storage.ErrDiskFullOrWriteFailed {
		t.Fatalf("expected %s, got %s", storage.ErrDiskFullOrWriteFailed, rejected.ErrorCode)
	}
	if !rejected.Active || rejected.HighestRevision != 3 {
		t.Fatalf("expected previous authority retained, got %+v", rejected)
	}
	if counting.commits != 2 {
		t.Fatalf("expected exactly one commit attempt for the failed switch, got %d total", counting.commits)
	}
	manifest, sErr := adapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	if manifest.Revision != 1 {
		t.Fatalf("disk-full attempt advanced the manifest to revision %d", manifest.Revision)
	}

	adapter.Faults.SimulateDiskFull = false
	retried := manager.Activate(ctx, c12Request("c12-disk-candidate-4", c12OperatorIdentity(), rev4))
	c12AssertActivated(t, retried, 4)
	if retried.StorageRevision != 2 || counting.commits != 3 {
		t.Fatalf("expected one new storage revision from one retry, got %+v commits=%d", retried, counting.commits)
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	restartedAdapter, restarted := c12OpenManager(t, dir)
	defer restartedAdapter.Close()
	state := restarted.Restore(ctx)
	if state.Status != bundles.ActivationStatusRestored || state.Revision != 4 {
		t.Fatalf("expected revision 4 after restart, got %+v", state)
	}
}

// TestC12OversizedActivationRecordFailsClosed covers the exhausted-quota bound: a bundle that fits the
// policy bundle bound but not the bounded activation record is rejected before any durable write.
func TestC12OversizedActivationRecordFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	adapter, manager := c12OpenManager(t, dir)
	defer adapter.Close()

	bundle := c12OversizedBundle(t)
	result := manager.Activate(ctx, c12Request("c12-oversized-1", c12OperatorIdentity(), bundle))
	if result.Status != bundles.ActivationStatusRejected || result.Durable || result.Active {
		t.Fatalf("expected non-durable oversized rejection, got %+v", result)
	}
	if result.ErrorCode != storage.ErrPayloadTooLarge {
		t.Fatalf("expected %s, got %s (%s)", storage.ErrPayloadTooLarge, result.ErrorCode, result.Message)
	}

	manifest, sErr := adapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	if manifest.Revision != 0 || len(manifest.Records) != 0 || len(manifest.Operations) != 0 {
		t.Fatalf("oversized activation produced a side effect: %+v", manifest)
	}

	state := manager.Restore(ctx)
	if state.Status != bundles.ActivationStatusEmpty || state.Active || state.HighestRevision != 0 {
		t.Fatalf("expected empty state after oversized rejection, got %+v", state)
	}
	decision := manager.Evaluate(ctx, c12AuthorizedInput("c12-oversized-eval"))
	if decision.Allow || c12DecisionErrorCode(decision) != policy.ErrCodeNoActiveBundle {
		t.Fatalf("expected fail-closed evaluation without authority, got %+v", decision)
	}
}

// TestC12PrivateResourcesFailClosed covers the private-resource negative case, including an
// authenticated subject without the required role and a corrupt durable record.
func TestC12PrivateResourcesFailClosed(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	adapter, manager := c12OpenManager(t, dir)
	defer adapter.Close()

	emptyDecision := manager.Evaluate(ctx, c12UnauthorizedPrivateInput("c12-no-authority"))
	if emptyDecision.Allow || c12DecisionErrorCode(emptyDecision) != policy.ErrCodeNoActiveBundle {
		t.Fatalf("expected no-authority fail closed, got %+v", emptyDecision)
	}

	rev3 := c12BuildBundle(t, 3, "bundle-analytics-v3", "2026-11-04T10:00:00Z")
	unauth := manager.Activate(ctx, c12Request("c12-unauth-3", c12UnauthenticatedIdentity(), rev3))
	if unauth.Status != bundles.ActivationStatusRejected || unauth.Durable || unauth.ErrorCode != storage.ErrUnauthenticatedIdentity {
		t.Fatalf("expected unauthenticated rejection, got %+v", unauth)
	}
	if state := manager.Restore(ctx); state.Status != bundles.ActivationStatusEmpty {
		t.Fatalf("unauthenticated attempt left durable state: %+v", state)
	}

	c12AssertActivated(t, manager.Activate(ctx, c12Request("c12-private-3", c12OperatorIdentity(), rev3)), 3)

	denied := manager.Evaluate(ctx, c12UnauthorizedPrivateInput("c12-private-denied"))
	if denied.Allow || c12DecisionErrorCode(denied) != policy.ErrCodePrivateFailClosed {
		t.Fatalf("expected private resource fail closed, got %+v", denied)
	}

	viewerInput := c12AuthorizedInput("c12-private-viewer")
	viewerInput.Subject.Roles = []string{"viewer"}
	viewer := manager.Evaluate(ctx, viewerInput)
	if viewer.Allow || c12DecisionErrorCode(viewer) != policy.ErrCodePrivateFailClosed {
		t.Fatalf("expected insufficient-role fail closed, got %+v", viewer)
	}

	allowed := manager.Evaluate(ctx, c12AuthorizedInput("c12-private-allowed"))
	if !allowed.Allow || allowed.Revision != 3 || c12DecisionErrorCode(allowed) != "" {
		t.Fatalf("expected authorized operator decision, got %+v", allowed)
	}

	manifest, sErr := adapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	entry, ok := manifest.Records[bundles.ActivePolicyRecordID]
	if !ok {
		t.Fatalf("active record missing from manifest: %+v", manifest)
	}
	objectPath := filepath.Join(dir, storage.ObjectsDirName, storage.HexDigest(entry.ObjectDigest))
	if err := os.WriteFile(objectPath, []byte(`{"tampered":true}`), 0600); err != nil {
		t.Fatalf("failed to tamper active record object: %v", err)
	}

	corrupt := bundles.NewActivationManager(bundles.NewStorageActivationStore(adapter), c12Keyring(t))
	corrupt.Now = c12Clock()
	corruptState := corrupt.Restore(ctx)
	if corruptState.Status != bundles.ActivationStatusRejected || corruptState.Active || corruptState.ErrorCode != storage.ErrCorruptState {
		t.Fatalf("expected corrupt durable state to fail closed, got %+v", corruptState)
	}
	blocked := corrupt.Activate(ctx, c12Request("c12-after-corrupt-4", c12OperatorIdentity(), c12BuildBundle(t, 4, "bundle-analytics-v4", "2026-11-04T10:00:00Z")))
	if blocked.Status != bundles.ActivationStatusRejected || blocked.ErrorCode != bundles.ErrCodeCorruptActivationState {
		t.Fatalf("expected activation blocked by corrupt state, got %+v", blocked)
	}
	if decision := corrupt.Evaluate(ctx, c12AuthorizedInput("c12-corrupt-eval")); decision.Allow {
		t.Fatalf("corrupt authority authorized a request: %+v", decision)
	}
	after, sErr := adapter.GetManifest()
	if sErr != nil {
		t.Fatalf("GetManifest failed: %v", sErr)
	}
	if after.Revision != 1 {
		t.Fatalf("corrupt-state activation overwrote durable authority: %+v", after)
	}
}

// TestC12FixturesAndManifestIntegration verifies every C12 fixture hash, license and declared outcome.
func TestC12FixturesAndManifestIntegration(t *testing.T) {
	manifestRaw, err := os.ReadFile(filepath.Join(c12FixtureDir, "manifest.json"))
	if err != nil {
		t.Fatalf("failed to read C12 manifest: %v", err)
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
		t.Fatalf("failed to unmarshal C12 manifest: %v", err)
	}
	if manifest.CommitID != "C12" {
		t.Fatalf("expected commit_id C12, got %s", manifest.CommitID)
	}
	if len(manifest.Fixtures) != 10 {
		t.Fatalf("expected 10 C12 fixtures, got %d", len(manifest.Fixtures))
	}

	for _, entry := range manifest.Fixtures {
		base := filepath.Base(entry.Path)
		raw, err := os.ReadFile(filepath.Join(c12FixtureDir, base))
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

		var fx c12FixtureFile
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("failed to unmarshal fixture %s: %v", base, err)
		}
		if fx.CommitID != "C12" || fx.FixtureID != entry.FixtureID {
			t.Fatalf("fixture identity mismatch for %s: %+v", base, fx)
		}
		t.Run(entry.FixtureID, func(t *testing.T) {
			runC12Fixture(t, fx)
		})
	}
}

func runC12Fixture(t *testing.T, fx c12FixtureFile) {
	t.Helper()
	if fx.SchemaVersion != bundles.ActivationSchemaVersion {
		t.Fatalf("unexpected fixture schema_version %q", fx.SchemaVersion)
	}

	dir := t.TempDir()
	ctx := context.Background()
	adapter, manager := c12OpenManager(t, dir)
	manager.Now = c12ClockAt(t, fx.EvaluationTime)

	if fx.Preload != nil {
		preloaded := manager.Activate(ctx, c12Request(fx.Preload.OperationID, fx.Preload.Identity, fx.Preload.Bundle))
		if preloaded.Status != bundles.ActivationStatusActivated {
			t.Fatalf("preload activation failed: %+v", preloaded)
		}
	}

	var results []bundles.ActivationResult
	if fx.Activation != nil {
		replays := fx.Replays
		if replays < 1 {
			replays = 1
		}
		for i := 0; i < replays; i++ {
			results = append(results, manager.Activate(ctx, c12Request(fx.Activation.OperationID, fx.Activation.Identity, fx.Activation.Bundle)))
		}
	}

	if len(results) > 0 {
		final := results[len(results)-1]
		expected := fx.Expected
		if expected.FirstStatus != "" && results[0].Status != expected.FirstStatus {
			t.Fatalf("expected first attempt status %q, got %+v", expected.FirstStatus, results[0])
		}
		if final.Status != expected.Status {
			t.Fatalf("expected final status %q, got %+v", expected.Status, final)
		}
		if final.Durable != expected.Durable || final.Replayed != expected.Replayed {
			t.Fatalf("expected durable=%v replayed=%v, got %+v", expected.Durable, expected.Replayed, final)
		}
		if final.Revision != expected.Revision || final.HighestRevision != expected.HighestRevision {
			t.Fatalf("expected revision %d highest %d, got %+v", expected.Revision, expected.HighestRevision, final)
		}
		if final.ErrorCode != expected.ErrorCode {
			t.Fatalf("expected error code %q, got %+v", expected.ErrorCode, final)
		}
		if expected.StorageRevisionStable && results[0].StorageRevision != final.StorageRevision {
			t.Fatalf("replay changed storage revision: first=%d final=%d", results[0].StorageRevision, final.StorageRevision)
		}
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	restartedAdapter, restarted := c12OpenManager(t, dir)
	defer restartedAdapter.Close()
	restarted.Now = c12ClockAt(t, fx.EvaluationTime)

	state := restarted.Restore(ctx)
	if state.Status != fx.Expected.RestoreStatus {
		t.Fatalf("expected restore status %q, got %+v", fx.Expected.RestoreStatus, state)
	}
	if state.Active != fx.Expected.Active {
		t.Fatalf("expected active=%v, got %+v", fx.Expected.Active, state)
	}
	if state.Revision != fx.Expected.StateRevision || state.HighestRevision != fx.Expected.HighestRevision {
		t.Fatalf("expected restored revision %d highest %d, got %+v", fx.Expected.StateRevision, fx.Expected.HighestRevision, state)
	}
	if fx.Expected.PolicyDigest != "" && state.Active && state.Digest != fx.Expected.PolicyDigest {
		t.Fatalf("expected restored digest %s, got %s", fx.Expected.PolicyDigest, state.Digest)
	}

	if fx.Evaluation != nil {
		decision := restarted.Evaluate(ctx, *fx.Evaluation)
		if decision.Allow != fx.Expected.Allow {
			t.Fatalf("expected allow=%v, got %+v", fx.Expected.Allow, decision)
		}
		if code := c12DecisionErrorCode(decision); code != fx.Expected.DecisionErrorCode {
			t.Fatalf("expected decision error %q, got %q (%+v)", fx.Expected.DecisionErrorCode, code, decision)
		}
		if fx.Expected.PolicyDigest != "" && decision.Allow && decision.PolicyDigest != fx.Expected.PolicyDigest {
			t.Fatalf("decision used digest %s, expected %s", decision.PolicyDigest, fx.Expected.PolicyDigest)
		}
	}
}

// TestC12CLIActivateReplayAndRestore exercises the engine workflow across real process boundaries.
func TestC12CLIActivateReplayAndRestore(t *testing.T) {
	dir := t.TempDir()
	envelopePath, err := filepath.Abs(filepath.Join(c12FixtureDir, "cli-activation-envelope.json"))
	if err != nil {
		t.Fatalf("failed to resolve activation envelope: %v", err)
	}
	expiredPath, err := filepath.Abs(filepath.Join(c12FixtureDir, "cli-activation-expired.json"))
	if err != nil {
		t.Fatalf("failed to resolve expired envelope: %v", err)
	}

	run := func(args ...string) ([]byte, string, error) {
		cmd := exec.Command("go", append([]string{"run", "../cmd/policyhelix"}, args...)...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()
		return stdout.Bytes(), stderr.String(), err
	}

	stdout, stderr, err := run("--activate-bundle", envelopePath, "--storage-dir", dir)
	if err != nil {
		t.Fatalf("CLI activation failed: %v, stderr: %s", err, stderr)
	}
	var activated bundles.ActivationResult
	if err := json.Unmarshal(stdout, &activated); err != nil {
		t.Fatalf("failed to parse activation output: %v, raw: %s", err, stdout)
	}
	if activated.Status != bundles.ActivationStatusActivated || !activated.Durable || activated.Revision != 3 {
		t.Fatalf("expected durable revision 3 activation, got %+v", activated)
	}

	stdout, stderr, err = run("--activate-bundle", envelopePath, "--storage-dir", dir)
	if err != nil {
		t.Fatalf("CLI replay failed: %v, stderr: %s", err, stderr)
	}
	var replayed bundles.ActivationResult
	if err := json.Unmarshal(stdout, &replayed); err != nil {
		t.Fatalf("failed to parse replay output: %v, raw: %s", err, stdout)
	}
	if replayed.Status != bundles.ActivationStatusReplayed || !replayed.Replayed || replayed.StorageRevision != activated.StorageRevision {
		t.Fatalf("expected idempotent CLI replay, got %+v", replayed)
	}

	stdout, stderr, err = run("--activation-state", envelopePath, "--storage-dir", dir)
	if err != nil {
		t.Fatalf("CLI restore failed: %v, stderr: %s", err, stderr)
	}
	var state bundles.ActivationState
	if err := json.Unmarshal(stdout, &state); err != nil {
		t.Fatalf("failed to parse activation state output: %v, raw: %s", err, stdout)
	}
	if state.Status != bundles.ActivationStatusRestored || !state.Active || state.Revision != 3 {
		t.Fatalf("expected restored revision 3 state, got %+v", state)
	}

	stdout, stderr, err = run("--activate-bundle", expiredPath, "--storage-dir", dir)
	if err == nil {
		t.Fatalf("expected non-zero exit for expired activation, got: %s", stdout)
	}
	var expired bundles.ActivationResult
	if err := json.Unmarshal(stdout, &expired); err != nil {
		t.Fatalf("failed to parse expired activation output: %v, raw: %s stderr: %s", err, stdout, stderr)
	}
	if expired.Status != bundles.ActivationStatusRejected || expired.ErrorCode != bundles.ErrCodeExpiredBundle || expired.HighestRevision != 3 {
		t.Fatalf("expected expired rejection retaining revision 3, got %+v", expired)
	}

	if _, _, err := run("--activate-bundle", envelopePath); err == nil {
		t.Fatal("expected activation without --storage-dir to fail")
	}
}

func c12OversizedBundle(t *testing.T) policy.LocalPolicyBundle {
	t.Helper()
	padding := 60000
	for attempt := 0; attempt < 12; attempt++ {
		spec := standardBuildSpec()
		spec.BundleID = "bundle-oversized-v1"
		spec.RegoModule = "package policyhelix.authz\ndefault allow = false\n# " + strings.Repeat("x", padding) + "\nallow { input.subject.authenticated == true }"
		bundle, err := bundles.BuildDeterministicBundle(spec)
		if err != nil {
			t.Fatalf("failed to build oversized bundle: %v", err)
		}
		bundleBytes, err := json.Marshal(bundle)
		if err != nil {
			t.Fatalf("failed to marshal oversized bundle: %v", err)
		}
		recordBytes, err := json.Marshal(bundles.ActivationRecord{
			SchemaVersion:   bundles.ActivationSchemaVersion,
			OperationID:     "c12-oversized-1",
			Bundle:          bundle,
			BundleDigest:    bundle.Digest,
			HighestRevision: bundle.Revision,
			Actor:           "operator-1",
		})
		if err != nil {
			t.Fatalf("failed to marshal oversized activation record: %v", err)
		}
		if len(bundleBytes) > policy.MaxBundleBytes {
			padding -= len(bundleBytes) - policy.MaxBundleBytes + 32
			continue
		}
		if len(recordBytes) > storage.MaxPayloadBytes {
			return bundle
		}
		padding += storage.MaxPayloadBytes - len(recordBytes) + 64
	}
	t.Fatal("could not construct a bundle within the policy bound but over the activation record bound")
	return policy.LocalPolicyBundle{}
}
