package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/parsa-emami/policyhelix/internal/auth"
	"github.com/parsa-emami/policyhelix/internal/bundles"
	"github.com/parsa-emami/policyhelix/internal/storage"
)

// GatewayFixtureEnv packages the initialized storage, key manager, session, and revocation stores for fixture evaluation.
type GatewayFixtureEnv struct {
	Adapter         *storage.Adapter
	KeyManager      *bundles.KeyRotationManager
	SessionStore    auth.SessionStore
	RevocationStore auth.RevocationStore
}

// Close releases the underlying storage resources.
func (e *GatewayFixtureEnv) Close() error {
	if e.Adapter != nil {
		return e.Adapter.Close()
	}
	return nil
}

// SetupGatewayFixtureEnv initializes storage, key rotation manager, preloaded bundle, sessions, and revocations.
func SetupGatewayFixtureEnv(
	ctx context.Context,
	storageDir string,
	trustedKeys []bundles.TrustedKey,
	preloadBundle *bundles.ActivationRequest,
	evalTimeStr string,
	evalTime time.Time,
	preloadSessions []auth.SessionRecord,
	preloadRevocations []auth.RevocationRecord,
) (*GatewayFixtureEnv, error) {
	ad, _, err := storage.Open(storageDir)
	if err != nil {
		return nil, fmt.Errorf("storage open failed: %w", err)
	}

	mgr := bundles.NewKeyRotationManagerFromAdapter(ad, bundles.NewKeyring(trustedKeys...))
	mgr.Now = func() time.Time { return evalTime }

	if preloadBundle != nil {
		preRes := mgr.ActivateBundle(ctx, *preloadBundle, evalTimeStr)
		if preRes.Status == bundles.ActivationStatusRejected {
			_ = ad.Close()
			return nil, fmt.Errorf("%s: preload bundle failed: %s", preRes.ErrorCode, preRes.Message)
		}
	}

	sessStore := auth.NewStorageSessionStore(ad)
	revStore := auth.NewStorageRevocationStore(ad)

	for _, s := range preloadSessions {
		_ = sessStore.SaveSession(ctx, s)
	}
	for _, r := range preloadRevocations {
		if r.SessionID != "" {
			_ = revStore.SaveSessionRevocation(ctx, r)
		}
		if r.SubjectID != "" && r.MinRequiredEpoch > 0 {
			_ = revStore.SaveSubjectRevocation(ctx, r)
		}
		if r.OwnerScope != "" {
			_ = revStore.SaveScopeRevocation(ctx, r)
		}
	}

	return &GatewayFixtureEnv{
		Adapter:         ad,
		KeyManager:      mgr,
		SessionStore:    sessStore,
		RevocationStore: revStore,
	}, nil
}
