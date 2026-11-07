package policy

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/policyhelix/internal/audit"
)

const (
	// DefaultCacheCapacity is the default maximum number of entries held in the LRU cache.
	DefaultCacheCapacity = 1000
	// DefaultCacheTTL is the default time-to-live for cached policy decisions.
	DefaultCacheTTL = 15 * time.Second
	// MaxCacheTTL is the strict upper bound on cache TTL (bounded <=30s per Requirement F09).
	MaxCacheTTL = 30 * time.Second
	// MinCacheTTL is the minimum allowed cache TTL.
	MinCacheTTL = 1 * time.Second

	// Cache-specific error codes
	ErrCodeInvalidCacheConfig      = "INVALID_CACHE_CONFIG"
	ErrCodeCacheKeyComputation     = "CACHE_KEY_COMPUTATION_ERROR"
	ErrCodeCacheRevokedSession     = "CACHE_REVOKED_SESSION"
	ErrCodeCacheProviderUnavailable = "PROVIDER_UNAVAILABLE"
	ErrCodeCacheMalformedRequest   = "MALFORMED_REQUEST"
	ErrCodeCachePrivateFailClosed  = "PRIVATE_RESOURCE_FAIL_CLOSED"
	ErrCodeTokenLeakDetected       = "TOKEN_LEAK_DETECTED"
)

// RevocationChecker defines an interface to query live session, subject, and scope revocation status.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, sessionID, subjectID, ownerScope string, sessionEpoch int64, evalTime time.Time) bool
}

// CacheKeyComponents defines the four binding dimensions:
// 1. Subject: SubjectID, Issuer, Roles (sorted), Authenticated, SessionEpoch, SessionID
// 2. Action: normalized lowercase action
// 3. Context: Path, ResourceID, OwnerScope
// 4. Revision: bundle Revision, PolicyDigest
type CacheKeyComponents struct {
	// Subject dimension
	SubjectID     string   `json:"subject_id"`
	Issuer        string   `json:"issuer"`
	Roles         []string `json:"roles"`
	Authenticated bool     `json:"authenticated"`
	SessionEpoch  int64    `json:"session_epoch"`
	SessionID     string   `json:"session_id,omitempty"`

	// Action dimension
	Action string `json:"action"`

	// Context dimension
	Path       string `json:"path"`
	ResourceID string `json:"resource_id,omitempty"`
	OwnerScope string `json:"owner_scope,omitempty"`

	// Revision dimension
	Revision     int64  `json:"revision"`
	PolicyDigest string `json:"policy_digest"`
}

type canonicalCacheKeyComponents struct {
	SubjectID     string   `json:"subject_id"`
	Issuer        string   `json:"issuer"`
	Roles         []string `json:"roles"`
	Authenticated bool     `json:"authenticated"`
	SessionEpoch  int64    `json:"session_epoch"`
	SessionID     string   `json:"session_id"`
	Action        string   `json:"action"`
	Path          string   `json:"path"`
	ResourceID    string   `json:"resource_id"`
	OwnerScope    string   `json:"owner_scope"`
	Revision      int64    `json:"revision"`
	PolicyDigest  string   `json:"policy_digest"`
}

// canonicalizeComponents trims strings, normalizes lowercase action, and deduplicates/sorts roles.
func canonicalizeComponents(comp CacheKeyComponents) CacheKeyComponents {
	var sortedRoles []string
	if len(comp.Roles) > 0 {
		seen := make(map[string]struct{}, len(comp.Roles))
		for _, r := range comp.Roles {
			trimmed := strings.TrimSpace(r)
			if trimmed != "" {
				if _, ok := seen[trimmed]; !ok {
					seen[trimmed] = struct{}{}
					sortedRoles = append(sortedRoles, trimmed)
				}
			}
		}
		sort.Strings(sortedRoles)
	}
	if sortedRoles == nil {
		sortedRoles = []string{}
	}

	return CacheKeyComponents{
		SubjectID:     strings.TrimSpace(comp.SubjectID),
		Issuer:        strings.TrimSpace(comp.Issuer),
		Roles:         sortedRoles,
		Authenticated: comp.Authenticated,
		SessionEpoch:  comp.SessionEpoch,
		SessionID:     strings.TrimSpace(comp.SessionID),
		Action:        strings.ToLower(strings.TrimSpace(comp.Action)),
		Path:          strings.TrimSpace(comp.Path),
		ResourceID:    strings.TrimSpace(comp.ResourceID),
		OwnerScope:    strings.TrimSpace(comp.OwnerScope),
		Revision:      comp.Revision,
		PolicyDigest:  strings.TrimSpace(comp.PolicyDigest),
	}
}

// ComputeCacheKey deterministically hashes the canonical components using SHA-256
// and returns a key formatted as `pk:<64-hex>`.
// Zero-token invariant: never includes bearer tokens, raw JWTs, or secret cookies.
func ComputeCacheKey(comp CacheKeyComponents) string {
	comp = canonicalizeComponents(comp)

	canonical := canonicalCacheKeyComponents{
		SubjectID:     comp.SubjectID,
		Issuer:        comp.Issuer,
		Roles:         comp.Roles,
		Authenticated: comp.Authenticated,
		SessionEpoch:  comp.SessionEpoch,
		SessionID:     comp.SessionID,
		Action:        comp.Action,
		Path:          comp.Path,
		ResourceID:    comp.ResourceID,
		OwnerScope:    comp.OwnerScope,
		Revision:      comp.Revision,
		PolicyDigest:  comp.PolicyDigest,
	}

	raw, err := json.Marshal(canonical)
	if err != nil {
		// Fallback deterministic string representation if marshal fails
		raw = []byte(fmt.Sprintf("%s|%s|%v|%t|%d|%s|%s|%s|%s|%s|%d|%s",
			canonical.SubjectID, canonical.Issuer, canonical.Roles, canonical.Authenticated,
			canonical.SessionEpoch, canonical.SessionID, canonical.Action, canonical.Path,
			canonical.ResourceID, canonical.OwnerScope, canonical.Revision, canonical.PolicyDigest))
	}

	sum := sha256.Sum256(raw)
	return "pk:" + hex.EncodeToString(sum[:])
}

// CacheEntry stores a cached authorization decision with bounding metadata.
type CacheEntry struct {
	Key          string             `json:"key"`
	Decision     BundleDecision     `json:"decision"`
	Components   CacheKeyComponents `json:"components"`
	CreatedAt    time.Time          `json:"created_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
	SessionID    string             `json:"session_id,omitempty"`
	SubjectID    string             `json:"subject_id,omitempty"`
	OwnerScope   string             `json:"owner_scope,omitempty"`
	SessionEpoch int64              `json:"session_epoch,omitempty"`
	Revision     int64              `json:"revision"`
	PolicyDigest string             `json:"policy_digest"`
}

// CacheStats provides telemetry and operational metrics for the decision cache.
type CacheStats struct {
	Hits           int64   `json:"hits"`
	Misses         int64   `json:"misses"`
	Evictions      int64   `json:"evictions"`
	Invalidations  int64   `json:"invalidations"`
	RevocationDrop int64   `json:"revocation_drop"`
	Count          int     `json:"count"`
	Capacity       int     `json:"capacity"`
	HitRate        float64 `json:"hit_rate"`
	TTLSeconds     float64 `json:"ttl_seconds"`
}

// CacheConfig configures the DecisionCache parameters.
type CacheConfig struct {
	Capacity          int               `json:"capacity,omitempty"`
	TTL               time.Duration     `json:"ttl,omitempty"`
	RevocationChecker RevocationChecker `json:"-"`
	Clock             func() time.Time  `json:"-"`
}

type lruElement struct {
	key   string
	entry CacheEntry
}

// DecisionCache implements a bounded, thread-safe, LRU decision cache
// with strict TTL enforcement (<=30s bound) and multi-dimensional invalidations.
type DecisionCache struct {
	mu         sync.RWMutex
	capacity   int
	ttl        time.Duration
	items      map[string]*list.Element
	lruList    *list.List
	revChecker RevocationChecker
	nowFn      func() time.Time

	// Metrics
	hits           int64
	misses         int64
	evictions      int64
	invalidations  int64
	revocationDrop int64
}

// NewDecisionCache constructs an initialized DecisionCache with bounded capacity and TTL.
func NewDecisionCache(cfg CacheConfig) (*DecisionCache, error) {
	capacity := cfg.Capacity
	if capacity <= 0 {
		capacity = DefaultCacheCapacity
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	if ttl > MaxCacheTTL {
		return nil, fmt.Errorf("%s: configured TTL %v exceeds maximum bound of %v (F09/F18)",
			ErrCodeInvalidCacheConfig, ttl, MaxCacheTTL)
	}
	if ttl < MinCacheTTL {
		ttl = MinCacheTTL
	}

	nowFn := cfg.Clock
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}

	return &DecisionCache{
		capacity:   capacity,
		ttl:        ttl,
		items:      make(map[string]*list.Element, capacity),
		lruList:    list.New(),
		revChecker: cfg.RevocationChecker,
		nowFn:      nowFn,
	}, nil
}

func (c *DecisionCache) initIfNil() {
	if c.capacity <= 0 {
		c.capacity = DefaultCacheCapacity
	}
	if c.ttl <= 0 {
		c.ttl = DefaultCacheTTL
	}
	if c.items == nil {
		c.items = make(map[string]*list.Element, c.capacity)
	}
	if c.lruList == nil {
		c.lruList = list.New()
	}
	if c.nowFn == nil {
		c.nowFn = func() time.Time { return time.Now().UTC() }
	}
}

// SetRevocationChecker sets or updates the revocation checker dynamically.
func (c *DecisionCache) SetRevocationChecker(rc RevocationChecker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revChecker = rc
}

// Get attempts to retrieve a valid, unexpired, non-revoked decision from the cache.
// Concurrency safe: releases mutex during external revocation checks to avoid engine lockup.
func (c *DecisionCache) Get(ctx context.Context, key string, evalTime time.Time) (BundleDecision, bool) {
	cleanKey := strings.TrimSpace(key)
	if cleanKey == "" {
		return BundleDecision{}, false
	}

	c.mu.Lock()
	c.initIfNil()

	elem, found := c.items[cleanKey]
	if !found {
		c.misses++
		c.mu.Unlock()
		return BundleDecision{}, false
	}

	item := elem.Value.(*lruElement)
	entry := item.entry

	if evalTime.IsZero() {
		evalTime = c.nowFn()
	}

	// 1. Strict TTL check
	if !evalTime.Before(entry.ExpiresAt) {
		c.removeElement(elem)
		c.misses++
		c.mu.Unlock()
		return BundleDecision{}, false
	}

	checker := c.revChecker
	if checker == nil {
		c.lruList.MoveToFront(elem)
		c.hits++
		c.mu.Unlock()
		return entry.Decision, true
	}

	// 2. Revocation check: release mutex during invocation to prevent deadlocks and lock contention
	c.mu.Unlock()

	revoked := checker.IsRevoked(ctx, entry.SessionID, entry.SubjectID, entry.OwnerScope, entry.SessionEpoch, evalTime)

	c.mu.Lock()
	defer c.mu.Unlock()

	curElem, stillFound := c.items[cleanKey]
	if revoked {
		if stillFound && curElem.Value.(*lruElement).entry.CreatedAt.Equal(entry.CreatedAt) {
			c.removeElement(curElem)
		}
		c.revocationDrop++
		c.misses++
		return BundleDecision{}, false
	}

	if !stillFound || !curElem.Value.(*lruElement).entry.CreatedAt.Equal(entry.CreatedAt) {
		// Overwritten or evicted while unlocked
		c.misses++
		return BundleDecision{}, false
	}

	// Re-verify TTL
	if !evalTime.Before(curElem.Value.(*lruElement).entry.ExpiresAt) {
		c.removeElement(curElem)
		c.misses++
		return BundleDecision{}, false
	}

	// Hit: move to front of LRU
	c.lruList.MoveToFront(curElem)
	c.hits++
	return curElem.Value.(*lruElement).entry.Decision, true
}

// Put places a decision into the cache with strict bounding and LRU eviction.
func (c *DecisionCache) Put(key string, decision BundleDecision, comp CacheKeyComponents, evalTime time.Time) error {
	cleanKey := strings.TrimSpace(key)
	if cleanKey == "" {
		return errors.New("cache key cannot be empty")
	}

	comp = canonicalizeComponents(comp)

	// Zero-token invariant validation
	if err := verifyComponentsNoToken(comp); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.initIfNil()

	if evalTime.IsZero() {
		evalTime = c.nowFn()
	}

	expiresAt := evalTime.Add(c.ttl)

	// If entry already exists, update and move to front
	if elem, found := c.items[cleanKey]; found {
		c.lruList.MoveToFront(elem)
		elem.Value = &lruElement{
			key: cleanKey,
			entry: CacheEntry{
				Key:          cleanKey,
				Decision:     decision,
				Components:   comp,
				CreatedAt:    evalTime,
				ExpiresAt:    expiresAt,
				SessionID:    comp.SessionID,
				SubjectID:    comp.SubjectID,
				OwnerScope:   comp.OwnerScope,
				SessionEpoch: comp.SessionEpoch,
				Revision:     comp.Revision,
				PolicyDigest: comp.PolicyDigest,
			},
		}
		return nil
	}

	// Check capacity and evict oldest if needed
	for c.lruList.Len() >= c.capacity {
		c.evictOldest()
	}

	entry := CacheEntry{
		Key:          cleanKey,
		Decision:     decision,
		Components:   comp,
		CreatedAt:    evalTime,
		ExpiresAt:    expiresAt,
		SessionID:    comp.SessionID,
		SubjectID:    comp.SubjectID,
		OwnerScope:   comp.OwnerScope,
		SessionEpoch: comp.SessionEpoch,
		Revision:     comp.Revision,
		PolicyDigest: comp.PolicyDigest,
	}

	elem := c.lruList.PushFront(&lruElement{
		key:   cleanKey,
		entry: entry,
	})
	c.items[cleanKey] = elem
	return nil
}

func (c *DecisionCache) removeElement(elem *list.Element) {
	c.lruList.Remove(elem)
	item := elem.Value.(*lruElement)
	delete(c.items, item.key)
}

func (c *DecisionCache) evictOldest() {
	elem := c.lruList.Back()
	if elem != nil {
		c.removeElement(elem)
		c.evictions++
	}
}

// InvalidateSession invalidates all cached decisions associated with a session ID.
func (c *DecisionCache) InvalidateSession(sessionID string) int {
	cleanID := strings.TrimSpace(sessionID)
	if cleanID == "" {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.initIfNil()

	var toRemove []*list.Element
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		item := elem.Value.(*lruElement)
		if item.entry.SessionID == cleanID {
			toRemove = append(toRemove, elem)
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
		c.invalidations++
	}
	return len(toRemove)
}

// InvalidateSubject invalidates all decisions for a subject whose SessionEpoch < minEpoch.
// If minEpoch <= 0, invalidates ALL cached decisions for that subject.
func (c *DecisionCache) InvalidateSubject(subjectID string, minEpoch int64) int {
	cleanID := strings.TrimSpace(subjectID)
	if cleanID == "" {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.initIfNil()

	var toRemove []*list.Element
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		item := elem.Value.(*lruElement)
		if item.entry.SubjectID == cleanID {
			if minEpoch <= 0 || item.entry.SessionEpoch < minEpoch {
				toRemove = append(toRemove, elem)
			}
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
		c.invalidations++
	}
	return len(toRemove)
}

// InvalidateScope invalidates all decisions for an owner scope whose SessionEpoch < minEpoch.
// If minEpoch <= 0, invalidates ALL cached decisions for that owner scope.
func (c *DecisionCache) InvalidateScope(ownerScope string, minEpoch int64) int {
	cleanScope := strings.TrimSpace(ownerScope)
	if cleanScope == "" {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.initIfNil()

	var toRemove []*list.Element
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		item := elem.Value.(*lruElement)
		if item.entry.OwnerScope == cleanScope {
			if minEpoch <= 0 || item.entry.SessionEpoch < minEpoch {
				toRemove = append(toRemove, elem)
			}
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
		c.invalidations++
	}
	return len(toRemove)
}

// InvalidateRevision invalidates all decisions associated with a specific revision or policy digest.
func (c *DecisionCache) InvalidateRevision(revision int64, digest string) int {
	cleanDigest := strings.TrimSpace(digest)
	if revision <= 0 && cleanDigest == "" {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.initIfNil()

	var toRemove []*list.Element
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		item := elem.Value.(*lruElement)
		match := false
		if revision > 0 && item.entry.Revision == revision {
			match = true
		}
		if cleanDigest != "" && item.entry.PolicyDigest == cleanDigest {
			match = true
		}
		if match {
			toRemove = append(toRemove, elem)
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
		c.invalidations++
	}
	return len(toRemove)
}

// InvalidateOlderThanRevision invalidates all decisions with revision < targetRevision.
func (c *DecisionCache) InvalidateOlderThanRevision(targetRevision int64) int {
	if targetRevision <= 0 {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.initIfNil()

	var toRemove []*list.Element
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		item := elem.Value.(*lruElement)
		if item.entry.Revision < targetRevision {
			toRemove = append(toRemove, elem)
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
		c.invalidations++
	}
	return len(toRemove)
}

// EvictExpired removes all expired items from the cache as of evalTime.
func (c *DecisionCache) EvictExpired(evalTime time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initIfNil()

	if evalTime.IsZero() {
		evalTime = c.nowFn()
	}

	var toRemove []*list.Element
	for elem := c.lruList.Front(); elem != nil; elem = elem.Next() {
		item := elem.Value.(*lruElement)
		if !evalTime.Before(item.entry.ExpiresAt) {
			toRemove = append(toRemove, elem)
		}
	}

	for _, elem := range toRemove {
		c.removeElement(elem)
		c.evictions++
	}
	return len(toRemove)
}

// Clear flushes all entries from the cache.
func (c *DecisionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.capacity = DefaultCacheCapacity
	if c.capacity <= 0 {
		c.capacity = DefaultCacheCapacity
	}
	c.items = make(map[string]*list.Element, c.capacity)
	c.lruList = list.New()
}

// Stats returns a snapshot of cache metrics.
func (c *DecisionCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}

	count := 0
	if c.lruList != nil {
		count = c.lruList.Len()
	}
	cap := c.capacity
	if cap <= 0 {
		cap = DefaultCacheCapacity
	}

	return CacheStats{
		Hits:           c.hits,
		Misses:         c.misses,
		Evictions:      c.evictions,
		Invalidations:  c.invalidations,
		RevocationDrop: c.revocationDrop,
		Count:          count,
		Capacity:       cap,
		HitRate:        hitRate,
		TTLSeconds:     c.ttl.Seconds(),
	}
}

// EvaluateCacheRequest defines the request payload for evaluating with decision cache.
type EvaluateCacheRequest struct {
	RequestID                string                 `json:"request_id,omitempty"`
	Path                     string                 `json:"path"`
	Action                   string                 `json:"action"`
	Subject                  SubjectIdentity        `json:"subject"`
	ResourceID               string                 `json:"resource_id,omitempty"`
	OwnerScope               string                 `json:"owner_scope,omitempty"`
	SessionID                string                 `json:"session_id,omitempty"`
	DeadlineMS               int                    `json:"deadline_ms,omitempty"`
	EvalTime                 string                 `json:"eval_time,omitempty"`
	ResourceClassification   ResourceClass          `json:"resource_classification,omitempty"`
	ProviderUnavailable      bool                   `json:"provider_unavailable,omitempty"`
	Bundle                   *LocalPolicyBundle     `json:"bundle,omitempty"`
	Headers                  map[string]string      `json:"headers,omitempty"`
	Context                  map[string]interface{} `json:"context,omitempty"`
}

// EvaluateCacheResponse defines the response payload returned by EvaluateRequest.
type EvaluateCacheResponse struct {
	Decision   BundleDecision `json:"decision"`
	Cached     bool           `json:"cached"`
	CacheKey   string         `json:"cache_key"`
	StatusCode int            `json:"status_code"`
	Stats      CacheStats     `json:"stats"`
}

// EvaluateWithCache evaluates an authorization decision against the evaluator using BundleEvalInput,
// using the DecisionCache to return cached decisions if available and valid.
// Checks revocation and TTL, and caches successful outcomes within deadline.
// Invariant: Unauthenticated requests to private resources strictly fail closed.
func (c *DecisionCache) EvaluateWithCache(ctx context.Context, evaluator *BundleEvaluator, input BundleEvalInput) (BundleDecision, bool) {
	evalTime := c.nowFn()
	if strings.TrimSpace(input.EvalTime) != "" {
		if pt, err := time.Parse(time.RFC3339, input.EvalTime); err == nil {
			evalTime = pt.UTC()
		}
	}

	// 1. Resolve active bundle or inline bundle to extract revision and digest
	var bundle LocalPolicyBundle
	if input.Bundle != nil {
		bundle = *input.Bundle
	} else if evaluator != nil {
		if ab, ok := evaluator.ActiveBundle(); ok {
			bundle = ab
		}
	}

	// 2. Compute deterministic cache key binding all 4 dimensions
	comp := CacheKeyComponents{
		SubjectID:     input.Subject.ID,
		Issuer:        input.Subject.Issuer,
		Roles:         input.Subject.Roles,
		Authenticated: input.Subject.Authenticated,
		SessionEpoch:  input.Subject.SessionEpoch,
		SessionID:     "",
		Action:        input.Action,
		Path:          input.Path,
		ResourceID:    input.ResourceID,
		OwnerScope:    "",
		Revision:      bundle.Revision,
		PolicyDigest:  bundle.Digest,
	}

	cacheKey := ComputeCacheKey(comp)

	// 3. Check cache for hit
	if cachedDecision, hit := c.Get(ctx, cacheKey, evalTime); hit {
		return cachedDecision, true
	}

	// 4. Cache miss: evaluate via BundleEvaluator or fallback rule resolution
	var dec BundleDecision
	if evaluator != nil {
		dec = evaluator.Evaluate(ctx, input)
	} else if input.Bundle != nil {
		tempEval := NewBundleEvaluator([]string{input.Bundle.Issuer}, []string{input.Bundle.SignerKeyID})
		dec = tempEval.Evaluate(ctx, input)
	} else {
		dec = BundleDecision{
			Allow:          false,
			Classification: ResourceClassPrivate,
			Reasons:        []string{ErrCodeNoActiveBundle},
			Error: &BundleError{
				Code:      ErrCodeNoActiveBundle,
				Message:   "No active policy bundle loaded; failing closed",
				Retryable: false,
			},
			WithinDeadline: true,
		}
	}

	// 5. Fail-closed private resource invariant:
	if !input.Subject.Authenticated && dec.Classification == ResourceClassPrivate {
		dec.Allow = false
		if dec.Error == nil {
			dec.Error = &BundleError{
				Code:      ErrCodePrivateFailClosed,
				Message:   "Unauthenticated access to private resource fails closed",
				Retryable: false,
			}
		}
	}

	// 6. Cache successful evaluation within deadline (do not cache server errors or timeouts)
	if dec.WithinDeadline && (dec.Error == nil || dec.Error.Code == ErrCodePrivateFailClosed) {
		_ = c.Put(cacheKey, dec, comp, evalTime)
	}

	return dec, false
}

// EvaluateRequest evaluates an authorization decision using the EvaluateCacheRequest envelope.
func (c *DecisionCache) EvaluateRequest(ctx context.Context, evaluator *BundleEvaluator, input EvaluateCacheRequest) (EvaluateCacheResponse, error) {
	// 1. Validate required fields
	if strings.TrimSpace(input.Path) == "" || strings.TrimSpace(input.Action) == "" {
		return EvaluateCacheResponse{
			Decision: BundleDecision{
				Allow:          false,
				Classification: ResourceClassPrivate,
				Reasons:        []string{ErrCodeCacheMalformedRequest},
				Error: &BundleError{
					Code:      ErrCodeCacheMalformedRequest,
					Message:   "Path and action are required",
					Retryable: false,
				},
			},
			Cached:     false,
			StatusCode: 400,
			Stats:      c.Stats(),
		}, errors.New("path and action are required")
	}

	if input.ProviderUnavailable {
		return EvaluateCacheResponse{
			Decision: BundleDecision{
				Allow:          false,
				Classification: ResourceClassPrivate,
				Reasons:        []string{ErrCodeCacheProviderUnavailable},
				Error: &BundleError{
					Code:      ErrCodeCacheProviderUnavailable,
					Message:   "Policy decision provider is unavailable",
					Retryable: true,
				},
			},
			Cached:     false,
			StatusCode: 503,
			Stats:      c.Stats(),
		}, nil
	}

	evalTime := c.nowFn()
	if strings.TrimSpace(input.EvalTime) != "" {
		if pt, err := time.Parse(time.RFC3339, input.EvalTime); err == nil {
			evalTime = pt.UTC()
		}
	}

	// 2. Resolve active bundle or inline bundle to extract revision and digest
	var bundle LocalPolicyBundle
	if input.Bundle != nil {
		bundle = *input.Bundle
	} else if evaluator != nil {
		if ab, ok := evaluator.ActiveBundle(); ok {
			bundle = ab
		}
	}

	// 3. Compute deterministic cache key binding all 4 dimensions
	comp := CacheKeyComponents{
		SubjectID:     input.Subject.ID,
		Issuer:        input.Subject.Issuer,
		Roles:         input.Subject.Roles,
		Authenticated: input.Subject.Authenticated,
		SessionEpoch:  input.Subject.SessionEpoch,
		SessionID:     input.SessionID,
		Action:        input.Action,
		Path:          input.Path,
		ResourceID:    input.ResourceID,
		OwnerScope:    input.OwnerScope,
		Revision:      bundle.Revision,
		PolicyDigest:  bundle.Digest,
	}

	cacheKey := ComputeCacheKey(comp)

	// 4. Check cache for hit
	if cachedDecision, hit := c.Get(ctx, cacheKey, evalTime); hit {
		statusCode := 200
		if !cachedDecision.Allow {
			statusCode = 403
		}
		return EvaluateCacheResponse{
			Decision:   cachedDecision,
			Cached:     true,
			CacheKey:   cacheKey,
			StatusCode: statusCode,
			Stats:      c.Stats(),
		}, nil
	}

	// 5. Cache miss: evaluate via BundleEvaluator or fallback rule resolution
	var dec BundleDecision
	if evaluator != nil {
		evalInput := BundleEvalInput{
			RequestID:  input.RequestID,
			Path:       input.Path,
			Action:     input.Action,
			Subject:    input.Subject,
			ResourceID: input.ResourceID,
			DeadlineMS: input.DeadlineMS,
			EvalTime:   evalTime.Format(time.RFC3339),
			Bundle:     input.Bundle,
		}
		dec = evaluator.Evaluate(ctx, evalInput)
	} else if input.Bundle != nil {
		tempEval := NewBundleEvaluator([]string{input.Bundle.Issuer}, []string{input.Bundle.SignerKeyID})
		evalInput := BundleEvalInput{
			RequestID:  input.RequestID,
			Path:       input.Path,
			Action:     input.Action,
			Subject:    input.Subject,
			ResourceID: input.ResourceID,
			DeadlineMS: input.DeadlineMS,
			EvalTime:   evalTime.Format(time.RFC3339),
			Bundle:     input.Bundle,
		}
		dec = tempEval.Evaluate(ctx, evalInput)
	} else {
		// No evaluator and no bundle: fail closed
		dec = BundleDecision{
			Allow:          false,
			Classification: ResourceClassPrivate,
			Reasons:        []string{ErrCodeNoActiveBundle},
			Error: &BundleError{
				Code:      ErrCodeNoActiveBundle,
				Message:   "No active policy bundle loaded; failing closed",
				Retryable: false,
			},
			WithinDeadline: true,
		}
	}

	// Enforce fail-closed private resource invariant:
	if !input.Subject.Authenticated && (input.ResourceClassification == ResourceClassPrivate || dec.Classification == ResourceClassPrivate) {
		dec.Allow = false
		if dec.Error == nil {
			dec.Error = &BundleError{
				Code:      ErrCodePrivateFailClosed,
				Message:   "Unauthenticated access to private resource fails closed",
				Retryable: false,
			}
		}
	}

	// 6. Cache successful evaluation within deadline (do not cache server errors or timeouts)
	if dec.WithinDeadline && (dec.Error == nil || dec.Error.Code == ErrCodePrivateFailClosed) {
		_ = c.Put(cacheKey, dec, comp, evalTime)
	}

	statusCode := 200
	if !dec.Allow {
		statusCode = 403
	}
	if dec.Error != nil && dec.Error.Code == ErrCodeNoActiveBundle {
		statusCode = 500
	}

	return EvaluateCacheResponse{
		Decision:   dec,
		Cached:     false,
		CacheKey:   cacheKey,
		StatusCode: statusCode,
		Stats:      c.Stats(),
	}, nil
}

// EvaluateWithCacheRequest is an alias for EvaluateRequest for caller backwards compatibility.
func (c *DecisionCache) EvaluateWithCacheRequest(ctx context.Context, evaluator *BundleEvaluator, input EvaluateCacheRequest) (EvaluateCacheResponse, error) {
	return c.EvaluateRequest(ctx, evaluator, input)
}

// verifyComponentsNoToken verifies that zero secrets or bearer tokens are present in CacheKeyComponents.
func verifyComponentsNoToken(comp CacheKeyComponents) error {
	raw, err := json.Marshal(comp)
	if err != nil {
		return err
	}
	s := string(raw)

	// Check Bearer token pattern
	if strings.Contains(strings.ToLower(s), "bearer ") {
		return fmt.Errorf("%s: bearer token detected in cache key components", ErrCodeTokenLeakDetected)
	}
	// Check standard JWT pattern
	if audit.RedactText(s, nil) != s {
		return fmt.Errorf("%s: credential or token detected in cache key components", ErrCodeTokenLeakDetected)
	}
	return nil
}
