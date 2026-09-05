package dpop

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrProofReplay is returned when a DPoP proof has already been accepted.
	ErrProofReplay = errors.New("dpop: proof replay")
	// ErrReplayStoreFull is returned when a replay store cannot safely record a
	// new proof without evicting a still-valid entry.
	ErrReplayStoreFull = errors.New("dpop: replay store capacity exhausted")
)

// ReplayStore atomically records a verified DPoP proof until its acceptance
// deadline. It must return [ErrProofReplay] when the same thumbprint and jti have
// already been recorded and [ErrReplayStoreFull] when it cannot record the
// proof without evicting a still-valid entry.
//
// Multi-replica resource servers must use a shared ReplayStore. The default
// in-memory store is process-local; load-balancer affinity does not provide
// cross-node replay protection.
type ReplayStore interface {
	CheckAndRecord(ctx context.Context, thumbprint, jti string, until time.Time) error
}

// DefaultReplayCacheMaxEntries bounds the zero-value Verifier's process-local
// replay cache.
const DefaultReplayCacheMaxEntries = 10_000

type inMemoryReplayStore struct {
	mu       sync.Mutex
	entries  map[[sha256.Size]byte]time.Time
	expiries replayExpiryHeap
	max      int
	now      func() time.Time
}

// NewInMemoryReplayStore constructs a bounded, concurrency-safe process-local
// replay store. maxEntries must be positive.
func NewInMemoryReplayStore(maxEntries int) (ReplayStore, error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("dpop: replay cache max entries must be positive")
	}
	return newInMemoryReplayStore(maxEntries), nil
}

func newInMemoryReplayStore(maxEntries int) *inMemoryReplayStore {
	return &inMemoryReplayStore{entries: make(map[[sha256.Size]byte]time.Time), max: maxEntries, now: time.Now}
}

func (s *inMemoryReplayStore) CheckAndRecord(ctx context.Context, thumbprint, jti string, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// A JWK thumbprint is base64url and cannot contain NUL, so this framing is
	// unambiguous. Keep only its fixed-size digest: jti is attacker controlled.
	key := sha256.Sum256([]byte(thumbprint + "\x00" + jti))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// A proof remains acceptable while now == deadline (claim validation uses
	// now.After(deadline)), so retain its replay entry through that instant.
	for len(s.expiries) > 0 && now.After(s.expiries[0].until) {
		entry := heap.Pop(&s.expiries).(replayExpiry)
		if expiry, ok := s.entries[entry.key]; ok && expiry.Equal(entry.until) {
			delete(s.entries, entry.key)
		}
	}
	if _, ok := s.entries[key]; ok {
		return ErrProofReplay
	}
	if len(s.entries) >= s.max {
		return ErrReplayStoreFull
	}
	s.entries[key] = until
	heap.Push(&s.expiries, replayExpiry{key: key, until: until})
	return nil
}

type replayExpiry struct {
	key   [sha256.Size]byte
	until time.Time
}

type replayExpiryHeap []replayExpiry

func (h replayExpiryHeap) Len() int           { return len(h) }
func (h replayExpiryHeap) Less(i, j int) bool { return h[i].until.Before(h[j].until) }
func (h replayExpiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *replayExpiryHeap) Push(x any)        { *h = append(*h, x.(replayExpiry)) }
func (h *replayExpiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}
