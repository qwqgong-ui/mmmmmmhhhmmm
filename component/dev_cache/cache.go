// Package dev_cache owns the lifetime of DNS answers, proxy DNS bundles and
// TCP connection hints. Refresh deadlines allow stale fallback for up to 30 days
// since the last content update; reads and failed refreshes do not renew it.
package dev_cache

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/arc"
	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/diagstats"
	"github.com/metacubex/mihomo/log"
)

const (
	RetryDelay      = 3 * time.Second
	RetentionPeriod = 30 * 24 * time.Hour
)

var ErrInvalidated = errors.New("cache refresh invalidated")

type backend[K comparable, V any] interface {
	GetWithExpire(K) (V, time.Time, bool)
	SetWithExpire(K, V, time.Time)
	Delete(K)
	Clear()
}

type Item[K comparable, V any] struct {
	Key       K
	Value     V
	Expires   time.Time // compatibility name: this is a refresh deadline, not a deletion time
	UpdatedAt time.Time
}

// Keep the update clock inline rather than allocating a second map per cache.
type storedValue[V any] struct {
	value     V
	updatedAt int64
}

type Result[V any] struct {
	Value V
	Err   error
}
type flight[V any] struct {
	done   chan struct{}
	result Result[V]
	cancel context.CancelFunc
}

type Cache[K comparable, V any] struct {
	mu      sync.Mutex
	data    backend[K, storedValue[V]]
	flights map[K]*flight[V]
	retry   map[K]time.Time
	kind    string
	nowFn   func() time.Time
}

type RefreshStatus struct {
	Refreshing bool      `json:"refreshing"`
	RetryAfter time.Time `json:"retryAfter,omitempty"`
}

// Status does not touch replacement order or start any work.
func (c *Cache[K, V]) Status(key K) RefreshStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return RefreshStatus{Refreshing: c.flights[key] != nil, RetryAfter: c.retry[key]}
}

func New[K comparable, V any](size int, algorithm string) *Cache[K, V] {
	c := &Cache[K, V]{flights: make(map[K]*flight[V]), retry: make(map[K]time.Time)}
	if algorithm == "arc" {
		c.data = arc.New(arc.WithSize[K, storedValue[V]](size))
	} else {
		c.data = lru.New(lru.WithSize[K, storedValue[V]](size), lru.WithStale[K, storedValue[V]](true))
	}
	return c
}

func (c *Cache[K, V]) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

func (c *Cache[K, V]) get(key K) (storedValue[V], time.Time, bool) {
	v, due, ok := c.data.GetWithExpire(key)
	if ok && v.updatedAt <= c.now().Add(-RetentionPeriod).UnixNano() {
		c.expire(key)
		return storedValue[V]{}, time.Time{}, false
	}
	return v, due, ok
}

// Retention removes the old value, while an already running refresh may still
// produce a genuinely new value. Configuration/scope invalidation uses delete.
func (c *Cache[K, V]) expire(key K) {
	c.data.Delete(key)
	delete(c.retry, key)
}

func (c *Cache[K, V]) GetWithExpire(key K) (V, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, due, ok := c.get(key)
	return v.value, due, ok
}
func (c *Cache[K, V]) Get(key K) (V, bool) { v, _, ok := c.GetWithExpire(key); return v, ok }

// GetWithExpireValidated discards only a rejected value that is still present.
// A miss must leave an in-flight refresh intact; an unconditional Delete would
// cancel coalesced work started by another reader of the same missing key.
func (c *Cache[K, V]) GetWithExpireValidated(key K, accept func(V) bool) (V, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, due, hit := c.get(key)
	if hit && !accept(value.value) {
		// The retained value is invalid; an active refresh can still replace it
		// with a valid answer. Keep that flight available to its waiters.
		c.data.Delete(key)
		delete(c.retry, key)
		var zero V
		return zero, time.Time{}, false
	}
	return value.value, due, hit
}

func (c *Cache[K, V]) SetWithExpire(key K, value V, due time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.SetWithExpire(key, storedValue[V]{value, c.now().UnixNano()}, due)
	delete(c.retry, key)
}
func (c *Cache[K, V]) Compute(key K, f func(V, bool) (V, bool)) (V, bool) {
	return c.ComputeWithExpire(key, func(v V, due time.Time, ok bool) (V, time.Time, bool) { v, remove := f(v, ok); return v, due, remove })
}

func (c *Cache[K, V]) ComputeWithExpire(key K, f func(V, time.Time, bool) (V, time.Time, bool)) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stored, due, ok := c.get(key)
	v, due, remove := f(stored.value, due, ok)
	if remove {
		c.delete(key)
		return v, false
	}
	c.data.SetWithExpire(key, storedValue[V]{v, c.now().UnixNano()}, due)
	return v, true
}

// Restoration must not make an old answer look newly updated, or overwrite a
// value that startup traffic has already refreshed.
func (c *Cache[K, V]) restore(key K, value V, due, updatedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !updatedAt.After(c.now().Add(-RetentionPeriod)) {
		return
	}
	if _, _, hit := c.get(key); hit {
		return
	}
	c.data.SetWithExpire(key, storedValue[V]{value, updatedAt.UnixNano()}, due)
}

// invalidateFlight must hold mu. Publish the invalidation before waking every
// waiter; an old worker may ignore cancellation, but cannot publish again.
func (c *Cache[K, V]) invalidateFlight(key K) {
	if f := c.flights[key]; f != nil {
		delete(c.flights, key)
		f.result = Result[V]{Err: ErrInvalidated}
		f.cancel()
		close(f.done)
	}
}
func (c *Cache[K, V]) delete(key K) {
	c.data.Delete(key)
	delete(c.retry, key)
	c.invalidateFlight(key)
}
func (c *Cache[K, V]) Delete(key K) { c.mu.Lock(); defer c.mu.Unlock(); c.delete(key) }
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.Clear()
	clear(c.retry)
	for key := range c.flights {
		c.invalidateFlight(key)
	}
}
func (c *Cache[K, V]) snapshot() (out []Item[K, V]) {
	cutoff := c.now().Add(-RetentionPeriod).UnixNano()
	add := func(key K, value storedValue[V], due time.Time) {
		if value.updatedAt <= cutoff {
			c.expire(key)
			return
		}
		out = append(out, Item[K, V]{key, value.value, due, time.Unix(0, value.updatedAt)})
	}
	switch data := c.data.(type) {
	case *lru.LruCache[K, storedValue[V]]:
		for _, i := range data.Snapshot() {
			add(i.Key, i.Value, i.Expires)
		}
	case *arc.ARC[K, storedValue[V]]:
		for _, i := range data.Snapshot() {
			add(i.Key, i.Value, i.Expires)
		}
	}
	return
}
func (c *Cache[K, V]) Snapshot() []Item[K, V] { c.mu.Lock(); defer c.mu.Unlock(); return c.snapshot() }
func (c *Cache[K, V]) DeleteMatching(match func(K) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, i := range c.snapshot() {
		if match(i.Key) {
			c.delete(i.Key)
			n++
		}
	}
	// A retired scope must not be resurrected by an outstanding cold lookup.
	for k := range c.flights {
		if match(k) {
			c.invalidateFlight(k)
		}
	}
	return n
}

// MarkStale keeps values while scheduling their next access to refresh. Dropping
// flights prevents a response started on the previous path from being committed.
func (c *Cache[K, V]) MarkStale(match func(K) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, i := range c.snapshot() {
		if match(i.Key) {
			c.data.SetWithExpire(i.Key, storedValue[V]{i.Value, i.UpdatedAt.UnixNano()}, time.Unix(0, 0))
			delete(c.retry, i.Key)
		}
	}
	for key := range c.flights {
		if match(key) {
			c.invalidateFlight(key)
		}
	}
}

// Refresh coalesces cold lookups and warm background refreshes. The worker is
// independent of any one waiter. Failure leaves the old value and its deadline
// intact; only retries are delayed. A zero deadline means do not store the result.
// Callers must return an error for an unusable replacement (including SERVFAIL).
func (c *Cache[K, V]) Refresh(key K, timeout time.Duration, fetch func(context.Context) (V, time.Time, error)) func(context.Context) (V, error) {
	c.mu.Lock()
	f := c.flights[key]
	if f != nil {
		diagstats.Add(diagstats.CacheRefreshShared)
	}
	if f == nil {
		if until := c.retry[key]; c.now().Before(until) {
			if v, _, ok := c.get(key); ok {
				c.mu.Unlock()
				return func(context.Context) (V, error) { return v.value, nil }
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		f = &flight[V]{done: make(chan struct{}), cancel: cancel}
		c.flights[key] = f
		diagstats.Add(diagstats.CacheRefreshStarted)
		go func() {
			defer cancel()
			v, due, err := fetch(ctx)
			c.mu.Lock()
			retained := false
			if c.flights[key] != f {
				err = ErrInvalidated
			} else {
				delete(c.flights, key)
				if err == nil {
					if !due.IsZero() {
						c.data.SetWithExpire(key, storedValue[V]{v, c.now().UnixNano()}, due)
					}
					delete(c.retry, key)
				} else if _, _, ok := c.get(key); ok {
					retained = true
					c.retry[key] = c.now().Add(RetryDelay)
				}
				f.result = Result[V]{v, err}
				close(f.done)
			}
			kind := c.kind
			c.mu.Unlock()
			event := "refresh_succeeded"
			switch {
			case errors.Is(err, ErrInvalidated):
				event = "refresh_invalidated"
				diagstats.Add(diagstats.CacheRefreshInvalidated)
			case err != nil:
				event = "refresh_failed"
				diagstats.Add(diagstats.CacheRefreshFailed)
			default:
				diagstats.Add(diagstats.CacheRefreshSucceeded)
			}
			if log.Enabled(log.DEBUG) {
				scope := ""
				if key, ok := any(key).(string); ok {
					scope, _, _ = strings.Cut(key, Separator)
				}
				log.Fields(log.DEBUG, map[string]string{"subsystem": "dev_cache", "event": event, "cache_kind": kind, "network_scope": scope, "retained": strconv.FormatBool(retained)}, "Cache refresh completed; retained=%t", retained)
			}
		}()
	}
	c.mu.Unlock()
	return func(ctx context.Context) (V, error) {
		select {
		case <-f.done:
			return f.result.Value, f.result.Err
		case <-ctx.Done():
			var zero V
			return zero, ctx.Err()
		}
	}
}
