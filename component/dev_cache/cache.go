// Package dev_cache owns the lifetime of DNS answers, proxy DNS bundles and
// TCP connection hints. Refresh deadlines never make an existing value unusable.
// Only successful replacement, cold-entry eviction or explicit invalidation do.
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

const RetryDelay = 3 * time.Second

var ErrInvalidated = errors.New("cache refresh invalidated")

type backend[K comparable, V any] interface {
	GetWithExpire(K) (V, time.Time, bool)
	SetWithExpire(K, V, time.Time)
	Delete(K)
	Clear()
}

type Item[K comparable, V any] struct {
	Key     K
	Value   V
	Expires time.Time // compatibility name: this is a refresh deadline, not a deletion time
}

type Result[V any] struct {
	Value V
	Err   error
}
type flight[V any] struct {
	done   chan struct{}
	result Result[V]
}

type Cache[K comparable, V any] struct {
	mu      sync.Mutex
	data    backend[K, V]
	flights map[K]*flight[V]
	retry   map[K]time.Time
	kind    string
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
		c.data = arc.New(arc.WithSize[K, V](size))
	} else {
		c.data = lru.New(lru.WithSize[K, V](size), lru.WithStale[K, V](true))
	}
	return c
}

func (c *Cache[K, V]) GetWithExpire(key K) (V, time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.GetWithExpire(key)
}
func (c *Cache[K, V]) Get(key K) (V, bool) { v, _, ok := c.GetWithExpire(key); return v, ok }
func (c *Cache[K, V]) SetWithExpire(key K, value V, due time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.SetWithExpire(key, value, due)
	delete(c.retry, key)
}
func (c *Cache[K, V]) Compute(key K, f func(V, bool) (V, bool)) (V, bool) {
	return c.ComputeWithExpire(key, func(v V, due time.Time, ok bool) (V, time.Time, bool) { v, remove := f(v, ok); return v, due, remove })
}

func (c *Cache[K, V]) ComputeWithExpire(key K, f func(V, time.Time, bool) (V, time.Time, bool)) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, due, ok := c.data.GetWithExpire(key)
	v, due, remove := f(v, due, ok)
	if remove {
		c.delete(key)
		return v, false
	}
	c.data.SetWithExpire(key, v, due)
	return v, true
}
func (c *Cache[K, V]) delete(key K) { c.data.Delete(key); delete(c.retry, key); delete(c.flights, key) }
func (c *Cache[K, V]) Delete(key K) { c.mu.Lock(); defer c.mu.Unlock(); c.delete(key) }
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.Clear()
	clear(c.retry)
	clear(c.flights)
}
func (c *Cache[K, V]) snapshot() (out []Item[K, V]) {
	switch data := c.data.(type) {
	case *lru.LruCache[K, V]:
		for _, i := range data.Snapshot() {
			out = append(out, Item[K, V]{i.Key, i.Value, i.Expires})
		}
	case *arc.ARC[K, V]:
		for _, i := range data.Snapshot() {
			out = append(out, Item[K, V]{i.Key, i.Value, i.Expires})
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
			delete(c.flights, k)
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
			c.data.SetWithExpire(i.Key, i.Value, time.Unix(0, 0))
			delete(c.retry, i.Key)
		}
	}
	for key := range c.flights {
		if match(key) {
			delete(c.flights, key)
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
		if until := c.retry[key]; time.Now().Before(until) {
			if v, _, ok := c.data.GetWithExpire(key); ok {
				c.mu.Unlock()
				return func(context.Context) (V, error) { return v, nil }
			}
		}
		f = &flight[V]{done: make(chan struct{})}
		c.flights[key] = f
		diagstats.Add(diagstats.CacheRefreshStarted)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
						c.data.SetWithExpire(key, v, due)
					}
					delete(c.retry, key)
				} else if _, _, ok := c.data.GetWithExpire(key); ok {
					retained = true
					c.retry[key] = time.Now().Add(RetryDelay)
				}
			}
			f.result = Result[V]{v, err}
			close(f.done)
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
