package dev_cache

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// Record is the versioned, protocol-neutral persistence envelope. Values are
// encoded by their owner; DNS wire messages and TCP hints never share a decoder.
type Record struct {
	Namespace, Key string
	Value          []byte
	Due            time.Time
	UpdatedAt      time.Time
}
type registered struct {
	cache    any
	snapshot func() []Record
	load     func([]Record)
	clear    func()
	evict    func(string) int
	stale    func(string)
}

var registry = struct {
	sync.Mutex
	entries map[string]registered
	pending map[string][]Record
	loaded  bool
}{entries: make(map[string]registered)}

// Attach reuses a namespace across resolver recreation (including Android IPv6
// availability updates). Only runtime-owned caches should be attached.
func Attach[V any](name string, c *Cache[string, V], encode func(V) ([]byte, error), decode func([]byte) (V, error)) *Cache[string, V] {
	registry.Lock()
	defer registry.Unlock()
	if old, ok := registry.entries[name]; ok {
		return old.cache.(*Cache[string, V])
	}
	c.mu.Lock()
	c.kind, _, _ = strings.Cut(name, "/")
	c.mu.Unlock()
	r := registered{cache: c, clear: c.Clear, evict: func(scope string) int { return c.DeleteMatching(func(k string) bool { return InScope(k, scope) }) }}
	r.stale = func(scope string) { c.MarkStale(func(k string) bool { return InScope(k, scope) }) }
	r.snapshot = func() (out []Record) {
		for _, i := range c.Snapshot() {
			if value, err := encode(i.Value); err == nil {
				out = append(out, Record{Namespace: name, Key: i.Key, Value: value, Due: i.Expires, UpdatedAt: i.UpdatedAt})
			}
		}
		return
	}
	r.load = func(records []Record) {
		for _, record := range records {
			if v, err := decode(record.Value); err == nil {
				c.restore(record.Key, v, record.Due, record.UpdatedAt)
			}
		}
	}
	registry.entries[name] = r
	if pending := registry.pending[name]; len(pending) > 0 {
		r.load(pending)
		delete(registry.pending, name)
	}
	return c
}

func AttachJSON[V any](name string, c *Cache[string, V]) *Cache[string, V] {
	return Attach(name, c, func(v V) ([]byte, error) { return json.Marshal(v) }, func(data []byte) (v V, err error) { err = json.Unmarshal(data, &v); return })
}

func Restore(records []Record) bool {
	return restoreAt(records, time.Now())
}

// Legacy snapshots contain only a refresh deadline. For an ordinary deadline
// it is a conservative upper bound on the last successful write. A forced-stale
// or future deadline cannot establish an age and gets one persisted grace period.
func recordUpdatedAt(record Record, now time.Time) time.Time {
	updated := record.UpdatedAt
	if updated.IsZero() {
		updated = record.Due
		if updated.Year() < 2000 {
			updated = now
		}
	}
	if updated.After(now) {
		updated = now
	}
	return updated
}

func restoreAt(records []Record, now time.Time) bool {
	registry.Lock()
	defer registry.Unlock()
	if registry.loaded {
		return false
	}
	registry.loaded = true
	registry.pending = make(map[string][]Record)
	for _, r := range records {
		r.UpdatedAt = recordUpdatedAt(r, now)
		if !r.UpdatedAt.After(now.Add(-RetentionPeriod)) {
			continue
		}
		registry.pending[r.Namespace] = append(registry.pending[r.Namespace], r)
	}
	for name, r := range registry.entries {
		r.load(registry.pending[name])
		delete(registry.pending, name)
	}
	return true
}
func Snapshot() (records []Record) {
	return snapshotAt(time.Now())
}

func snapshotAt(now time.Time) (records []Record) {
	registry.Lock()
	defer registry.Unlock()
	for _, r := range registry.entries {
		records = append(records, r.snapshot()...)
	}
	cutoff := now.Add(-RetentionPeriod)
	for name, pending := range registry.pending {
		kept := pending[:0]
		for _, r := range pending {
			if r.UpdatedAt.After(cutoff) {
				kept = append(kept, r)
			}
		}
		// Release expired payload references in the backing array as well.
		clear(pending[len(kept):])
		if len(kept) == 0 {
			delete(registry.pending, name)
		} else {
			registry.pending[name] = kept
			records = append(records, kept...)
		}
	}
	return
}

// RetainNamespaces is called after a new configuration has registered all its
// stores. Retired stores are invalidated before their registry references are
// removed so an outstanding refresh cannot republish their previous contents.
func RetainNamespaces(keep func(string) bool) (removed int) {
	registry.Lock()
	defer registry.Unlock()
	for name, r := range registry.entries {
		if !keep(name) {
			r.clear()
			delete(registry.entries, name)
			removed++
		}
	}
	for name := range registry.pending {
		if !keep(name) {
			delete(registry.pending, name)
			removed++
		}
	}
	return
}
func ClearAll() {
	registry.Lock()
	defer registry.Unlock()
	for _, r := range registry.entries {
		r.clear()
	}
	clear(registry.pending)
}

func RefreshScope(scope string) {
	if scope == "" {
		return
	}
	registry.Lock()
	defer registry.Unlock()
	for _, r := range registry.entries {
		r.stale(scope)
	}
}
func EvictScope(scope string) (n int) {
	if scope == "" {
		return
	}
	registry.Lock()
	defer registry.Unlock()
	for _, r := range registry.entries {
		n += r.evict(scope)
	}
	for name, records := range registry.pending {
		kept := records[:0]
		for _, r := range records {
			if InScope(r.Key, scope) {
				n++
			} else {
				kept = append(kept, r)
			}
		}
		registry.pending[name] = kept
	}
	return
}
