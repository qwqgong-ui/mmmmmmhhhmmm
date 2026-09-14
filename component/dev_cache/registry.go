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
				out = append(out, Record{name, i.Key, value, i.Expires})
			}
		}
		return
	}
	r.load = func(records []Record) {
		for _, record := range records {
			if v, err := decode(record.Value); err == nil {
				// Startup traffic may already have populated this key.
				c.ComputeWithExpire(record.Key, func(current V, due time.Time, hit bool) (V, time.Time, bool) {
					if hit {
						return current, due, false
					}
					return v, record.Due, false
				})
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
	registry.Lock()
	defer registry.Unlock()
	if registry.loaded {
		return false
	}
	registry.loaded = true
	registry.pending = make(map[string][]Record)
	for _, r := range records {
		registry.pending[r.Namespace] = append(registry.pending[r.Namespace], r)
	}
	for name, r := range registry.entries {
		r.load(registry.pending[name])
		delete(registry.pending, name)
	}
	return true
}
func Snapshot() (records []Record) {
	registry.Lock()
	defer registry.Unlock()
	for _, r := range registry.entries {
		records = append(records, r.snapshot()...)
	}
	for _, pending := range registry.pending {
		records = append(records, pending...)
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
