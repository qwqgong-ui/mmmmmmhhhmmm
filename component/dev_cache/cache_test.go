package dev_cache

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetainedValueRefreshFailureAndReplacement(t *testing.T) {
	for _, algorithm := range []string{"lru", "arc"} {
		t.Run(algorithm, func(t *testing.T) {
			c := New[string, string](4, algorithm)
			old := time.Now().Add(-365 * 24 * time.Hour)
			c.SetWithExpire("key", "old", old)
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			fetch := func(context.Context) (string, time.Time, error) {
				calls.Add(1)
				close(started)
				<-release
				return "", time.Time{}, errors.New("offline")
			}
			wait1 := c.Refresh("key", time.Second, fetch)
			<-started
			wait2 := c.Refresh("key", time.Second, fetch)
			if value, _, ok := c.GetWithExpire("key"); !ok || value != "old" {
				t.Fatal("pending refresh hid old value")
			}
			close(release)
			if _, err := wait1(t.Context()); err == nil {
				t.Fatal("missing failure")
			}
			_, _ = wait2(t.Context())
			if calls.Load() != 1 {
				t.Fatal("refresh was not coalesced")
			}
			if value, due, ok := c.GetWithExpire("key"); !ok || value != "old" || due.Unix() != old.Unix() {
				t.Fatal("failure replaced value or deadline")
			}
			_, _ = c.Refresh("key", time.Second, func(context.Context) (string, time.Time, error) {
				t.Error("retry backoff ignored")
				return "", time.Time{}, nil
			})(t.Context())
			c.mu.Lock()
			delete(c.retry, "key")
			c.mu.Unlock()
			_, err := c.Refresh("key", time.Second, func(context.Context) (string, time.Time, error) { return "new", time.Now().Add(time.Hour), nil })(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if value, ok := c.Get("key"); !ok || value != "new" {
				t.Fatal("success did not replace old value")
			}
		})
	}
}

func TestRefreshInvalidationAndWaiterCancellation(t *testing.T) {
	c := New[string, string](4, "lru")
	release := make(chan struct{})
	wait := c.Refresh("key", time.Second, func(context.Context) (string, time.Time, error) { <-release; return "late", time.Now(), nil })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	c.Clear()
	close(release)
	if _, err := wait(t.Context()); !errors.Is(err, ErrInvalidated) {
		t.Fatal(err)
	}
	if _, ok := c.Get("key"); ok {
		t.Fatal("late refresh undid clear")
	}
}

func TestColdEvictionAndScopeRetirement(t *testing.T) {
	for _, algorithm := range []string{"lru", "arc"} {
		t.Run(algorithm, func(t *testing.T) {
			c := New[string, int](2, algorithm)
			c.SetWithExpire(ScopedKey("wifi", "a"), 1, time.Now().Add(-time.Hour))
			c.SetWithExpire(ScopedKey("cell", "a"), 2, time.Now())
			if n := c.DeleteMatching(func(k string) bool { return InScope(k, "wifi") }); n != 1 {
				t.Fatal(n)
			}
			if v, ok := c.Get(ScopedKey("cell", "a")); !ok || v != 2 {
				t.Fatal("retired another network")
			}
			c.SetWithExpire("b", 3, time.Now())
			c.SetWithExpire("c", 4, time.Now())
			if len(c.Snapshot()) > 2 {
				t.Fatal("cold eviction stopped")
			}
		})
	}
}

func TestDesktopScopeIsPrivateIPv4Slash16Only(t *testing.T) {
	parse := func(values ...string) (out []netip.Prefix) {
		for _, s := range values {
			out = append(out, netip.MustParsePrefix(s))
		}
		return
	}
	a := DesktopScope(parse("192.168.1.2/24", "2001:db8:1::1/64"))
	b := DesktopScope(parse("192.168.200.99/24", "2001:db8:ffff::2/64"))
	if a != b || a != "ipv4-private|192.168.0.0/16" {
		t.Fatal(a, b)
	}
	if DesktopScope(parse("10.1.2.3/8")) == DesktopScope(parse("10.2.2.3/8")) {
		t.Fatal("different /16 networks merged")
	}
	if DesktopScope(parse("172.16.1.2/12")) != DesktopScope(parse("172.16.254.2/24")) {
		t.Fatal("host bits affected scope")
	}
	if DesktopScope(parse("2001:db8::1/64", "8.8.8.8/32")) != DesktopScope(nil) {
		t.Fatal("non-private IPv4 or IPv6 affected scope")
	}
}

func TestRegistryPreservesStaleAndNamespaceIsolation(t *testing.T) {
	// This package's tests do not use the process-wide runtime registry in parallel.
	registry.Lock()
	oldEntries, oldPending, oldLoaded := registry.entries, registry.pending, registry.loaded
	registry.entries = make(map[string]registered)
	registry.pending = nil
	registry.loaded = false
	registry.Unlock()
	t.Cleanup(func() {
		registry.Lock()
		registry.entries, registry.pending, registry.loaded = oldEntries, oldPending, oldLoaded
		registry.Unlock()
	})
	key := ScopedKey("wifi", "host/A")
	Restore([]Record{{Namespace: "dns", Key: key, Value: []byte(`"old"`), Due: time.Now().Add(-time.Hour)}})
	c := AttachJSON("dns", New[string, string](4, "lru"))
	if value, ok := c.Get(key); !ok || value != "old" {
		t.Fatal("stale restore lost")
	}
	if AttachJSON("dns", New[string, string](4, "lru")) != c {
		t.Fatal("resolver recreation lost store")
	}
	other := AttachJSON("bundle", New[string, string](4, "lru"))
	other.SetWithExpire(ScopedKey("cell", "host/A"), "other", time.Now())
	if EvictScope("wifi") != 1 {
		t.Fatal("wrong eviction count")
	}
	if len(Snapshot()) != 1 {
		t.Fatal("scope eviction crossed namespaces or networks")
	}
}
