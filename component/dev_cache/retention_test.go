package dev_cache

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type retentionClock struct{ ns atomic.Int64 }

func newRetentionClock() *retentionClock {
	c := new(retentionClock)
	c.ns.Store(time.Now().UnixNano())
	return c
}
func (c *retentionClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *retentionClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func resetRetentionRegistry(t *testing.T) {
	t.Helper()
	registry.Lock()
	entries, pending, loaded := registry.entries, registry.pending, registry.loaded
	registry.entries = make(map[string]registered)
	registry.pending = nil
	registry.loaded = false
	registry.Unlock()
	t.Cleanup(func() {
		registry.Lock()
		registry.entries, registry.pending, registry.loaded = entries, pending, loaded
		registry.Unlock()
	})
}

func TestRetentionIsSinceContentUpdateNotDeadlineReadOrStaleMark(t *testing.T) {
	for _, algorithm := range []string{"lru", "arc"} {
		t.Run(algorithm, func(t *testing.T) {
			clock := newRetentionClock()
			c := New[string, string](4, algorithm)
			c.nowFn = clock.now
			c.SetWithExpire("key", "value", clock.now().Add(365*24*time.Hour))
			updated := c.Snapshot()[0].UpdatedAt
			clock.advance(29 * 24 * time.Hour)
			for range 10 {
				if v, ok := c.Get("key"); !ok || v != "value" {
					t.Fatal("premature retention expiry")
				}
			}
			c.MarkStale(func(string) bool { return true })
			if !c.Snapshot()[0].UpdatedAt.Equal(updated) {
				t.Fatal("reading or stale marking renewed retention")
			}
			clock.advance(24 * time.Hour)
			if _, ok := c.Get("key"); ok {
				t.Fatal("30-day value survived without an update")
			}
			c.SetWithExpire("idle", "idle", clock.now().Add(365*24*time.Hour))
			clock.advance(RetentionPeriod)
			if len(c.Snapshot()) != 0 {
				t.Fatal("idle snapshot failed to prune old data")
			}
		})
	}
}

func TestFailedRefreshDoesNotRenewRetentionAndSuccessDoes(t *testing.T) {
	for _, algorithm := range []string{"lru", "arc"} {
		t.Run(algorithm, func(t *testing.T) {
			clock := newRetentionClock()
			c := New[string, string](4, algorithm)
			c.nowFn = clock.now
			c.SetWithExpire("failed", "old", clock.now().Add(-time.Hour))
			c.SetWithExpire("success", "old", clock.now().Add(-time.Hour))
			clock.advance(29 * 24 * time.Hour)
			_, err := c.Refresh("failed", time.Second, func(context.Context) (string, time.Time, error) {
				return "", time.Time{}, errors.New("offline")
			})(t.Context())
			if err == nil {
				t.Fatal("missing failure")
			}
			_, err = c.Refresh("success", time.Second, func(context.Context) (string, time.Time, error) {
				return "new", clock.now().Add(time.Hour), nil
			})(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			clock.advance(24 * time.Hour)
			if _, ok := c.Get("failed"); ok {
				t.Fatal("failed refresh extended retention")
			}
			if v, ok := c.Get("success"); !ok || v != "new" {
				t.Fatal("successful refresh did not extend retention")
			}
			clock.advance(29 * 24 * time.Hour)
			if _, ok := c.Get("success"); ok {
				t.Fatal("updated value never expired")
			}
		})
	}
}

func TestRetentionExpiryKeepsAnInFlightFreshLookup(t *testing.T) {
	clock := newRetentionClock()
	c := New[string, string](4, "lru")
	c.nowFn = clock.now
	c.SetWithExpire("key", "old", clock.now())
	clock.advance(RetentionPeriod - time.Second)
	started, release := make(chan struct{}), make(chan struct{})
	wait := c.Refresh("key", time.Second, func(context.Context) (string, time.Time, error) {
		close(started)
		<-release
		return "fresh", clock.now().Add(time.Hour), nil
	})
	<-started
	clock.advance(time.Second)
	if _, ok := c.Get("key"); ok {
		t.Fatal("expired old value remained visible")
	}
	close(release)
	if v, err := wait(t.Context()); err != nil || v != "fresh" {
		t.Fatalf("fresh lookup was invalidated: %q %v", v, err)
	}
	if v, ok := c.Get("key"); !ok || v != "fresh" {
		t.Fatal("fresh result was not retained")
	}
}

func TestPersistentUpdateTimeSurvivesRestoreAndStartupWritesWin(t *testing.T) {
	resetRetentionRegistry(t)
	clock := newRetentionClock()
	updated := clock.now().Add(-20 * 24 * time.Hour)
	namespace := "dns/current/main"
	if !restoreAt([]Record{{Namespace: namespace, Key: "restored", Value: []byte(`"old"`), Due: clock.now().Add(-time.Hour), UpdatedAt: updated}, {Namespace: namespace, Key: "startup", Value: []byte(`"saved"`), Due: clock.now(), UpdatedAt: updated}}, clock.now()) {
		t.Fatal("restore did not run")
	}
	c := New[string, string](4, "arc")
	c.nowFn = clock.now
	c.SetWithExpire("startup", "fresh", clock.now().Add(time.Hour))
	c = AttachJSON(namespace, c)
	if v, ok := c.Get("startup"); !ok || v != "fresh" {
		t.Fatal("restore overwrote a startup write")
	}
	var savedUpdated time.Time
	for _, r := range snapshotAt(clock.now()) {
		if r.Key == "restored" {
			savedUpdated = r.UpdatedAt
		}
	}
	if !savedUpdated.Equal(updated) {
		t.Fatal("restore renewed the update time")
	}
	encoded, err := json.Marshal(snapshotAt(clock.now()))
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	if err := json.Unmarshal(encoded, &records); err != nil {
		t.Fatal(err)
	}
	registry.Lock()
	registry.entries = make(map[string]registered)
	registry.pending = nil
	registry.loaded = false
	registry.Unlock()
	clock.advance(9 * 24 * time.Hour)
	restoreAt(records, clock.now())
	restarted := New[string, string](4, "arc")
	restarted.nowFn = clock.now
	restarted = AttachJSON(namespace, restarted)
	if _, ok := restarted.Get("restored"); !ok {
		t.Fatal("unexpired record disappeared on restart")
	}
	clock.advance(24 * time.Hour)
	if _, ok := restarted.Get("restored"); ok {
		t.Fatal("restart extended the old record's lifetime")
	}
}

func TestLegacyMigrationAndUnattachedRecordExpiry(t *testing.T) {
	resetRetentionRegistry(t)
	now := time.Now()
	namespace := "dns/legacy/main"
	restoreAt([]Record{
		{Namespace: namespace, Key: "old", Value: []byte(`"old"`), Due: now.Add(-RetentionPeriod)},
		{Namespace: namespace, Key: "recent", Value: []byte(`"recent"`), Due: now.Add(-time.Hour)},
		{Namespace: namespace, Key: "stale", Value: []byte(`"stale"`), Due: time.Unix(0, 0)},
		{Namespace: namespace, Key: "future", Value: []byte(`"future"`), Due: now.Add(365 * 24 * time.Hour)},
	}, now)
	initial := snapshotAt(now)
	if len(initial) != 3 {
		t.Fatalf("legacy migration kept %d records, want 3", len(initial))
	}
	for _, r := range initial {
		if r.UpdatedAt.IsZero() || r.UpdatedAt.After(now) {
			t.Fatal("migration failed to establish an update clock")
		}
	}
	if len(snapshotAt(now.Add(RetentionPeriod))) != 0 {
		t.Fatal("unattached records were retained indefinitely")
	}
	registry.Lock()
	defer registry.Unlock()
	if len(registry.pending) != 0 {
		t.Fatal("expired pending namespaces retained references")
	}
}

func TestConfigurationRetirementKeepsCurrentScopesAndCancelsOldRefresh(t *testing.T) {
	resetRetentionRegistry(t)
	current := AttachJSON("dns/current/main", New[string, string](4, "lru"))
	for _, scope := range []string{"wifi", "cell"} {
		current.SetWithExpire(ScopedKey(scope, "host"), scope, time.Now())
	}
	winner := AttachJSON("tcp-winner/v1", New[string, string](4, "lru"))
	winner.SetWithExpire("winner", "winner", time.Now())
	old := AttachJSON("dns/old/main", New[string, string](4, "lru"))
	old.SetWithExpire("key", "old", time.Now())
	restoreAt([]Record{{Namespace: "domain-bundle/v1/old", Key: "pending", Value: []byte(`"old"`), Due: time.Now()}}, time.Now())
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	wait := old.Refresh("running", time.Second, func(context.Context) (string, time.Time, error) {
		close(started)
		<-release
		defer close(finished)
		return "late", time.Now(), nil
	})
	<-started
	if n := RetainNamespaces(func(name string) bool { return name == "dns/current/main" || name == "tcp-winner/v1" }); n != 2 {
		t.Fatalf("retired %d namespaces, want 2", n)
	}
	if _, err := wait(t.Context()); !errors.Is(err, ErrInvalidated) {
		t.Fatal("retired refresh was not invalidated", err)
	}
	close(release)
	<-finished
	if _, ok := old.Get("running"); ok {
		t.Fatal("old refresh revived a retired cache")
	}
	if AttachJSON("dns/current/main", New[string, string](4, "lru")) != current {
		t.Fatal("matching store was replaced")
	}
	for _, scope := range []string{"wifi", "cell"} {
		if v, ok := current.Get(ScopedKey(scope, "host")); !ok || v != scope {
			t.Fatal("current network branch was cleared")
		}
	}
	if _, ok := winner.Get("winner"); !ok {
		t.Fatal("unrelated TCP hints were cleared")
	}
	for _, r := range Snapshot() {
		if r.Namespace != "dns/current/main" && r.Namespace != "tcp-winner/v1" {
			t.Fatal("retired namespace was persisted again")
		}
	}
}
