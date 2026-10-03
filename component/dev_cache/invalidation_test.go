package dev_cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
)

func TestInvalidationWakesWaitersBeforeUncooperativeWorker(t *testing.T) {
	for _, algorithm := range []string{"lru", "arc"} {
		for _, method := range []string{"clear", "delete", "matching", "stale"} {
			t.Run(algorithm+"/"+method, func(t *testing.T) {
				c := New[string, string](4, algorithm)
				started, release, cancelled, finished := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
				wait := c.Refresh("old", time.Second, func(ctx context.Context) (string, time.Time, error) {
					close(started)
					<-ctx.Done()
					close(cancelled)
					<-release // Deliberately ignore cancellation until released.
					defer close(finished)
					return "late", time.Now().Add(time.Hour), nil
				})
				<-started
				otherRelease := make(chan struct{})
				other := c.Refresh("other", time.Second, func(context.Context) (string, time.Time, error) {
					<-otherRelease
					return "other", time.Now().Add(time.Hour), nil
				})
				t.Cleanup(func() { close(release); close(otherRelease); <-finished })
				switch method {
				case "clear":
					c.Clear()
				case "delete":
					c.Delete("old")
				case "matching":
					c.DeleteMatching(func(k string) bool { return k == "old" })
				case "stale":
					c.MarkStale(func(k string) bool { return k == "old" })
				}
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				before := time.Now()
				if _, err := wait(ctx); !errors.Is(err, ErrInvalidated) {
					t.Fatalf("wait: %v", err)
				}
				t.Logf("invalidation wake=%s", time.Since(before))
				select {
				case <-cancelled:
				case <-ctx.Done():
					t.Fatal("worker context not cancelled")
				}
				replacement := c.Refresh("old", time.Second, func(context.Context) (string, time.Time, error) { return "new", time.Now().Add(time.Hour), nil })
				if v, err := replacement(ctx); err != nil || v != "new" {
					t.Fatalf("replacement: %q %v", v, err)
				}
				if method != "clear" {
					cancelWait, cancelOther := context.WithCancel(t.Context())
					cancelOther()
					if _, err := other(cancelWait); !errors.Is(err, context.Canceled) {
						t.Fatalf("unrelated flight invalidated: %v", err)
					}
				}
			})
		}
	}
}

func TestOldCompletionCannotReplaceNewFlight(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			c := New[string, string](4, "lru")
			c.kind = t.Name()
			sub := log.SubscribeLevel(log.DEBUG)
			defer log.UnSubscribe(sub)
			release, finished := make(chan struct{}), make(chan struct{})
			old := c.Refresh("key", time.Second, func(context.Context) (string, time.Time, error) {
				<-release
				defer close(finished)
				var err error
				if fail {
					err = errors.New("old error")
				}
				return "old", time.Now().Add(time.Hour), err
			})
			c.Delete("key")
			nextRelease := make(chan struct{})
			next := c.Refresh("key", time.Second, func(context.Context) (string, time.Time, error) {
				<-nextRelease
				return "new", time.Now().Add(time.Hour), nil
			})
			close(release)
			<-finished
			// The completion event is emitted after the old worker has left the
			// cache critical section, while the new fetch is still blocked.
			deadline := time.NewTimer(time.Second)
			defer deadline.Stop()
		completion:
			for {
				select {
				case e := <-sub:
					if e.Fields["cache_kind"] == c.kind && e.Fields["event"] == "refresh_invalidated" {
						break completion
					}
				case <-deadline.C:
					t.Fatal("old worker did not finish invalidated completion")
				}
			}
			if !c.Status("key").Refreshing {
				t.Fatal("old completion removed new flight")
			}
			if _, err := old(t.Context()); !errors.Is(err, ErrInvalidated) {
				t.Fatal(err)
			}
			close(nextRelease)
			if v, err := next(t.Context()); v != "new" || err != nil {
				t.Fatalf("%q %v", v, err)
			}
			if v, ok := c.Get("key"); !ok || v != "new" {
				t.Fatalf("stored %q %v", v, ok)
			}
		})
	}
}

func TestOneWaiterCancellationDoesNotCancelSharedRefresh(t *testing.T) {
	c := New[string, string](4, "lru")
	release := make(chan struct{})
	wait := c.Refresh("key", time.Second, func(ctx context.Context) (string, time.Time, error) {
		select {
		case <-release:
			return "value", time.Now().Add(time.Hour), nil
		case <-ctx.Done():
			return "", time.Time{}, ctx.Err()
		}
	})
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := wait(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	if v, err := wait(t.Context()); v != "value" || err != nil {
		t.Fatalf("%q %v", v, err)
	}
}
