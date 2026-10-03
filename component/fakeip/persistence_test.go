package fakeip

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/component/profile/cachefile"
)

func persistentTestPool(t *testing.T, prefix netip.Prefix) (*Pool, *bbolt.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fakeip.db")
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second, NoStatistics: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p, err := New(Options{IPNet: prefix, Size: 16})
	if err != nil {
		t.Fatal(err)
	}
	p.store = newCachefileStore(&cachefile.CacheFile{DB: db}, prefix)
	return p, db, path
}

func TestPersistentReadsDoNotWaitForAllocationWriter(t *testing.T) {
	for _, prefix := range []string{"198.18.0.0/24", "2001:2::/120"} {
		t.Run(prefix, func(t *testing.T) {
			p, db, _ := persistentTestPool(t, netip.MustParsePrefix(prefix))
			ip := p.Lookup("cached.test")
			writerStarted, releaseWriter, writerDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				writerDone <- db.Update(func(*bbolt.Tx) error {
					close(writerStarted)
					<-releaseWriter
					return nil
				})
			}()
			<-writerStarted
			allocationDone := make(chan struct{})
			defer func() { close(releaseWriter); <-writerDone; <-allocationDone }()
			go func() { p.Lookup("new.test"); close(allocationDone) }()
			// Confirm the new allocation is holding the pool lock while waiting
			// for the database writer. Existing reads must bypass this lock.
			deadline := time.Now().Add(time.Second)
			for p.mux.TryLock() {
				p.mux.Unlock()
				if time.Now().After(deadline) {
					t.Fatal("allocation did not acquire pool lock")
				}
				time.Sleep(time.Millisecond)
			}
			readsDone := make(chan error, 1)
			start := time.Now()
			go func() {
				if got := p.Lookup("CACHED.TEST"); got != ip {
					readsDone <- fmt.Errorf("lookup got %s, want %s", got, ip)
					return
				}
				if host, ok := p.LookBack(ip); !ok || host != "cached.test" {
					readsDone <- fmt.Errorf("reverse lookup got %q/%v", host, ok)
					return
				}
				if !p.Exist(ip) {
					readsDone <- fmt.Errorf("existing IP disappeared")
					return
				}
				readsDone <- nil
			}()
			select {
			case err := <-readsDone:
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("cached reads while allocation writer blocked: %s", time.Since(start))
			case <-time.After(time.Second):
				t.Fatal("cached reads waited for allocation writer")
			}
			// The new mapping must still wait for its durable commit.
			select {
			case <-allocationDone:
				t.Fatal("new mapping returned before database writer was released")
			default:
			}
		})
	}
}

func TestPersistentMappingAvoidsBatchDelay(t *testing.T) {
	p, db, _ := persistentTestPool(t, netip.MustParsePrefix("198.18.0.0/24"))
	db.MaxBatchDelay = 500 * time.Millisecond
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		p.Lookup("cold.test")
		done <- time.Since(start)
	}()
	select {
	case elapsed := <-done:
		t.Logf("durable new mapping: %s (Batch delay configured to 500ms)", elapsed)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("new mapping waited for Batch timer")
	}
}

func TestPersistentStateReopenAndFlush(t *testing.T) {
	for _, prefix := range []string{"198.18.0.0/28", "2001:2::/124"} {
		t.Run(prefix, func(t *testing.T) {
			p, db, path := persistentTestPool(t, netip.MustParsePrefix(prefix))
			for i := range 20 {
				p.Lookup(fmt.Sprintf("host-%d.test", i))
			}
			p.StoreState()
			last, cycle := p.offset, p.cycle
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := bbolt.Open(path, 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restored, err := New(Options{IPNet: p.ipnet, Size: 16})
			if err != nil {
				t.Fatal(err)
			}
			restored.store = newCachefileStore(&cachefile.CacheFile{DB: reopened}, p.ipnet)
			restored.restoreState()
			if restored.offset != last || restored.cycle != cycle {
				t.Fatalf("restored state %s/%v, want %s/%v", restored.offset, restored.cycle, last, cycle)
			}
			if got := restored.Lookup("host-19.test"); got != last {
				t.Fatalf("lost durable mapping: %s != %s", got, last)
			}
			if err := restored.FlushFakeIP(); err != nil {
				t.Fatal(err)
			}
			if restored.Exist(last) {
				t.Fatal("flush retained an old mapping")
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
			afterFlush, err := bbolt.Open(path, 0o600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer afterFlush.Close()
			restored.store = newCachefileStore(&cachefile.CacheFile{DB: afterFlush}, p.ipnet)
			restored.restoreState()
			if restored.Exist(last) {
				t.Fatal("reopening after flush recovered old mapping")
			}
			if got := restored.Lookup("after-flush.test"); got != restored.first {
				t.Fatalf("flush did not reset allocator: %s", got)
			}
		})
	}
}

func TestPersistentFailedAllocationDoesNotPublishRecycledAddress(t *testing.T) {
	p, _, _ := persistentTestPool(t, netip.MustParsePrefix("198.18.0.0/29"))
	oldIP := p.Lookup("old.test")
	p.Lookup("two.test")
	p.Lookup("three.test")
	previousOffset, previousCycle := p.offset, p.cycle
	ip, err := p.LookupWithError(strings.Repeat("x", bbolt.MaxKeySize+1))
	if err == nil || ip.IsValid() {
		t.Fatalf("failed allocation published %s, error %v", ip, err)
	}
	if p.offset != previousOffset || p.cycle != previousCycle {
		t.Fatal("failed allocation advanced allocator state")
	}
	if host, ok := p.LookBack(oldIP); !ok || host != "old.test" {
		t.Fatal("failed recycled allocation changed old reverse mapping")
	}
	if got, err := p.LookupWithError("new.test"); err != nil || got != oldIP {
		t.Fatalf("retry did not reuse expected address: %s/%v", got, err)
	}
	if host, ok := p.LookBack(oldIP); !ok || host != "new.test" {
		t.Fatal("successful retry did not publish new reverse mapping")
	}
}

func TestPersistentFlushAndStateConcurrentWithAllocation(t *testing.T) {
	p, _, _ := persistentTestPool(t, netip.MustParsePrefix("198.18.0.0/24"))
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		for i := range 25 {
			ip := p.Lookup(fmt.Sprintf("host-%d.test", i))
			p.LookBack(ip)
			p.Exist(ip)
		}
	}()
	go func() {
		defer workers.Done()
		for range 5 {
			if err := p.FlushFakeIP(); err != nil {
				t.Error(err)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for range 5 {
			p.StoreState()
		}
	}()
	workers.Wait()
	if err := p.FlushFakeIP(); err != nil {
		t.Fatal(err)
	}
	if got := p.Lookup("final.test"); got != p.first {
		t.Fatalf("allocator did not reset: %s", got)
	}
}
