package cachefile

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/bbolt"
)

func TestFakeIPPairReplacementAndRollback(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "fakeip.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := &CacheFile{DB: db}
	for _, store := range []*FakeIpStore{c.FakeIpStore(), c.FakeIpStore6()} {
		ip := netip.MustParseAddr("198.18.0.4")
		if bytes.Equal(store.bucketName, bucketFakeip6) {
			ip = netip.MustParseAddr("2001:2::4")
		}
		store.PutMapping("old.test", ip)
		store.PutMapping("new.test", ip)
		if _, ok := store.GetByHost("old.test"); ok {
			t.Fatal("recycled IP retained old forward mapping")
		}
		if host, ok := store.GetByIP(ip); !ok || host != "new.test" {
			t.Fatalf("reverse mapping = %q/%v", host, ok)
		}
		// An invalid host key fails after replacement has started. The entire
		// transaction, including deletion of the old mapping, must roll back.
		if err := store.PutMapping(strings.Repeat("x", bbolt.MaxKeySize+1), ip); err == nil {
			t.Fatal("invalid mapping unexpectedly committed")
		}
		if got, ok := store.GetByHost("new.test"); !ok || got != ip {
			t.Fatal("failed commit removed existing forward mapping")
		}
		if host, ok := store.GetByIP(ip); !ok || host != "new.test" {
			t.Fatal("failed commit changed existing reverse mapping")
		}
	}
}

func TestFakeIPPublicationWaitsForCommitResult(t *testing.T) {
	for _, address := range []string{"198.18.0.4", "2001:2::4"} {
		for _, repair := range []string{"success", "retry", "state", "flush"} {
			t.Run(address+"/"+repair, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "fakeip.db")
				db, err := bbolt.Open(path, 0o600, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				cache := &CacheFile{DB: db}
				storeFor := func(c *CacheFile) *FakeIpStore {
					if netip.MustParseAddr(address).Is6() {
						return c.FakeIpStore6()
					}
					return c.FakeIpStore()
				}
				store, reader := storeFor(cache), storeFor(cache)
				ip := netip.MustParseAddr(address)
				if err := store.PutMapping("old.test", ip); err != nil {
					t.Fatal(err)
				}
				if err := store.PutMapping("cached.test", ip.Next()); err != nil {
					t.Fatal(err)
				}

				// Model bbolt publishing meta before its final sync returns. The
				// raw database has changed, but Fake-IP must keep confirmed values.
				visible, release, writerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				result := make(chan error, 1)
				go func() {
					result <- store.putMapping("new.test", ip, func(change func(*bbolt.Tx) error) error {
						if err := db.Update(change); err != nil {
							return err
						}
						close(visible)
						<-release
						if repair != "success" {
							return syscall.EIO
						}
						return nil
					})
					close(writerDone)
				}()
				defer func() { releaseOnce.Do(func() { close(release) }); <-writerDone }()
				select {
				case <-visible:
				case <-time.After(time.Second):
					t.Fatal("writer did not publish meta")
				}
				reads := make(chan error, 1)
				start := time.Now()
				go func() {
					if _, ok := reader.GetByHost("new.test"); ok {
						reads <- errors.New("new mapping returned before commit result")
						return
					}
					if got, ok := reader.GetByHost("old.test"); !ok || got != ip {
						reads <- fmt.Errorf("old mapping = %s/%v", got, ok)
						return
					}
					if got, ok := reader.GetByIP(ip); !ok || got != "old.test" {
						reads <- fmt.Errorf("reverse mapping = %s/%v", got, ok)
						return
					}
					if got, ok := reader.GetByHost("cached.test"); !ok || got != ip.Next() {
						reads <- fmt.Errorf("unrelated mapping = %s/%v", got, ok)
						return
					}
					reads <- nil
				}()
				select {
				case err := <-reads:
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("confirmed reads while commit result blocked: %s", time.Since(start))
				case <-time.After(time.Second):
					t.Fatal("confirmed reads waited for disk sync")
				}
				releaseOnce.Do(func() { close(release) })
				err = <-result
				if repair == "success" {
					if err != nil {
						t.Fatal(err)
					}
					if got, ok := reader.GetByHost("new.test"); !ok || got != ip {
						t.Fatal("successful commit did not publish mapping")
					}
					return
				}
				if !errors.Is(err, syscall.EIO) {
					t.Fatalf("commit error = %v", err)
				}
				if _, ok := reader.GetByHost("new.test"); ok {
					t.Fatal("failed mapping became visible")
				}
				if got, ok := reader.GetByIP(ip); !ok || got != "old.test" {
					t.Fatal("failed sync replaced confirmed mapping")
				}
				want := "old.test"
				switch repair {
				case "retry":
					want = "retry.test"
					if err := store.PutMapping(want, ip); err != nil {
						t.Fatal(err)
					}
				case "state":
					store.PutByHost("allocator-state", ip.Prev())
				case "flush":
					want = ""
					if err := store.FlushFakeIP(); err != nil {
						t.Fatal(err)
					}
				}
				if len(store.before) != 0 {
					t.Fatal("successful mutation retained unconfirmed keys")
				}
				if err := db.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := bbolt.Open(path, 0o600, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				restored := storeFor(&CacheFile{DB: reopened})
				if _, ok := restored.GetByHost("new.test"); ok {
					t.Fatal("reopening recovered failed mapping")
				}
				if got, ok := restored.GetByIP(ip); got != want || ok != (want != "") {
					t.Fatalf("restored mapping = %q/%v, want %q", got, ok, want)
				}
			})
		}
	}
}

func TestFakeIPRepeatedUnconfirmedWritesKeepOnlyChangedKeys(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "fakeip.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := (&CacheFile{DB: db}).FakeIpStore()
	ip := netip.MustParseAddr("198.18.0.4")
	if err := store.PutMapping("old.test", ip); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		name := fmt.Sprintf("failed-%d.test", i)
		if err := store.putMapping(name, ip, func(change func(*bbolt.Tx) error) error {
			if err := db.Update(change); err != nil {
				return err
			}
			return syscall.EIO
		}); !errors.Is(err, syscall.EIO) {
			t.Fatal(err)
		}
		if got, ok := store.GetByIP(ip); !ok || got != "old.test" {
			t.Fatal("failed writes replaced confirmed reverse mapping")
		}
		if _, ok := store.GetByHost(name); ok {
			t.Fatal("failed mapping became visible")
		}
		if len(store.before) != 3 {
			t.Fatalf("failed writes accumulated %d keys, want 3", len(store.before))
		}
	}
}

func TestFakeIPReadersSeeCompletePairsDuringRecycling(t *testing.T) {
	db, err := bbolt.Open(filepath.Join(t.TempDir(), "fakeip.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := (&CacheFile{DB: db}).FakeIpStore()
	ip := netip.MustParseAddr("198.18.0.4")
	store.PutMapping("one.test", ip)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := range 100 {
			host := "one.test"
			if i%2 == 0 {
				host = "two.test"
			}
			store.PutMapping(host, ip)
		}
	}()
	for range 100 {
		if err := db.View(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket(bucketFakeip)
			host := bucket.Get(ip.AsSlice())
			if !bytes.Equal(bucket.Get(host), ip.AsSlice()) {
				t.Error("reader observed incomplete forward/reverse pair")
			}
			for _, name := range []string{"one.test", "two.test"} {
				if addr := bucket.Get([]byte(name)); addr != nil && !bytes.Equal(host, []byte(name)) {
					t.Error("reader observed obsolete forward mapping")
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
}
