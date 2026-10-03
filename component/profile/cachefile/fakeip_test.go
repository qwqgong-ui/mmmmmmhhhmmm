package cachefile

import (
	"bytes"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
