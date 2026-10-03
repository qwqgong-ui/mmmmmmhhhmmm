package fakeip

import (
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/component/profile/cachefile"
)

type reverseLookupCounter struct {
	store
	lookups, exists int
}

func (s *reverseLookupCounter) GetByIP(ip netip.Addr) (string, bool) {
	s.lookups++
	return s.store.GetByIP(ip)
}
func (s *reverseLookupCounter) Exist(ip netip.Addr) bool {
	s.exists++
	return s.store.Exist(ip)
}

func TestPoolReverseLookupUsesConfiguredPrefix(t *testing.T) {
	for _, prefix := range []string{"192.0.2.8/29", "2001:db8:1234::/120"} {
		t.Run(prefix, func(t *testing.T) {
			p, err := New(Options{IPNet: netip.MustParsePrefix(prefix), Size: 16})
			if err != nil {
				t.Fatal(err)
			}
			ip := p.Lookup("inside.test")
			s := &reverseLookupCounter{store: p.store}
			p.store = s
			for _, addr := range []netip.Addr{{}, netip.MustParseAddr("127.0.0.5"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("198.18.0.4"), netip.MustParseAddr("2001:2::4"), netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("::ffff:192.0.2.12")} {
				if host, ok := p.LookBack(addr); ok || host != "" {
					t.Fatalf("outside address %s resolved to %q", addr, host)
				}
				if p.Exist(addr) {
					t.Fatalf("outside address %s exists", addr)
				}
			}
			if s.lookups != 0 || s.exists != 0 {
				t.Fatalf("outside addresses reached store: %+v", s)
			}
			if host, ok := p.LookBack(ip); !ok || host != "inside.test" {
				t.Fatalf("lost allocated mapping: %s %v", host, ok)
			}
			if !p.Exist(ip) || s.lookups != 1 || s.exists != 1 {
				t.Fatal("allocated address did not reach store")
			}
		})
	}
}

func TestPersistentReverseLookupSkipsTransactionsOutsidePrefix(t *testing.T) {
	for _, prefix := range []string{"198.18.0.0/24", "2001:2::/120"} {
		t.Run(prefix, func(t *testing.T) {
			db, err := bbolt.Open(filepath.Join(t.TempDir(), "fakeip.db"), 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			p, err := New(Options{IPNet: netip.MustParsePrefix(prefix), Size: 16})
			if err != nil {
				t.Fatal(err)
			}
			p.store = newCachefileStore(&cachefile.CacheFile{DB: db}, p.ipnet)
			ip := p.Lookup("persistent.test")
			before := db.Stats().TxN
			for range 100 {
				if _, ok := p.LookBack(netip.MustParseAddr("127.0.0.5")); ok {
					t.Fatal("real address resolved")
				}
				if p.Exist(netip.MustParseAddr("2606:4700:4700::1111")) {
					t.Fatal("real address exists")
				}
			}
			if db.Stats().TxN != before {
				t.Fatal("real addresses opened bbolt transactions")
			}
			if host, ok := p.LookBack(ip); !ok || host != "persistent.test" {
				t.Fatal("persistent mapping lost")
			}
			if !p.Exist(ip) || db.Stats().TxN <= before {
				t.Fatal("in-prefix reads skipped the persistent store")
			}
		})
	}
}
