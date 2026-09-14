package dns

import (
	D "github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

func TestInspectMessageExcludesUnrelatedGlue(t *testing.T) {
	m := new(D.Msg)
	m.SetQuestion("example.test.", D.TypeA)
	m.Answer = []D.RR{&D.CNAME{Hdr: D.RR_Header{Name: "example.test.", Rrtype: D.TypeCNAME}, Target: "cdn.test."}, &D.A{Hdr: D.RR_Header{Name: "cdn.test.", Rrtype: D.TypeA}, A: net.ParseIP("192.0.2.1")}}
	m.Extra = []D.RR{&D.A{Hdr: D.RR_Header{Name: "unrelated.test.", Rrtype: D.TypeA}, A: net.ParseIP("192.0.2.2")}}
	got := InspectMessage(m)
	if len(got.Addresses) != 1 || got.Addresses[0] != "192.0.2.1" {
		t.Fatal(got)
	}
}

func TestCacheSnapshotKeepsScopeExpiryAndUnknownGeneration(t *testing.T) {
	c := Config{}.newCache()
	m := new(D.Msg)
	m.SetQuestion("example.test.", D.TypeA)
	m.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: "example.test.", Rrtype: D.TypeA, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
	expiry := time.Now().Add(-time.Second)
	c.SetWithExpire(directCacheKey("old-scope", m.Question[0]), m, expiry)
	persistMu.Lock()
	old := persistCaches
	persistCaches = map[string]dnsCache{"direct": c}
	persistMu.Unlock()
	defer func() { persistMu.Lock(); persistCaches = old; persistMu.Unlock() }()
	got := CacheSnapshots("EXAMPLE.test.")
	if len(got) != 1 || got[0].State != "stale" || got[0].TTL != 0 || got[0].NetworkScope != "old-scope" || got[0].ECSGenerationKnown {
		t.Fatal(got)
	}
	if _, _, ok := c.GetWithExpire(directCacheKey("old-scope", m.Question[0])); !ok {
		t.Fatal("snapshot evicted cached data")
	}
}
