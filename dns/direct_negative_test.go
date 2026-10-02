package dns

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/diagstats"
	D "github.com/miekg/dns"
)

func directNegative(q *D.Msg, rcode int, ttl uint32) *D.Msg {
	m := new(D.Msg).SetReply(q)
	m.Rcode = rcode
	m.Ns = []D.RR{&D.SOA{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: ttl}, Ns: "ns.example.", Mbox: "hostmaster.example.", Minttl: ttl}}
	return m
}

func collectDirect(t *testing.T, r *directResolver, ipv6 bool) []netip.Addr {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var ips []netip.Addr
	for batch := range r.LookupIPCandidates(ctx, "ipv4-only.example", ipv6, "test-network") {
		if batch.Err != nil {
			t.Fatal(batch.Err)
		}
		ips = append(ips, batch.IPs...)
	}
	return ips
}

func TestDirectNegativeCacheKeepsIPv4AndAvoidsRepeatedRefresh(t *testing.T) {
	var calls atomic.Int32
	r := newDirectCandidateResolver(&directCandidateClient{address: "first", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
		calls.Add(1)
		if q.Question[0].Qtype == D.TypeA {
			return directAnswer(q, "192.0.2.1", 60), nil
		}
		return directNegative(q, D.RcodeSuccess, 60), nil
	}})
	before := diagstats.Snapshot()["dev_cache.refresh.failed"]
	for range 3 {
		if got := collectDirect(t, r, false); len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.1") {
			t.Fatal(got)
		}
		if got := collectDirect(t, r, true); len(got) != 0 {
			t.Fatal(got)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("IPv4-only lookups made %d queries, want one per family", calls.Load())
	}
	if got := diagstats.Snapshot()["dev_cache.refresh.failed"]; got != before {
		t.Fatalf("NODATA counted as failure: %d -> %d", before, got)
	}
}

func TestDirectNegativeDoesNotHideOtherSource(t *testing.T) {
	for _, code := range []int{D.RcodeSuccess, D.RcodeNameError} {
		r := newDirectCandidateResolver(
			&directCandidateClient{address: "empty", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
				m := directNegative(q, code, 60)
				if code == D.RcodeNameError {
					m.Answer = directAnswer(q, "2001:db8::99", 60).Answer
				}
				return m, nil
			}},
			&directCandidateClient{address: "positive", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) { return directAnswer(q, "2001:db8::1", 60), nil }},
		)
		for range 2 {
			if got := collectDirect(t, r, true); len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::1") {
				t.Fatalf("rcode=%d: %v", code, got)
			}
		}
	}
}

func TestDirectExpiredNegativeDiscoversNewIPv6(t *testing.T) {
	var available atomic.Bool
	r := newDirectCandidateResolver(&directCandidateClient{address: "changing", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
		if available.Load() {
			return directAnswer(q, "2001:db8::2", 60), nil
		}
		return directNegative(q, D.RcodeSuccess, 60), nil
	}})
	if ips := collectDirect(t, r, true); len(ips) != 0 {
		t.Fatal(ips)
	}
	key := r.directSourceCacheKey(directCacheKey("test-network", directQuestion("ipv4-only.example", true)), 0)
	m, _, _ := r.sourceCaches[0].GetWithExpire(key)
	r.sourceCaches[0].SetWithExpire(key, m, time.Now().Add(-time.Second))
	available.Store(true)
	if ips := collectDirect(t, r, true); len(ips) != 1 || ips[0] != netip.MustParseAddr("2001:db8::2") {
		t.Fatal(ips)
	}
}

func TestDirectNegativeReplacementCannotResurrectAggregateAddress(t *testing.T) {
	r := newDirectCandidateResolver(&directCandidateClient{address: "empty", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) { return directNegative(q, D.RcodeSuccess, 60), nil }})
	q := directQuestion("ipv4-only.example", true)
	key := directCacheKey("test-network", q)
	m := directAnswer(new(D.Msg).SetQuestion(q.Name, q.Qtype), "2001:db8::9", 60)
	r.cache.SetWithExpire(key, m, time.Now().Add(-time.Second))
	r.sourceCaches[0].SetWithExpire(r.directSourceCacheKey(key, 0), m, time.Now().Add(-time.Second))
	collectDirect(t, r, true) // stale address can be served while its source refreshes
	if got := collectDirect(t, r, true); len(got) != 0 {
		t.Fatalf("aggregate revived removed address: %v", got)
	}
}

func TestDirectWarmNegativeSourcesContinueToLaterSource(t *testing.T) {
	r := newDirectCandidateResolver(
		&directCandidateClient{address: "empty1", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) { return directNegative(q, D.RcodeSuccess, 60), nil }},
		&directCandidateClient{address: "empty2", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) { return directNegative(q, D.RcodeSuccess, 60), nil }},
		&directCandidateClient{address: "positive", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) { return directAnswer(q, "2001:db8::3", 60), nil }},
	)
	q := directQuestion("ipv4-only.example", true)
	r.cache.SetWithExpire(directCacheKey("test-network", q), directAnswer(new(D.Msg).SetQuestion(q.Name, q.Qtype), "2001:db8::9", 60), time.Now().Add(-time.Second))
	if got := collectDirect(t, r, true); !containsAddr(got, netip.MustParseAddr("2001:db8::3")) {
		t.Fatal(got)
	}
}

func TestDirectNegativeRejectsFailuresAndReferrals(t *testing.T) {
	for _, code := range []int{D.RcodeServerFailure, D.RcodeRefused, D.RcodeSuccess} {
		r := newDirectCandidateResolver(&directCandidateClient{address: "invalid", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
			m := new(D.Msg).SetReply(q)
			m.Rcode = code
			if code == D.RcodeSuccess {
				m.Ns = []D.RR{&D.NS{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeNS, Ttl: 60}, Ns: "ns.example."}}
			}
			return m, nil
		}})
		_, err := r.exchangeDirectSource(context.Background(), 0, new(D.Msg).SetQuestion("ipv4-only.example", D.TypeAAAA))
		if err == nil {
			t.Fatalf("accepted rcode/referral %d", code)
		}
	}
	if got := msgToAddressIPs(directAnswer(new(D.Msg).SetQuestion("example", D.TypeAAAA), "192.0.2.1", 60), D.TypeAAAA); len(got) != 0 {
		t.Fatalf("A leaked into AAAA: %v", got)
	}
	r := newDirectCandidateResolver(&directCandidateClient{address: "down", exchange: func(context.Context, *D.Msg) (*D.Msg, error) { return nil, errors.New("offline") }})
	for batch := range r.LookupIPCandidates(t.Context(), "example", true, "test-network") {
		if batch.Err == nil {
			t.Fatal("real failure disappeared")
		}
	}
}

func TestDirectNegativeOnlyReplacesItsSourceAndFamily(t *testing.T) {
	r := newDirectCandidateResolver(
		&directCandidateClient{address: "removed-v6", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) { return directNegative(q, D.RcodeSuccess, 60), nil }},
		&directCandidateClient{address: "valid-v6", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) { return directAnswer(q, "2001:db8::2", 60), nil }},
	)
	v4 := directQuestion("ipv4-only.example", false)
	v6 := directQuestion("ipv4-only.example", true)
	r.sourceCaches[0].SetWithExpire(r.directSourceCacheKey(directCacheKey("test-network", v4), 0), directAnswer(new(D.Msg).SetQuestion(v4.Name, v4.Qtype), "192.0.2.1", 60), time.Now().Add(time.Minute))
	r.sourceCaches[0].SetWithExpire(r.directSourceCacheKey(directCacheKey("test-network", v6), 0), directAnswer(new(D.Msg).SetQuestion(v6.Name, v6.Qtype), "2001:db8::1", 60), time.Now().Add(-time.Second))
	r.sourceCaches[1].SetWithExpire(r.directSourceCacheKey(directCacheKey("test-network", v6), 1), directAnswer(new(D.Msg).SetQuestion(v6.Name, v6.Qtype), "2001:db8::2", 60), time.Now().Add(time.Minute))
	collectDirect(t, r, true)
	if got := collectDirect(t, r, true); len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::2") {
		t.Fatalf("negative replaced another source: %v", got)
	}
	if got := collectDirect(t, r, false); len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("AAAA negative replaced A: %v", got)
	}
}

func TestNegativeCacheTTLRespectsSOAAndCNAME(t *testing.T) {
	for _, tc := range []struct {
		ttl, minimum, cname, want uint32
		soa                       bool
	}{
		{120, 5, 0, 5, true}, {5, 120, 0, 5, true}, {0, 60, 0, 0, true}, {60, 0, 0, 0, true},
		{120, 60, 3, 3, true}, {0, 0, 0, negativeCacheTTL, false},
	} {
		q := new(D.Msg).SetQuestion("example.", D.TypeAAAA)
		m := directNegative(q, D.RcodeSuccess, tc.ttl)
		if tc.soa {
			m.Ns[0].(*D.SOA).Minttl = tc.minimum
		} else {
			m.Ns = nil
		}
		if tc.cname > 0 {
			m.Answer = []D.RR{&D.CNAME{Hdr: D.RR_Header{Name: "example.", Rrtype: D.TypeCNAME, Ttl: tc.cname}, Target: "target.example."}}
		}
		_, due := prepareDirectCachedMessage(q.Question[0], m)
		remaining := time.Until(due)
		if remaining > time.Duration(tc.want)*time.Second || remaining < time.Duration(tc.want)*time.Second-time.Second {
			t.Fatalf("%+v: ttl=%v", tc, remaining)
		}
	}
}
