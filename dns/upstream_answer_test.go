package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dev_cache"
	R "github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	D "github.com/miekg/dns"
)

func withUpstreamFakeIPPools(t *testing.T) {
	t.Helper()
	previous := R.DefaultHostMapper
	R.DefaultHostMapper = &ResolverEnhancer{
		mode:        C.DNSFakeIP,
		fakeIPPool:  newTestFakeIPPool(t, "198.18.0.0/16"),
		fakeIPPool6: newTestFakeIPPool(t, "2001:2::/64"),
	}
	t.Cleanup(func() { R.DefaultHostMapper = previous })
}

func TestUpstreamRejectsOwnFakeIPAndUsesNextSource(t *testing.T) {
	withUpstreamFakeIPPools(t)
	for _, ip := range []string{"198.18.0.66", "2001:2::3c"} {
		t.Run(ip, func(t *testing.T) {
			ipv6 := netip.MustParseAddr(ip).Is6()
			good := "192.0.2.42"
			if ipv6 {
				good = "2001:db8::42"
			}
			badClient := &directCandidateClient{address: "looped-system", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
				return directAnswer(q, ip, 3600), nil
			}}
			q := directQuestion("image.example", ipv6)
			query := new(D.Msg).SetQuestion(q.Name, q.Qtype)
			if _, err := exchangeDiagnostic(context.Background(), badClient, query, 1); !errors.Is(err, errUpstreamFakeIP) {
				t.Fatalf("fake upstream reply accepted: %v", err)
			}
			r := newDirectCandidateResolver(badClient, &directCandidateClient{address: "healthy", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
				return directAnswer(q, good, 60), nil
			}})
			batches := 0
			for batch := range r.LookupIPCandidates(context.Background(), "image.example", ipv6, "cellular") {
				batches++
				if batch.Err != nil || len(batch.IPs) != 1 || batch.IPs[0].String() != good || batch.Source != 1 {
					t.Fatalf("invalid fallback: %+v", batch)
				}
			}
			if batches != 1 {
				t.Fatalf("batches=%d", batches)
			}
			key := r.directSourceCacheKey(directCacheKey("cellular", q), 0)
			if _, hit := r.sourceCaches[0].Get(key); hit {
				t.Fatal("fake reply cached")
			}
		})
	}
}

func TestBootstrapReplacesRetainedFakeIPWithoutWaitingForTTL(t *testing.T) {
	withUpstreamFakeIPPools(t)
	query := new(D.Msg).SetQuestion("dns.example.", D.TypeA)
	r := NewResolverFromClient(&directCandidateClient{address: "healthy", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
		return directAnswer(q, "192.0.2.53", 60), nil
	}})
	key := dev_cache.ScopedKey(dev_cache.CurrentScope(), query.Question[0].String())
	r.cache.SetWithExpire(key, directAnswer(query, "198.18.0.66", 3600), time.Now().Add(time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	msg, err := r.ExchangeContext(ctx, query)
	if err != nil || len(msgToIP(msg)) != 1 || msgToIP(msg)[0].String() != "192.0.2.53" {
		t.Fatalf("retained bootstrap answer survived: %v %v", msg, err)
	}
}

func TestDirectRetainedFakeIPDoesNotHideHealthySource(t *testing.T) {
	withUpstreamFakeIPPools(t)
	r := newDirectCandidateResolver(&directCandidateClient{address: "system", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
		return directAnswer(q, "192.0.2.42", 60), nil
	}})
	q := directQuestion("image.example", false)
	query := new(D.Msg).SetQuestion(q.Name, q.Qtype)
	key := directCacheKey("cellular", q)
	bad := directAnswer(query, "198.18.0.66", 3600)
	r.cache.SetWithExpire(key, bad, time.Now().Add(time.Hour))
	r.sourceCaches[0].SetWithExpire(r.directSourceCacheKey(key, 0), bad, time.Now().Add(time.Hour))
	batches := 0
	for batch := range r.LookupIPCandidates(context.Background(), "image.example", false, "cellular") {
		batches++
		if batch.Err != nil || len(batch.IPs) != 1 || batch.IPs[0].String() != "192.0.2.42" {
			t.Fatalf("retained fake candidate published: %+v", batch)
		}
	}
	if batches != 1 {
		t.Fatalf("batches=%d", batches)
	}
}

func TestResolverClearsAndExpiresBootstrapCache(t *testing.T) {
	withUpstreamFakeIPPools(t)
	mapper := R.DefaultHostMapper.(*ResolverEnhancer)
	fake := mapper.fakeIPPool.Lookup("image.example")
	bootstrap := &Resolver{cache: Config{}.newCache()}
	rs := Resolvers{Resolver: &Resolver{cache: Config{}.newCache()}, DirectResolver: newDirectCandidateResolver(), BootstrapResolver: bootstrap}
	query := new(D.Msg).SetQuestion("dns.example.", D.TypeA)
	key := dev_cache.ScopedKey(dev_cache.CurrentScope(), query.Question[0].String())
	bootstrap.cache.SetWithExpire(key, directAnswer(query, "192.0.2.53", 3600), time.Now().Add(time.Hour))
	rs.ClearVolatileCache()
	if _, due, hit := bootstrap.cache.GetWithExpire(key); !hit || time.Now().Before(due) {
		t.Fatalf("bootstrap not marked stale: hit=%v due=%v", hit, due)
	}
	rs.ClearCache()
	if _, hit := bootstrap.cache.Get(key); hit {
		t.Fatal("bootstrap survived explicit clear")
	}
	if host, ok := mapper.FindHostByIP(fake); !ok || host != "image.example" {
		t.Fatal("DNS clear erased an application's fake-IP mapping")
	}
}

func TestUpstreamCacheMissPreservesCoalescedRefresh(t *testing.T) {
	c := Config{}.newCache()
	release := make(chan struct{})
	query := new(D.Msg).SetQuestion("image.example.", D.TypeA)
	wait := c.Refresh("key", time.Second, func(ctx context.Context) (*D.Msg, time.Time, error) {
		<-release
		return directAnswer(query, "192.0.2.42", 60), time.Now().Add(time.Minute), nil
	})
	if _, _, hit := readUpstreamCache(c, "key"); hit {
		t.Fatal("unexpected hit")
	}
	close(release)
	if _, err := wait(context.Background()); err != nil {
		t.Fatalf("miss cancelled refresh: %v", err)
	}
	if _, _, hit := readUpstreamCache(c, "key"); !hit {
		t.Fatal("refresh was not retained")
	}
}

func TestUpstreamFakeCacheHitPreservesCoalescedRefresh(t *testing.T) {
	withUpstreamFakeIPPools(t)
	c := Config{}.newCache()
	release := make(chan struct{})
	query := new(D.Msg).SetQuestion("image.example.", D.TypeA)
	c.SetWithExpire("key", directAnswer(query, "198.18.0.66", 60), time.Now().Add(time.Minute))
	wait := c.Refresh("key", time.Second, func(ctx context.Context) (*D.Msg, time.Time, error) {
		<-release
		return directAnswer(query, "192.0.2.42", 60), time.Now().Add(time.Minute), nil
	})
	if _, _, hit := readUpstreamCache(c, "key"); hit {
		t.Fatal("fake answer accepted")
	}
	close(release)
	if _, err := wait(context.Background()); err != nil {
		t.Fatalf("fake entry eviction cancelled replacement: %v", err)
	}
	if msg, _, hit := readUpstreamCache(c, "key"); !hit || msgToIP(msg)[0].String() != "192.0.2.42" {
		t.Fatal("valid replacement was not retained")
	}
}
