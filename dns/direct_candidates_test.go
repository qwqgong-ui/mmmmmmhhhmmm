package dns

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
)

type directCandidateClient struct {
	address  string
	exchange func(context.Context, *D.Msg) (*D.Msg, error)
}

func (c *directCandidateClient) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	return c.exchange(ctx, msg)
}

func (c *directCandidateClient) Address() string  { return c.address }
func (c *directCandidateClient) ResetConnection() {}

func directAnswer(query *D.Msg, ip string, ttl uint32) *D.Msg {
	msg := new(D.Msg)
	msg.SetReply(query)
	addr := netip.MustParseAddr(ip)
	if addr.Is4() {
		msg.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: ttl}, A: addr.AsSlice()}}
	} else {
		msg.Answer = []D.RR{&D.AAAA{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: ttl}, AAAA: addr.AsSlice()}}
	}
	return msg
}

func newDirectCandidateResolver(clients ...dnsClient) *directResolver {
	r := &Resolver{main: clients, cache: Config{}.newCache()}
	for range clients {
		r.sourceCaches = append(r.sourceCaches, Config{}.newCache())
	}
	return &directResolver{Resolver: r}
}

func TestProgressiveResolverCapabilityIsDirectOnly(t *testing.T) {
	if _, ok := any(&Resolver{}).(R.ProgressiveResolver); ok {
		t.Fatal("ordinary resolver unexpectedly exposes direct candidate streaming")
	}
	if _, ok := any(newDirectCandidateResolver()).(R.ProgressiveResolver); !ok {
		t.Fatal("direct resolver does not expose candidate streaming")
	}
}

func TestDirectCandidatesColdMissFallsBackInOrder(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	client := func(address string, err error, ip string) dnsClient {
		return &directCandidateClient{address: address, exchange: func(_ context.Context, query *D.Msg) (*D.Msg, error) {
			mu.Lock()
			calls = append(calls, address)
			mu.Unlock()
			if err != nil {
				return nil, err
			}
			return directAnswer(query, ip, 60), nil
		}}
	}
	r := newDirectCandidateResolver(
		client("#1", errors.New("down"), ""),
		client("#2", nil, "192.0.2.2"),
		client("#3", nil, "192.0.2.3"),
	)

	var batches int
	for batch := range r.LookupIPCandidates(context.Background(), "cold.example", false, "wlan0|192.168.0.0/16") {
		if batch.Err != nil {
			t.Fatal(batch.Err)
		}
		batches++
		if len(batch.IPs) != 1 || batch.IPs[0] != netip.MustParseAddr("192.0.2.2") || batch.Source != 1 {
			t.Fatalf("unexpected batch: %+v", batch)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if batches != 1 || len(calls) != 2 || calls[0] != "#1" || calls[1] != "#2" {
		t.Fatalf("calls=%v batches=%d", calls, batches)
	}
}

func TestDirectCandidatesStaleCachePublishesTwoSourcesIndependently(t *testing.T) {
	release1 := make(chan struct{})
	release2 := make(chan struct{})
	r := newDirectCandidateResolver(
		&directCandidateClient{address: "#1", exchange: func(_ context.Context, query *D.Msg) (*D.Msg, error) {
			<-release1
			return directAnswer(query, "192.0.2.1", 60), nil
		}},
		&directCandidateClient{address: "#2", exchange: func(_ context.Context, query *D.Msg) (*D.Msg, error) {
			<-release2
			return directAnswer(query, "192.0.2.2", 60), nil
		}},
	)
	scope := "wlan0|192.168.0.0/16"
	q := directQuestion("stale.example", false)
	key := directCacheKey(scope, q)
	staleQuery := new(D.Msg).SetQuestion(q.Name, q.Qtype)
	r.cache.SetWithExpire(key, directAnswer(staleQuery, "192.0.2.9", 60), time.Now().Add(-time.Second))

	batches := r.LookupIPCandidates(context.Background(), "stale.example", false, scope)
	retained := <-batches
	if retained.Source != -1 || !containsAddr(retained.IPs, netip.MustParseAddr("192.0.2.9")) {
		t.Fatalf("missing retained batch: %+v", retained)
	}
	close(release1)
	first := <-batches
	if first.Source != 0 || len(first.IPs) != 1 || first.IPs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("first batch: %+v", first)
	}
	close(release2)
	second := <-batches
	if second.Source != 1 || len(second.IPs) != 1 || second.IPs[0] != netip.MustParseAddr("192.0.2.2") {
		t.Fatalf("second batch: %+v", second)
	}
	if _, open := <-batches; open {
		t.Fatal("candidate stream did not close")
	}

	for source, want := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")} {
		msg, _, hit := r.sourceCaches[source].GetWithExpire(r.directSourceCacheKey(key, source))
		if !hit || len(msgToIP(msg)) != 1 || msgToIP(msg)[0] != want {
			t.Fatalf("source cache %d = %v, hit=%v", source+1, msgToIP(msg), hit)
		}
	}

	r.PromoteIP("stale.example", false, scope, netip.MustParseAddr("192.0.2.1"))
	winner, due, hit := r.cache.GetWithExpire(key)
	if !hit || msgToIP(winner)[0] != netip.MustParseAddr("192.0.2.9") || time.Now().Before(due) {
		t.Fatal("TCP winner renewed or replaced a DNS answer")
	}
}

func TestDirectCandidatesStaleCachePublishesSourceCacheBeforeRefresh(t *testing.T) {
	release1 := make(chan struct{})
	release2 := make(chan struct{})
	r := newDirectCandidateResolver(
		&directCandidateClient{address: "#1", exchange: func(_ context.Context, query *D.Msg) (*D.Msg, error) {
			<-release1
			return directAnswer(query, "192.0.2.11", 60), nil
		}},
		&directCandidateClient{address: "#2", exchange: func(_ context.Context, query *D.Msg) (*D.Msg, error) {
			<-release2
			return directAnswer(query, "192.0.2.12", 60), nil
		}},
	)
	scope := "wlan0|192.168.0.0/16"
	q := directQuestion("cached.example", false)
	key := directCacheKey(scope, q)
	query := new(D.Msg).SetQuestion(q.Name, q.Qtype)
	r.cache.SetWithExpire(key, directAnswer(query, "192.0.2.9", 60), time.Now().Add(-time.Second))
	for source, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		r.sourceCaches[source].SetWithExpire(
			r.directSourceCacheKey(key, source),
			directAnswer(query, ip, 60),
			time.Now().Add(-365*24*time.Hour),
		)
	}

	batches := r.LookupIPCandidates(context.Background(), "cached.example", false, scope)
	select {
	case first := <-batches:
		want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
		if first.Source != -1 || len(first.IPs) != len(want) {
			t.Fatalf("source-cache batch: %+v", first)
		}
		for index := range want {
			if first.IPs[index] != want[index] {
				t.Fatalf("source-cache batch IPs = %v, want %v", first.IPs, want)
			}
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("stale lookup waited for DNS refresh before publishing source cache")
	}

	close(release1)
	close(release2)
	var refreshed []netip.Addr
	for batch := range batches {
		if batch.Err != nil {
			t.Fatal(batch.Err)
		}
		refreshed = append(refreshed, batch.IPs...)
	}
	if !containsAddr(refreshed, netip.MustParseAddr("192.0.2.11")) ||
		!containsAddr(refreshed, netip.MustParseAddr("192.0.2.12")) {
		t.Fatalf("refreshed candidates = %v", refreshed)
	}
}

func TestDirectCandidatesSourceCacheIsNetworkScoped(t *testing.T) {
	release := make(chan struct{})
	r := newDirectCandidateResolver(
		&directCandidateClient{address: "#1", exchange: func(_ context.Context, query *D.Msg) (*D.Msg, error) {
			<-release
			return directAnswer(query, "192.0.2.11", 60), nil
		}},
	)
	q := directQuestion("scoped.example", false)
	query := new(D.Msg).SetQuestion(q.Name, q.Qtype)
	oldScope := "wlan0|192.168.0.0/16"
	newScope := "wlan0|10.0.0.0/24"
	oldKey := directCacheKey(oldScope, q)
	newKey := directCacheKey(newScope, q)
	r.sourceCaches[0].SetWithExpire(
		r.directSourceCacheKey(oldKey, 0),
		directAnswer(query, "192.0.2.1", 60),
		time.Now().Add(time.Hour),
	)
	r.cache.SetWithExpire(newKey, directAnswer(query, "192.0.2.9", 60), time.Now().Add(-time.Second))

	batches := r.LookupIPCandidates(context.Background(), "scoped.example", false, newScope)
	select {
	case batch := <-batches:
		if containsAddr(batch.IPs, netip.MustParseAddr("192.0.2.1")) || !containsAddr(batch.IPs, netip.MustParseAddr("192.0.2.9")) {
			t.Fatalf("wrong network's retained data: %+v", batch)
		}
	case <-time.After(25 * time.Millisecond):
		t.Fatal("current network's retained answer waited for DNS")
	}
	close(release)
	for range batches {
	}
}

func containsAddr(addrs []netip.Addr, want netip.Addr) bool {
	return slices.Contains(addrs, want)
}
