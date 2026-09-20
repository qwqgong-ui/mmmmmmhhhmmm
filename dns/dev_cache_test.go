package dns

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dev_cache"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSDevCacheStaleIsImmediateAndFailureCannotReplace(t *testing.T) {
	for _, rcode := range []int{D.RcodeServerFailure, D.RcodeRefused} {
		t.Run(D.RcodeToString[rcode], func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			client := &directCandidateClient{address: "offline", exchange: func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
				calls.Add(1)
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				m := new(D.Msg).SetReply(q)
				m.Rcode = rcode
				return m, nil
			}}
			r := NewResolverFromClient(client)
			q := new(D.Msg).SetQuestion("old.example.", D.TypeA)
			key := dev_cache.ScopedKey(dev_cache.CurrentScope(), q.Question[0].String())
			due := time.Now().Add(-365 * 24 * time.Hour)
			r.cache.SetWithExpire(key, directAnswer(q, "192.0.2.1", 60), due)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			answer, err := r.ExchangeContext(ctx, q)
			require.NoError(t, err)
			require.Equal(t, uint32(3), answer.Answer[0].Header().Ttl)
			<-started
			for range 10 {
				_, err = r.ExchangeContext(ctx, q)
				require.NoError(t, err)
			}
			close(release)
			require.Eventually(t, func() bool { _, _, ok := r.cache.GetWithExpire(key); return ok && calls.Load() == 1 }, time.Second, time.Millisecond)
			stored, expiry, ok := r.cache.GetWithExpire(key)
			require.True(t, ok)
			require.Equal(t, due.Unix(), expiry.Unix())
			require.Equal(t, "192.0.2.1", stored.Answer[0].(*D.A).A.String())
		})
	}
}

func TestDomainBundleRetainsAtomicFamiliesDuringFailedRefresh(t *testing.T) {
	client, _, _ := testBundleClient(t)
	q := new(D.Msg).SetQuestion("example.com.", D.TypeA)
	_, err := client.ExchangeContext(t.Context(), q)
	require.NoError(t, err)
	key := domainKey("JP", "example.com")
	old, ok := client.cache.Get(key)
	require.True(t, ok)
	client.cache.SetWithExpire(key, old, time.Now().Add(-365*24*time.Hour))
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	client.prepare = func(string) (string, func(context.Context) (net.Conn, error), error) {
		return "JP", func(ctx context.Context) (net.Conn, error) {
			calls.Add(1)
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, errors.New("offline")
		}, nil
	}
	answer, err := client.ExchangeContext(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, uint32(3), answer.Answer[0].Header().Ttl)
	<-started
	v6 := new(D.Msg).SetQuestion("example.com.", D.TypeAAAA)
	answer, err = client.ExchangeContext(t.Context(), v6)
	require.NoError(t, err)
	require.Empty(t, answer.Answer)
	service, err := client.ExchangeContext(t.Context(), httpsQuery("example.com"))
	require.NoError(t, err)
	require.NotEmpty(t, service.Answer)
	require.EqualValues(t, 1, calls.Load())
	close(release)
}

func TestDNSDevCacheNetworkAndAddressFamilyIsolation(t *testing.T) {
	dev_cache.SetEnvironment("wifi")
	t.Cleanup(func() { dev_cache.SetEnvironment("") })
	var calls atomic.Int32
	r := NewResolverFromClient(&directCandidateClient{address: "test", exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
		calls.Add(1)
		if q.Question[0].Qtype == D.TypeAAAA {
			return directAnswer(q, "2001:db8::1", 60), nil
		}
		return directAnswer(q, "192.0.2.1", 60), nil
	}})
	for _, network := range []string{"wifi", "cell", "wifi"} {
		dev_cache.SetEnvironment(network)
		for _, typ := range []uint16{D.TypeA, D.TypeAAAA} {
			_, err := r.ExchangeContext(t.Context(), new(D.Msg).SetQuestion("same.example.", typ))
			require.NoError(t, err)
		}
	}
	require.EqualValues(t, 4, calls.Load(), "each network/family needs its own entry; switching back should reuse it")
}

func TestRuntimeCacheReattachAcrossIPv6Availability(t *testing.T) {
	config := Config{Main: []NameServer{{Addr: "127.0.0.1:54191"}}, DirectServer: []NameServer{{Addr: "127.0.0.1:54192"}}}
	first := NewResolver(config)
	RegisterPersistentCaches(first)
	q := new(D.Msg).SetQuestion("reattach.example.", D.TypeA)
	key := dev_cache.ScopedKey("environment|reattach-test", q.Question[0].String())
	first.cache.SetWithExpire(key, directAnswer(q, "192.0.2.1", 60), time.Now().Add(-time.Hour))
	config.IPv6 = true
	second := NewResolver(config)
	RegisterPersistentCaches(second)
	require.Same(t, first.cache, second.cache)
	require.Same(t, first.DirectResolver.sourceCaches[0], second.DirectResolver.sourceCaches[0])
	entry := CacheSnapshots("reattach.example")
	require.Len(t, entry, 1)
	require.True(t, entry[0].Usable)
	require.True(t, entry[0].RefreshDue)
	require.Equal(t, "environment|reattach-test", entry[0].NetworkScope)
	first.ClearCache()
	RegisterPersistentCaches(Resolvers{})
}

func TestZeroTTLSuccessIsStillAReplacement(t *testing.T) {
	q := new(D.Msg).SetQuestion("zero.example.", D.TypeA)
	msg, due := prepareCachedMessage(q.Question[0], directAnswer(q, "192.0.2.2", 0))
	require.False(t, due.IsZero(), "zero TTL means refresh due, not discard successful replacement")
	c := Config{}.newCache()
	c.SetWithExpire("key", directAnswer(q, "192.0.2.1", 60), time.Now().Add(-time.Hour))
	_, err := c.Refresh("key", time.Second, func(context.Context) (*D.Msg, time.Time, error) { return msg, due, nil })(t.Context())
	require.NoError(t, err)
	stored, ok := c.Get("key")
	require.True(t, ok)
	require.Equal(t, "192.0.2.2", stored.Answer[0].(*D.A).A.String())
}

// TestPrepareCachedMessageFloorsNegativeAnswers pins the negative-cache floor.
// An empty NOERROR has no record to take a TTL from, so minimalTTL returns 0
// and the entry lands in the cache already stale -- every later lookup then
// takes the stale branch and fires a fresh upstream refresh. That turned one
// retried destination into tens of upstream queries per second.
func TestPrepareCachedMessageFloorsNegativeAnswers(t *testing.T) {
	q := D.Question{Name: "stun6.chat.bilibili.com.", Qtype: D.TypeA, Qclass: D.ClassINET}
	empty := &D.Msg{}
	empty.SetQuestion(q.Name, q.Qtype)
	empty.Rcode = D.RcodeSuccess

	_, due := prepareCachedMessage(q, empty)
	if remaining := time.Until(due); remaining < time.Duration(negativeCacheTTL-5)*time.Second {
		t.Fatalf("empty answer cached for %v, want at least ~%ds", remaining, negativeCacheTTL)
	}

	// A real answer keeps its own TTL, including an upstream's deliberate 0.
	answered := empty.Copy()
	answered.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 0},
		A:   net.IPv4(1, 2, 3, 4),
	}}
	if _, due := prepareCachedMessage(q, answered); time.Until(due) > 5*time.Second {
		t.Fatal("answered record with TTL 0 was given the negative floor, want it respected")
	}
}
