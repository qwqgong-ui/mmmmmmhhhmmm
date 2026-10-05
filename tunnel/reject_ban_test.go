package tunnel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	rulecommon "github.com/metacubex/mihomo/rules/common"
)

func rejectBanMetadata() *C.Metadata {
	return &C.Metadata{
		NetWork: C.TCP,
		Type:    C.SOCKS5,
		SrcIP:   netip.MustParseAddr("192.0.2.1"),
		SrcPort: 10000,
		Host:    "rejected.example",
		DstPort: 443,
	}
}

func TestRejectBanThresholdAndFixedExpiry(t *testing.T) {
	cache := newRejectBanCache()
	key, _ := tcpRejectBanKey(rejectBanMetadata())
	proxy := newRejectBanTestProxy("REJECT", C.Reject)
	now := time.Now()
	_, generation := cache.Lookup(key, now)
	for i := range rejectBanThreshold - 1 {
		if _, banned := cache.Reject(key, generation, proxy, now.Add(time.Duration(i)*time.Millisecond)); banned {
			t.Fatalf("banned after only %d rejections", i+1)
		}
	}
	if banned, _ := cache.Lookup(key, now.Add(time.Second)); banned != nil {
		t.Fatal("fewer than ten rejections created a ban")
	}
	tenth := now.Add(time.Second)
	until, banned := cache.Reject(key, generation, proxy, tenth)
	if !banned || !until.Equal(tenth.Add(time.Minute)) {
		t.Fatalf("ban deadline = %v, created = %t", until, banned)
	}
	if banned, _ := cache.Lookup(key, until.Add(-time.Nanosecond)); banned != proxy {
		t.Fatal("ban expired before one minute")
	}
	if _, renewed := cache.Reject(key, generation, proxy, until.Add(-time.Nanosecond)); renewed {
		t.Fatal("a repeated attempt renewed the ban")
	}
	if banned, _ := cache.Lookup(key, until); banned != nil {
		t.Fatal("ban was extended by a repeated attempt")
	}
	if _, banned := cache.Reject(key, generation, proxy, until); banned {
		t.Fatal("expired ban did not restart counting from zero")
	}
}

func TestRejectBanUsesSlidingWindow(t *testing.T) {
	cache := newRejectBanCache()
	key, _ := tcpRejectBanKey(rejectBanMetadata())
	proxy := newRejectBanTestProxy("REJECT", C.Reject)
	now := time.Now()
	_, generation := cache.Lookup(key, now)
	cache.Reject(key, generation, proxy, now)
	for range 8 {
		cache.Reject(key, generation, proxy, now.Add(9*time.Second))
	}
	if _, banned := cache.Reject(key, generation, proxy, now.Add(rejectBanWindow+time.Nanosecond)); banned {
		t.Fatal("a rejection outside the ten-second window counted toward a ban")
	}
	if _, banned := cache.Reject(key, generation, proxy, now.Add(rejectBanWindow+2*time.Nanosecond)); !banned {
		t.Fatal("ten rejections spanning a fixed-window boundary did not ban")
	}
}

func TestRejectBanWindowBoundaryAndSparseAttempts(t *testing.T) {
	for _, test := range []struct {
		name     string
		interval time.Duration
		wantBan  bool
	}{
		{name: "exact boundary", interval: rejectBanWindow / 9, wantBan: true},
		{name: "sparse attempts", interval: 2 * time.Second, wantBan: false},
		{name: "expired counters", interval: rejectBanWindow + time.Second, wantBan: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := newRejectBanCache()
			key, _ := tcpRejectBanKey(rejectBanMetadata())
			proxy := newRejectBanTestProxy("REJECT", C.Reject)
			now := time.Now()
			_, generation := cache.Lookup(key, now)
			var banned bool
			for i := range rejectBanThreshold {
				when := now.Add(time.Duration(i) * test.interval)
				if test.wantBan && i == rejectBanThreshold-1 {
					when = now.Add(rejectBanWindow)
				}
				_, banned = cache.Reject(key, generation, proxy, when)
			}
			if banned != test.wantBan {
				t.Fatalf("ban = %t, want %t", banned, test.wantBan)
			}
		})
	}
}

func TestRejectBanKeyScope(t *testing.T) {
	metadata := rejectBanMetadata()
	key, ok := tcpRejectBanKey(metadata)
	if !ok {
		t.Fatal("valid TCP source/destination was not eligible")
	}
	for _, change := range []func(*C.Metadata){
		func(m *C.Metadata) { m.SrcPort++ },
		func(m *C.Metadata) { m.Host = "REJECTED.EXAMPLE." },
		func(m *C.Metadata) { m.DstIP = netip.MustParseAddr("192.0.2.99") },
		func(m *C.Metadata) { m.SrcIP = netip.MustParseAddr("::ffff:192.0.2.1") },
	} {
		m := metadata.Clone()
		change(m)
		if other, ok := tcpRejectBanKey(m); !ok || other != key {
			t.Fatal("port changes, domain spelling or resolved addresses evaded a ban")
		}
	}
	for _, change := range []func(*C.Metadata){
		func(m *C.Metadata) { m.SrcIP = netip.MustParseAddr("192.0.2.2") },
		func(m *C.Metadata) { m.Host = "allowed.example" },
		func(m *C.Metadata) { m.DstPort++ },
		func(m *C.Metadata) { m.SniffHost = "other.example" },
		func(m *C.Metadata) { m.Type = C.TUN },
		func(m *C.Metadata) { m.InIP = netip.MustParseAddr("127.0.0.1") },
		func(m *C.Metadata) { m.InPort++ },
		func(m *C.Metadata) { m.InName = "other" },
		func(m *C.Metadata) { m.InUser = "other" },
		func(m *C.Metadata) { m.SpecialProxy = "DIRECT" },
		func(m *C.Metadata) { m.SpecialRules = "other" },
		func(m *C.Metadata) { m.DSCP++ },
	} {
		m := metadata.Clone()
		change(m)
		if other, _ := tcpRejectBanKey(m); other == key {
			t.Fatal("different source, destination or routing context shared a ban")
		}
	}
	for _, change := range []func(*C.Metadata){
		func(m *C.Metadata) { m.SrcIP = netip.Addr{} },
		func(m *C.Metadata) { m.SrcIP = netip.IPv4Unspecified() },
		func(m *C.Metadata) { m.DstPort = 0 },
		func(m *C.Metadata) { m.NetWork = C.UDP },
	} {
		m := metadata.Clone()
		change(m)
		if _, ok := tcpRejectBanKey(m); ok {
			t.Fatal("unknown source, invalid destination or UDP was eligible")
		}
	}
}

func TestRejectBanResetDiscardsInFlightResults(t *testing.T) {
	cache := newRejectBanCache()
	key, _ := tcpRejectBanKey(rejectBanMetadata())
	proxy := newRejectBanTestProxy("REJECT", C.Reject)
	now := time.Now()
	_, oldGeneration := cache.Lookup(key, now)
	for range rejectBanThreshold - 1 {
		cache.Reject(key, oldGeneration, proxy, now)
	}
	cache.Reset()
	for range rejectBanThreshold {
		if _, banned := cache.Reject(key, oldGeneration, proxy, now); banned {
			t.Fatal("an old routing result restored a ban after invalidation")
		}
	}
	if len(cache.entries.Snapshot()) != 0 {
		t.Fatal("old routing results restored counters after invalidation")
	}
	_, generation := cache.Lookup(key, now)
	cache.Reject(key, generation, proxy, now)
	cache.Forget(key, oldGeneration)
	if len(cache.entries.Snapshot()) != 1 {
		t.Fatal("an old allowed result deleted new counters")
	}
}

func TestRejectBanConcurrentAttemptsCreateOneBan(t *testing.T) {
	cache := newRejectBanCache()
	key, _ := tcpRejectBanKey(rejectBanMetadata())
	proxy := newRejectBanTestProxy("REJECT", C.Reject)
	now := time.Now()
	_, generation := cache.Lookup(key, now)
	var created atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if _, banned := cache.Reject(key, generation, proxy, now); banned {
				created.Add(1)
			}
		})
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatalf("created %d bans for one burst", created.Load())
	}
	if banned, _ := cache.Lookup(key, now.Add(time.Minute)); banned != nil {
		t.Fatal("concurrent attempts extended the ban")
	}
}

func TestRejectBanBoundsCountersAndBans(t *testing.T) {
	cache := newRejectBanCache()
	metadata := rejectBanMetadata()
	key, _ := tcpRejectBanKey(metadata)
	proxy := newRejectBanTestProxy("REJECT", C.Reject)
	now := time.Now()
	_, generation := cache.Lookup(key, now)
	for range rejectBanThreshold {
		cache.Reject(key, generation, proxy, now)
	}
	for i := range maxRejectBanKeys {
		metadata.DstPort = uint16(i + 1000)
		other, _ := tcpRejectBanKey(metadata)
		cache.Reject(other, generation, proxy, now)
	}
	if size := len(cache.entries.Snapshot()); size != maxRejectBanKeys {
		t.Fatalf("cache size = %d, want %d", size, maxRejectBanKeys)
	}
	if banned, _ := cache.Lookup(key, now); banned != nil {
		t.Fatal("least recently used ban was not evicted")
	}
}

type countingRejectRule struct {
	C.Rule
	calls int
}

func (r *countingRejectRule) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	r.calls++
	return r.Rule.Match(metadata, helper)
}

// Keep tunnel tests independent of outbound's DNS -> tunnel dependency.
type rejectBanTestProxy struct {
	C.Proxy
	name       string
	kind       C.AdapterType
	selected   C.Proxy
	dials      int
	unwrapHook func()
}

func newRejectBanTestProxy(name string, kind C.AdapterType) *rejectBanTestProxy {
	return &rejectBanTestProxy{name: name, kind: kind}
}

func (p *rejectBanTestProxy) Name() string        { return p.name }
func (p *rejectBanTestProxy) Type() C.AdapterType { return p.kind }
func (p *rejectBanTestProxy) Unwrap(*C.Metadata, bool) C.Proxy {
	if p.unwrapHook != nil {
		p.unwrapHook()
	}
	return p.selected
}
func (p *rejectBanTestProxy) Adapter() C.ProxyAdapter { return p }
func (p *rejectBanTestProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if p.selected != nil {
		return p.selected.DialContext(ctx, metadata)
	}
	p.dials++
	return nil, resolver.ErrIPVersion // stop before opening a real socket
}

func setupRejectBanTunnel(t *testing.T, proxy C.Proxy, rule C.Rule) {
	t.Helper()
	oldRules, oldSubRules, oldRuleProviders := rules, subRules, ruleProviders
	oldProxies, oldProviders := proxies, providers
	oldStatus, oldMode, oldSniffing, oldBans := Status(), Mode(), sniffingEnable, defaultRejectBans
	oldLogLevel := log.Level()
	defaultRejectBans = newRejectBanCache()
	sniffingEnable = false
	log.SetLevel(log.WARNING)
	SetMode(Rule)
	OnRunning()
	UpdateRules([]C.Rule{rule}, nil, nil)
	UpdateProxies(map[string]C.Proxy{proxy.Name(): proxy}, nil)
	t.Cleanup(func() {
		UpdateRules(oldRules, oldSubRules, oldRuleProviders)
		UpdateProxies(oldProxies, oldProviders)
		SetMode(oldMode)
		status.Store(oldStatus)
		sniffingEnable, defaultRejectBans = oldSniffing, oldBans
		log.SetLevel(oldLogLevel)
	})
}

func closeRejectedTCP(t *testing.T, metadata *C.Metadata) {
	t.Helper()
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	Tunnel.HandleTCPConn(client, metadata)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client connection was not closed immediately: %v", err)
	}
}

func TestTCPRejectBanSkipsMatchingAndRepeatedLogs(t *testing.T) {
	proxy := newRejectBanTestProxy("REJECT", C.Reject)
	rule := &countingRejectRule{Rule: rulecommon.NewMatch(proxy.Name())}
	setupRejectBanTunnel(t, proxy, rule)
	subscriber := log.SubscribeLevel(log.INFO)
	defer log.UnSubscribe(subscriber)
	for i := range 100 {
		metadata := rejectBanMetadata()
		metadata.SrcPort += uint16(i)
		closeRejectedTCP(t, metadata)
	}
	if rule.calls != rejectBanThreshold {
		t.Fatalf("matched %d times, want only %d before the ban", rule.calls, rejectBanThreshold)
	}
	var connectionLogs, banLogs int
	for {
		select {
		case event := <-subscriber:
			if strings.Contains(event.Payload, "REJECT failban") {
				banLogs++
				if !strings.Contains(event.Payload, "until ") {
					t.Fatal("ban event omitted its deadline")
				}
			} else {
				connectionLogs++
			}
		default:
			if connectionLogs != rejectBanThreshold || banLogs != 1 {
				t.Fatalf("connection logs = %d, ban logs = %d", connectionLogs, banLogs)
			}
			return
		}
	}
}

func TestTCPRejectBanInvalidatesOnRoutingUpdates(t *testing.T) {
	for _, test := range []struct {
		name   string
		update func(C.Proxy, C.Rule)
	}{
		{name: "rules", update: func(_ C.Proxy, rule C.Rule) { UpdateRules([]C.Rule{rule}, nil, nil) }},
		{name: "proxies", update: func(proxy C.Proxy, _ C.Rule) {
			UpdateProxies(map[string]C.Proxy{proxy.Name(): proxy}, map[string]P.ProxyProvider{})
		}},
		{name: "mode", update: func(C.Proxy, C.Rule) { SetMode(Rule) }},
		{name: "rule provider", update: func(C.Proxy, C.Rule) { Tunnel.InvalidateRejectCache() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			proxy := newRejectBanTestProxy("REJECT", C.Reject)
			rule := &countingRejectRule{Rule: rulecommon.NewMatch(proxy.Name())}
			setupRejectBanTunnel(t, proxy, rule)
			for range rejectBanThreshold {
				closeRejectedTCP(t, rejectBanMetadata())
			}
			test.update(proxy, rule)
			closeRejectedTCP(t, rejectBanMetadata())
			if rule.calls != rejectBanThreshold+1 {
				t.Fatal("routing update left an old ban active")
			}
		})
	}
}

func TestTCPRejectBanRechecksProxyGroupSelection(t *testing.T) {
	direct := newRejectBanTestProxy("DIRECT", C.Direct)
	proxy := newRejectBanTestProxy("group", C.Selector)
	proxy.selected = newRejectBanTestProxy("REJECT", C.Reject)
	rule := &countingRejectRule{Rule: rulecommon.NewMatch(proxy.Name())}
	setupRejectBanTunnel(t, proxy, rule)
	for range rejectBanThreshold {
		closeRejectedTCP(t, rejectBanMetadata())
	}
	proxy.selected = direct
	closeRejectedTCP(t, rejectBanMetadata())
	if rule.calls != rejectBanThreshold+1 || direct.dials != 1 {
		t.Fatalf("group selection stayed banned: matches=%d, dials=%d", rule.calls, direct.dials)
	}
}

func TestTCPRejectBanDoesNotUsePolicyChangedDuringLookup(t *testing.T) {
	direct := newRejectBanTestProxy("DIRECT", C.Direct)
	group := newRejectBanTestProxy("group", C.Selector)
	group.selected = newRejectBanTestProxy("REJECT", C.Reject)
	rule := &countingRejectRule{Rule: rulecommon.NewMatch(group.Name())}
	setupRejectBanTunnel(t, group, rule)
	UpdateProxies(map[string]C.Proxy{group.Name(): group, direct.Name(): direct}, nil)
	for range rejectBanThreshold {
		closeRejectedTCP(t, rejectBanMetadata())
	}
	allowed := &countingRejectRule{Rule: rulecommon.NewMatch(direct.Name())}
	group.unwrapHook = func() { UpdateRules([]C.Rule{allowed}, nil, nil) }
	closeRejectedTCP(t, rejectBanMetadata())
	if allowed.calls != 1 || direct.dials != 1 {
		t.Fatalf("used a stale ban after policy update: matches=%d, dials=%d", allowed.calls, direct.dials)
	}
}

func BenchmarkRejectBanLookup(b *testing.B) {
	cache := newRejectBanCache()
	key, _ := tcpRejectBanKey(rejectBanMetadata())
	proxy := newRejectBanTestProxy("REJECT", C.Reject)
	now := time.Now()
	_, generation := cache.Lookup(key, now)
	for range rejectBanThreshold {
		cache.Reject(key, generation, proxy, now)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Lookup(key, now)
		}
	})
}
