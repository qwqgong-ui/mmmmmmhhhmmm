package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
)

func TestTCPConcurrentCacheLifecycle(t *testing.T) {
	cache := NewTCPConcurrentCache(2, 30*time.Minute)
	now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	ipC := netip.MustParseAddr("192.0.2.3")

	cache.Set("a:443/tcp", ipA)
	cache.Set("b:443/tcp", ipB)
	if winner, loaded := cache.Get("a:443/tcp"); !loaded || winner != ipA {
		t.Fatalf("Get(a) = %s, %v; want %s, true", winner, loaded, ipA)
	}

	// Reading a makes b the least-recently used entry.
	cache.Set("c:443/tcp", ipC)
	if _, loaded := cache.Get("b:443/tcp"); loaded {
		t.Fatal("least-recently used entry was not evicted")
	}

	cache.Delete("a:443/tcp")
	if _, loaded := cache.Get("a:443/tcp"); loaded {
		t.Fatal("deleted entry still exists")
	}

	cache.Clear()
	if _, loaded := cache.Get("c:443/tcp"); loaded {
		t.Fatal("cleared entry still exists")
	}
}

func TestTCPWinnerSnapshotsDecodeScopedKey(t *testing.T) {
	cache := NewTCPConcurrentCache(4, time.Minute)
	key, ok := tcpConcurrentCacheScopedKey("Example.Test", "443", "tcp", "wlan0|192.168.0.0/16")
	if !ok {
		t.Fatal("failed to build cache key")
	}
	cache.SetWithRTT(key, netip.MustParseAddr("192.0.2.10"), 12*time.Millisecond)
	snapshots := cache.Snapshots("example.test")
	if len(snapshots) != 1 || snapshots[0].Host != "example.test" || snapshots[0].Port != "443" || snapshots[0].NetworkScope != "wlan0|192.168.0.0/16" || snapshots[0].RTTMillis != 12 {
		t.Fatalf("snapshots = %#v", snapshots)
	}
}

func TestTCPConcurrentCacheExpirationAndRefresh(t *testing.T) {
	cache := NewTCPConcurrentCache(2, 30*time.Minute)
	now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	key := "example.test:443/tcp"
	ip := netip.MustParseAddr("192.0.2.1")

	cache.Set(key, ip)
	now = now.Add(20 * time.Minute)
	cache.Set(key, ip)
	now = now.Add(20 * time.Minute)
	if winner, loaded := cache.Get(key); !loaded || winner != ip {
		t.Fatalf("refreshed entry = %s, %v; want %s, true", winner, loaded, ip)
	}

	now = now.Add(11 * time.Minute)
	if _, loaded := cache.Get(key); loaded {
		t.Fatal("expired entry was returned")
	}
}

func TestTCPConcurrentCacheKey(t *testing.T) {
	key, cacheable := tcpConcurrentCacheKey("WWW.Example.COM.", "443", "tcp")
	if !cacheable || key != "www.example.com:443/tcp" {
		t.Fatalf("cache key = %q, %v", key, cacheable)
	}
	if _, cacheable := tcpConcurrentCacheKey("192.0.2.1", "443", "tcp"); cacheable {
		t.Fatal("literal IP should not be cached")
	}
	if _, cacheable := tcpConcurrentCacheKey("example.com", "443", "udp"); cacheable {
		t.Fatal("UDP destination should not be cached")
	}
}

type testDialBehavior struct {
	release <-chan struct{}
	err     error
}

type testTCPDialer struct {
	mu        sync.Mutex
	behaviors map[netip.Addr][]testDialBehavior
	counts    map[netip.Addr]int
	attempts  chan netip.Addr
}

type staticTestResolver struct {
	R.Resolver
	ips []netip.Addr
}

func (r *staticTestResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return r.ips, nil
}

func (r *staticTestResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	var ips []netip.Addr
	for _, ip := range r.ips {
		if ip.Unmap().Is4() {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func (r *staticTestResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	var ips []netip.Addr
	for _, ip := range r.ips {
		if ip.Unmap().Is6() {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func (r *staticTestResolver) Invalid() bool { return true }

func newTestTCPDialer(behaviors map[netip.Addr][]testDialBehavior) *testTCPDialer {
	return &testTCPDialer{
		behaviors: behaviors,
		counts:    make(map[netip.Addr]int),
		attempts:  make(chan netip.Addr, 32),
	}
}

func (d *testTCPDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip := netip.MustParseAddr(host).Unmap()

	d.mu.Lock()
	index := d.counts[ip]
	d.counts[ip]++
	behaviors := d.behaviors[ip]
	behavior := testDialBehavior{err: errors.New("unexpected TCP attempt")}
	if len(behaviors) > 0 {
		if index >= len(behaviors) {
			index = len(behaviors) - 1
		}
		behavior = behaviors[index]
	}
	d.mu.Unlock()
	d.attempts <- ip

	if behavior.release == nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-behavior.release:
	}
	if behavior.err != nil {
		return nil, behavior.err
	}
	client, peer := net.Pipe()
	_ = peer.Close()
	return client, nil
}

func (d *testTCPDialer) count(ip netip.Addr) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counts[ip]
}

func closedTestGate() <-chan struct{} {
	gate := make(chan struct{})
	close(gate)
	return gate
}

func installTestTCPConcurrentCache(t *testing.T) *TCPConcurrentCache {
	t.Helper()
	previous := tcpConcurrentCache
	cache := NewTCPConcurrentCache(32, 30*time.Minute)
	tcpConcurrentCache = cache
	t.Cleanup(func() { tcpConcurrentCache = previous })
	return cache
}

func mustTCPConcurrentCacheKey(t *testing.T, host, port, network string) string {
	t.Helper()
	key, cacheable := tcpConcurrentCacheKey(host, port, network)
	if !cacheable {
		t.Fatalf("destination %s:%s/%s is not cacheable", host, port, network)
	}
	return key
}

func waitForAttemptCount(t *testing.T, dialer *testTCPDialer, ip netip.Addr, want int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if dialer.count(ip) >= want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("attempt count for %s = %d, want at least %d", ip, dialer.count(ip), want)
		case <-ticker.C:
		}
	}
}

func TestDirectDialContextUsesTCPConcurrentCache(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previousConcurrent) })
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	cache.Set(key, ipB)
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: closedTestGate()}},
		ipB: {{release: closedTestGate()}},
	})

	conn, err := DialContext(
		context.Background(),
		"tcp",
		"example.test:443",
		WithDirectDualStack(),
		WithResolver(&staticTestResolver{ips: []netip.Addr{ipA, ipB}}),
		WithNetDialer(dialer),
	)
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	_ = conn.Close()
	if dialer.count(ipA) != 0 || dialer.count(ipB) != 1 {
		t.Fatalf("attempt counts = A:%d B:%d; want A:0 B:1", dialer.count(ipA), dialer.count(ipB))
	}
}

func TestTCPConcurrentCacheMissStoresFullRaceWinner(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	blocked := make(chan struct{})
	var releaseOnce sync.Once
	releaseBlocked := func() { releaseOnce.Do(func() { close(blocked) }) }
	t.Cleanup(releaseBlocked)
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	ipC := netip.MustParseAddr("192.0.2.3")
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: blocked}},
		ipB: {{release: blocked}},
		ipC: {{release: closedTestGate()}},
	})

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB, ipC}, "443", option{netDialer: dialer}, parallelDialContext)
	if result.error != nil || result.ip != ipC {
		t.Fatalf("race result = %s, %v; want %s, nil", result.ip, result.error, ipC)
	}
	_ = result.Conn.Close()
	waitForAttemptCount(t, dialer, ipA, 1)
	waitForAttemptCount(t, dialer, ipB, 1)
	waitForAttemptCount(t, dialer, ipC, 1)
	releaseBlocked()

	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	if winner, loaded := cache.Get(key); !loaded || winner != ipC {
		t.Fatalf("cached winner = %s, %v; want %s, true", winner, loaded, ipC)
	}
}

func TestTCPConcurrentCacheHitUsesOnlyFastPathAndRefreshes(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	now := time.Date(2026, time.August, 12, 0, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	cache.Set(key, ipB)
	now = now.Add(20 * time.Minute)
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: closedTestGate()}},
		ipB: {{release: closedTestGate()}},
	})

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB}, "443", option{netDialer: dialer}, parallelDialContext)
	if result.error != nil || result.ip != ipB {
		t.Fatalf("fast-path result = %s, %v; want %s, nil", result.ip, result.error, ipB)
	}
	_ = result.Conn.Close()
	if dialer.count(ipA) != 0 || dialer.count(ipB) != 1 {
		t.Fatalf("attempt counts = A:%d B:%d; want A:0 B:1", dialer.count(ipA), dialer.count(ipB))
	}

	now = now.Add(20 * time.Minute)
	if winner, loaded := cache.Get(key); !loaded || winner != ipB {
		t.Fatalf("refreshed winner = %s, %v; want %s, true", winner, loaded, ipB)
	}
}

func TestTCPConcurrentFastPathErrorFallsBackImmediately(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	blocked := make(chan struct{})
	var releaseOnce sync.Once
	releaseBlocked := func() { releaseOnce.Do(func() { close(blocked) }) }
	t.Cleanup(releaseBlocked)
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	ipC := netip.MustParseAddr("192.0.2.3")
	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	cache.Set(key, ipB)
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: blocked}},
		ipB: {
			{release: closedTestGate(), err: errors.New("cached address failed")},
			{release: blocked},
		},
		ipC: {{release: closedTestGate()}},
	})

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB, ipC}, "443", option{netDialer: dialer}, parallelDialContext)
	if result.error != nil || result.ip != ipC {
		t.Fatalf("fallback result = %s, %v; want %s, nil", result.ip, result.error, ipC)
	}
	_ = result.Conn.Close()
	waitForAttemptCount(t, dialer, ipA, 1)
	waitForAttemptCount(t, dialer, ipB, 2)
	waitForAttemptCount(t, dialer, ipC, 1)
	releaseBlocked()
	if winner, loaded := cache.Get(key); !loaded || winner != ipC {
		t.Fatalf("replacement winner = %s, %v; want %s, true", winner, loaded, ipC)
	}
}

func TestTCPConcurrentFastPathTimeoutFallsBackToAllCandidates(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	blocked := make(chan struct{})
	var releaseOnce sync.Once
	releaseBlocked := func() { releaseOnce.Do(func() { close(blocked) }) }
	t.Cleanup(releaseBlocked)
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	ipC := netip.MustParseAddr("192.0.2.3")
	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	cache.Set(key, ipB)
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: blocked}},
		ipB: {
			{release: nil},
			{release: blocked},
		},
		ipC: {{release: closedTestGate()}},
	})

	resultChannel := make(chan dialResult, 1)
	started := time.Now()
	go func() {
		resultChannel <- tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB, ipC}, "443", option{netDialer: dialer}, parallelDialContext)
	}()
	select {
	case first := <-dialer.attempts:
		if first != ipB {
			t.Fatalf("first attempt = %s, want cached %s", first, ipB)
		}
	case <-time.After(time.Second):
		t.Fatal("cached fast path did not start")
	}
	select {
	case attempt := <-dialer.attempts:
		t.Fatalf("fallback attempt %s started before fast-path timeout", attempt)
	case <-time.After(tcpConcurrentFastPathTimeout / 2):
	}

	var result dialResult
	select {
	case result = <-resultChannel:
	case <-time.After(time.Second):
		t.Fatal("fallback did not produce a result")
	}
	if result.error != nil || result.ip != ipC {
		t.Fatalf("fallback result = %s, %v; want %s, nil", result.ip, result.error, ipC)
	}
	_ = result.Conn.Close()
	if elapsed := time.Since(started); elapsed < tcpConcurrentFastPathTimeout {
		t.Fatalf("fallback started too early: %s", elapsed)
	}
	waitForAttemptCount(t, dialer, ipA, 1)
	waitForAttemptCount(t, dialer, ipB, 2)
	waitForAttemptCount(t, dialer, ipC, 1)
	releaseBlocked()
	if winner, loaded := cache.Get(key); !loaded || winner != ipC {
		t.Fatalf("replacement winner = %s, %v; want %s, true", winner, loaded, ipC)
	}
}

func TestTCPConcurrentCachedWinnerMustRemainCandidate(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	blocked := make(chan struct{})
	var releaseOnce sync.Once
	releaseBlocked := func() { releaseOnce.Do(func() { close(blocked) }) }
	t.Cleanup(releaseBlocked)
	ipA := netip.MustParseAddr("192.0.2.1")
	staleIP := netip.MustParseAddr("192.0.2.2")
	ipC := netip.MustParseAddr("192.0.2.3")
	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	cache.Set(key, staleIP)
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: blocked}},
		ipC: {{release: closedTestGate()}},
	})

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipC}, "443", option{netDialer: dialer}, parallelDialContext)
	if result.error != nil || result.ip != ipC {
		t.Fatalf("fallback result = %s, %v; want %s, nil", result.ip, result.error, ipC)
	}
	_ = result.Conn.Close()
	waitForAttemptCount(t, dialer, ipA, 1)
	waitForAttemptCount(t, dialer, ipC, 1)
	releaseBlocked()
	if dialer.count(staleIP) != 0 {
		t.Fatalf("stale cached address was dialed %d times", dialer.count(staleIP))
	}
	if winner, loaded := cache.Get(key); !loaded || winner != ipC {
		t.Fatalf("replacement winner = %s, %v; want %s, true", winner, loaded, ipC)
	}
}

func TestTCPConcurrentDoesNotCacheFailedFallback(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	cache.Set(key, ipB)
	failure := errors.New("dial failed")
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: closedTestGate(), err: failure}},
		ipB: {
			{release: closedTestGate(), err: failure},
			{release: closedTestGate(), err: failure},
		},
	})

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB}, "443", option{netDialer: dialer}, parallelDialContext)
	if result.error == nil {
		t.Fatal("failed full race returned nil error")
	}
	if _, loaded := cache.Get(key); loaded {
		t.Fatal("failed fallback left a cached winner")
	}
}

func TestFastPathTimeoutForBounds(t *testing.T) {
	cases := []struct {
		name string
		rtt  time.Duration
		want time.Duration
	}{
		{"no sample uses default", 0, tcpConcurrentFastPathTimeout},
		{"tiny rtt is floored", time.Millisecond, minFastPathTimeout},
		{"typical rtt is tripled", 40 * time.Millisecond, 120 * time.Millisecond},
		{"huge rtt is capped", 10 * time.Second, maxFastPathTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fastPathTimeoutFor(c.rtt); got != c.want {
				t.Fatalf("fastPathTimeoutFor(%s) = %s, want %s", c.rtt, got, c.want)
			}
		})
	}
}

func TestTCPConcurrentCacheRTTSample(t *testing.T) {
	cache := NewTCPConcurrentCache(2, 30*time.Minute)
	ip := netip.MustParseAddr("192.0.2.1")
	key := "example.test:443/tcp"

	if _, loaded := cache.RTT(key); loaded {
		t.Fatal("RTT should be absent before any sample is recorded")
	}

	cache.Set(key, ip)
	if _, loaded := cache.RTT(key); loaded {
		t.Fatal("plain Set must not fabricate an RTT sample")
	}

	cache.SetWithRTT(key, ip, 25*time.Millisecond)
	if rtt, loaded := cache.RTT(key); !loaded || rtt != 25*time.Millisecond {
		t.Fatalf("RTT = %s, %v; want 25ms, true", rtt, loaded)
	}
}

func TestTCPConcurrentDialContextRecordsRTTSample(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: closedTestGate()}},
		ipB: {{release: closedTestGate()}},
	})

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB}, "443", option{netDialer: dialer}, parallelDialContext)
	if result.error != nil {
		t.Fatalf("race failed: %v", result.error)
	}
	_ = result.Conn.Close()

	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	if rtt, loaded := cache.RTT(key); !loaded || rtt <= 0 {
		t.Fatalf("RTT sample = %s, %v; want a positive duration", rtt, loaded)
	}
}

func TestTCPConcurrentDualStackRTTSampleExcludesHoldWait(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")

	// ipv4 is the preferred family but takes 50ms to fail; ipv6 wins almost
	// instantly but, being non-preferred, dualStackDialContext holds it until
	// ipv4 is resolved (success, failure, or the fallback ticker) before
	// returning it. The RTT sample must reflect ipv6's own ~0ms connect time,
	// not the ~50ms the winner spent waiting to be released.
	slowFail := make(chan struct{})
	time.AfterFunc(50*time.Millisecond, func() { close(slowFail) })
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipv4: {{release: slowFail, err: errors.New("ipv4 failed")}},
		ipv6: {{release: closedTestGate()}},
	})

	fallback := func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) dialResult {
		return dualStackDialContext(ctx, parallelDialContext, network, ips, port, opt)
	}

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipv4, ipv6}, "443", option{netDialer: dialer, prefer: 4}, fallback)
	if result.error != nil || result.ip != ipv6 {
		t.Fatalf("result = %s, %v; want %s, nil", result.ip, result.error, ipv6)
	}
	_ = result.Conn.Close()

	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	rtt, loaded := cache.RTT(key)
	if !loaded {
		t.Fatal("expected an RTT sample to be recorded")
	}
	if rtt >= 40*time.Millisecond {
		t.Fatalf("RTT sample = %s; want it close to ipv6's own connect time, not inflated by ipv4's 50ms failure", rtt)
	}
}

func TestParallelDialContextRacesWithoutTFOAndMeasuresRTT(t *testing.T) {
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	slow := make(chan struct{})
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: slow}},
		ipB: {{release: slow, err: errors.New("ipB failed")}},
	})
	time.AfterFunc(20*time.Millisecond, func() { close(slow) })

	// Racing more than one candidate must ignore opt.tfo and still produce a
	// real, positive RTT sample, just like the single-candidate fast path.
	result := parallelDialContext(context.Background(), "tcp", []netip.Addr{ipA, ipB}, "443", option{netDialer: dialer, tfo: true})
	if result.error != nil || result.ip != ipA {
		t.Fatalf("result = %s, %v; want %s, nil", result.ip, result.error, ipA)
	}
	_ = result.Conn.Close()
	// The timer is armed just before the dial, so dialDuration lands a hair
	// under 20ms; the point is that it reflects the real connect wait rather
	// than a TFO-stub near-zero value.
	if result.dialDuration < 15*time.Millisecond {
		t.Fatalf("dialDuration = %s; want it to reflect the real ~20ms connect wait, not a TFO-stub near-zero value", result.dialDuration)
	}
}

func TestParallelDialContextSingleIPDisablesTFO(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	slow := make(chan struct{})
	time.AfterFunc(20*time.Millisecond, func() { close(slow) })
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ip: {{release: slow}},
	})

	result := parallelDialContext(context.Background(), "tcp", []netip.Addr{ip}, "443", option{netDialer: dialer, tfo: true})
	if result.error != nil {
		t.Fatalf("result error = %v", result.error)
	}
	_ = result.Conn.Close()
	if result.dialDuration < 15*time.Millisecond {
		t.Fatalf("dialDuration = %s; want real handshake timing despite opt.tfo", result.dialDuration)
	}
}

func TestTCPConcurrentDialContextRacesWithoutTFOAndRecordsRTT(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: closedTestGate()}},
		ipB: {{release: closedTestGate()}},
	})

	// Even with opt.tfo set, a fresh full race (more than one candidate,
	// no cached winner yet) must ignore it for the race itself and record a
	// real RTT sample, per the fix in parallelDialContext.
	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB}, "443", option{netDialer: dialer, tfo: true}, parallelDialContext)
	if result.error != nil {
		t.Fatalf("race failed: %v", result.error)
	}
	_ = result.Conn.Close()

	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	if _, loaded := cache.Get(key); !loaded {
		t.Fatal("winner should be cached for fast-path reuse")
	}
	if rtt, loaded := cache.RTT(key); !loaded || rtt <= 0 {
		t.Fatalf("RTT sample = %s, %v; want a positive duration even with opt.tfo set", rtt, loaded)
	}
}

func TestTCPConcurrentFastPathDisablesTFO(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	ipA := netip.MustParseAddr("192.0.2.1")
	ipB := netip.MustParseAddr("192.0.2.2")
	key := mustTCPConcurrentCacheKey(t, "example.test", "443", "tcp")
	cache.Set(key, ipB)
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipA: {{release: closedTestGate()}},
		ipB: {{release: closedTestGate()}},
	})

	result := tcpConcurrentDialContext(context.Background(), "tcp", "example.test", []netip.Addr{ipA, ipB}, "443", option{netDialer: dialer, tfo: true}, parallelDialContext)
	if result.error != nil || result.ip != ipB {
		t.Fatalf("fast-path result = %s, %v; want %s, nil", result.ip, result.error, ipB)
	}
	_ = result.Conn.Close()
	if rtt, loaded := cache.RTT(key); !loaded || rtt <= 0 {
		t.Fatal("fast-path must record a real RTT despite opt.tfo")
	}
}

func TestDualStackConcurrentReturnsPreferredWinnerIP(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")
	dialer := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		ipv4: {{release: closedTestGate()}},
		ipv6: {{release: closedTestGate()}},
	})

	result := dualStackDialContext(context.Background(), parallelDialContext, "tcp", []netip.Addr{ipv4, ipv6}, "443", option{netDialer: dialer, prefer: 6})
	if result.error != nil || result.ip != ipv6 {
		t.Fatalf("dual-stack result = %s, %v; want %s, nil", result.ip, result.error, ipv6)
	}
	_ = result.Conn.Close()
}

func TestTCPConcurrentCacheKeepsTwoFastestWinners(t *testing.T) {
	cache := NewTCPConcurrentCache(4, 30*time.Minute)
	key := "example.test:443/tcp"
	slow := netip.MustParseAddr("192.0.2.3")
	fast := netip.MustParseAddr("192.0.2.1")
	middle := netip.MustParseAddr("192.0.2.2")

	cache.SetWithRTT(key, slow, 30*time.Millisecond)
	cache.SetWithRTT(key, fast, 5*time.Millisecond)
	winners, loaded := cache.Winners(key)
	if !loaded || len(winners) != 2 {
		t.Fatalf("winners = %v, loaded=%v; want two entries", winners, loaded)
	}
	if winners[0].IP != fast || winners[1].IP != slow {
		t.Fatalf("winners = %v; want fastest first", winners)
	}
	if got, _ := cache.Get(key); got != fast {
		t.Fatalf("Get = %s, want the fastest winner %s", got, fast)
	}

	// A third address displaces the slowest one, never the fastest.
	cache.SetIfFaster(key, middle, 10*time.Millisecond)
	winners, _ = cache.Winners(key)
	if len(winners) != tcpConcurrentWinnersKept {
		t.Fatalf("winners = %v; want the list capped at %d", winners, tcpConcurrentWinnersKept)
	}
	if winners[0].IP != fast || winners[1].IP != middle {
		t.Fatalf("winners = %v; want %s then %s", winners, fast, middle)
	}

	// A repeat success without a sample must not erase the latency held.
	cache.Set(key, fast)
	winners, _ = cache.Winners(key)
	if winners[0].IP != fast || winners[0].RTT != 5*time.Millisecond {
		t.Fatalf("winners = %v; want %s to keep its 5ms sample", winners, fast)
	}
}

func TestTCPConcurrentCacheRemoveKeepsRemainingWinner(t *testing.T) {
	cache := NewTCPConcurrentCache(4, 30*time.Minute)
	key := "example.test:443/tcp"
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("192.0.2.2")
	cache.SetWithRTT(key, first, 5*time.Millisecond)
	cache.SetWithRTT(key, second, 9*time.Millisecond)

	cache.Remove(key, first)
	winners, loaded := cache.Winners(key)
	if !loaded || len(winners) != 1 || winners[0].IP != second {
		t.Fatalf("winners after removing %s = %v, loaded=%v; want only %s", first, winners, loaded, second)
	}

	cache.Remove(key, second)
	if winners, loaded := cache.Winners(key); loaded || winners != nil {
		t.Fatalf("winners after removing the last one = %v, loaded=%v; want the entry gone", winners, loaded)
	}
}
