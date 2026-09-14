package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
)

type progressiveTestResolver struct {
	v4       chan R.IPCandidateBatch
	v6       chan R.IPCandidateBatch
	promoted chan netip.Addr
}

func (r *progressiveTestResolver) LookupIPCandidates(_ context.Context, _ string, ipv6 bool, _ string) <-chan R.IPCandidateBatch {
	if ipv6 {
		return r.v6
	}
	return r.v4
}

func (r *progressiveTestResolver) PromoteIP(_ string, _ bool, _ string, ip netip.Addr) {
	r.promoted <- ip.Unmap()
}

func TestProgressiveDirectReturnsFirstDNSRaceAndAcceptsLaterFasterSource(t *testing.T) {
	ClearTCPConcurrentCache()
	t.Cleanup(ClearTCPConcurrentCache)
	v4 := make(chan R.IPCandidateBatch, 2)
	v6 := make(chan R.IPCandidateBatch)
	close(v6)
	progressive := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	firstIP := netip.MustParseAddr("192.0.2.1")
	laterIP := netip.MustParseAddr("192.0.2.2")
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{firstIP}, Source: 0}

	dial := NetDialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		delay := 25 * time.Millisecond
		if host == laterIP.String() {
			delay = 5 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
		client, peer := net.Pipe()
		go func() {
			<-ctx.Done()
			_ = peer.Close()
		}()
		return client, nil
	})

	conn, err := directProgressiveDialContext(context.Background(), "tcp", "race.example:443", option{netDialer: dial}, progressive)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case got := <-progressive.promoted:
		if got != firstIP {
			t.Fatalf("first promoted IP = %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first DNS source did not start TCP promptly")
	}

	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{laterIP}, Source: 1}
	close(v4)
	select {
	case got := <-progressive.promoted:
		if got != laterIP {
			t.Fatalf("later promoted IP = %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("later DNS source did not refresh the TCP winner")
	}

	key, ok := tcpConcurrentCacheScopedKey("race.example", "443", "tcp", directNetworkScope(option{}))
	if !ok {
		t.Fatal("missing TCP winner cache key")
	}
	winner, loaded := tcpConcurrentCache.Get(key)
	if !loaded || winner != laterIP {
		t.Fatalf("TCP winner = %s, loaded=%v", winner, loaded)
	}
}

func TestProgressiveDirectUsesTCPConcurrentWinnerBeforeStaleCandidates(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previousConcurrent) })
	SetDirectNetworkEnvironment("tcp-cache-test")
	t.Cleanup(func() { SetDirectNetworkEnvironment("") })

	cachedIP := netip.MustParseAddr("192.0.2.2")
	otherIP := netip.MustParseAddr("192.0.2.1")
	key, ok := tcpConcurrentCacheScopedKey("stale.example", "443", "tcp", "environment|tcp-cache-test")
	if !ok {
		t.Fatal("missing scoped TCP winner cache key")
	}
	cache.SetWithRTT(key, cachedIP, 5*time.Millisecond)

	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{otherIP, cachedIP}, Source: -1}
	close(v4)
	v6 := make(chan R.IPCandidateBatch)
	close(v6)
	progressive := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	dial := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		otherIP:  {{release: blocked}},
		cachedIP: {{release: closedTestGate()}},
	})

	conn, err := directProgressiveDialContext(context.Background(), "tcp", "stale.example:443", option{netDialer: dial}, progressive)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	time.Sleep(10 * time.Millisecond)
	if dial.count(cachedIP) != 1 || dial.count(otherIP) != 0 {
		t.Fatalf("attempt counts = cached:%d other:%d; want cached:1 other:0", dial.count(cachedIP), dial.count(otherIP))
	}
	if winner, loaded := cache.Get(key); !loaded || winner != cachedIP {
		t.Fatalf("TCP winner = %s, loaded=%v; want %s, true", winner, loaded, cachedIP)
	}
}

func TestProgressiveDirectTCPConcurrentFailureFallsBackToAllCandidates(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previousConcurrent) })
	SetDirectNetworkEnvironment("tcp-cache-fallback-test")
	t.Cleanup(func() { SetDirectNetworkEnvironment("") })

	cachedIP := netip.MustParseAddr("192.0.2.2")
	otherIP := netip.MustParseAddr("192.0.2.1")
	key, ok := tcpConcurrentCacheScopedKey("fallback.example", "443", "tcp", "environment|tcp-cache-fallback-test")
	if !ok {
		t.Fatal("missing scoped TCP winner cache key")
	}
	cache.SetWithRTT(key, cachedIP, 5*time.Millisecond)

	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{otherIP, cachedIP}, Source: -1}
	close(v4)
	v6 := make(chan R.IPCandidateBatch)
	close(v6)
	progressive := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	dial := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		otherIP: {{release: closedTestGate()}},
		cachedIP: {
			{release: closedTestGate(), err: errors.New("cached address failed")},
			{release: blocked},
		},
	})

	conn, err := directProgressiveDialContext(context.Background(), "tcp", "fallback.example:443", option{netDialer: dial}, progressive)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	waitForAttemptCount(t, dial, otherIP, 1)
	// The refused address is never dialed again: the fallback race covers the
	// candidates that have not been tried, not the one that just failed.
	if dial.count(cachedIP) != 1 {
		t.Fatalf("attempts for refused cached address = %d, want 1", dial.count(cachedIP))
	}
	if winner, loaded := cache.Get(key); !loaded || winner != otherIP {
		t.Fatalf("replacement TCP winner = %s, loaded=%v; want %s, true", winner, loaded, otherIP)
	}
}

func TestProgressiveDirectTCPConcurrentTimeoutFallsBackToAllCandidates(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previousConcurrent) })
	SetDirectNetworkEnvironment("tcp-cache-timeout-test")
	t.Cleanup(func() { SetDirectNetworkEnvironment("") })

	cachedIP := netip.MustParseAddr("192.0.2.2")
	otherIP := netip.MustParseAddr("192.0.2.1")
	key, ok := tcpConcurrentCacheScopedKey("timeout.example", "443", "tcp", "environment|tcp-cache-timeout-test")
	if !ok {
		t.Fatal("missing scoped TCP winner cache key")
	}
	cache.SetWithRTT(key, cachedIP, time.Millisecond)

	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{otherIP, cachedIP}, Source: -1}
	close(v4)
	v6 := make(chan R.IPCandidateBatch)
	close(v6)
	progressive := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	dial := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		otherIP: {{release: closedTestGate()}},
		cachedIP: {
			{release: nil},
			{release: blocked},
		},
	})

	started := time.Now()
	conn, err := directProgressiveDialContext(context.Background(), "tcp", "timeout.example:443", option{netDialer: dial}, progressive)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if elapsed := time.Since(started); elapsed < minFastPathTimeout {
		t.Fatalf("fallback started before cached fast-path timeout: %s", elapsed)
	}
	waitForAttemptCount(t, dial, otherIP, 1)
	// The timed-out attempt keeps running rather than being cancelled and
	// re-issued, so the address is only ever dialed once.
	if dial.count(cachedIP) != 1 {
		t.Fatalf("attempts for timed-out cached address = %d, want 1", dial.count(cachedIP))
	}
	if winner, loaded := cache.Get(key); !loaded || winner != otherIP {
		t.Fatalf("replacement TCP winner = %s, loaded=%v; want %s, true", winner, loaded, otherIP)
	}
}

func TestProgressiveDirectIgnoresCachedWinnerFromUnavailableFamily(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previousConcurrent) })
	SetDirectNetworkEnvironment("tcp-cache-family-test")
	t.Cleanup(func() { SetDirectNetworkEnvironment("") })

	cachedIPv6 := netip.MustParseAddr("2001:db8::2")
	currentIPv4 := netip.MustParseAddr("192.0.2.1")
	key, ok := tcpConcurrentCacheScopedKey("family.example", "443", "tcp4", "environment|tcp-cache-family-test")
	if !ok {
		t.Fatal("missing scoped TCP winner cache key")
	}
	cache.SetWithRTT(key, cachedIPv6, 5*time.Millisecond)

	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{currentIPv4}, Source: -1}
	close(v4)
	v6 := make(chan R.IPCandidateBatch)
	close(v6)
	progressive := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	dial := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		currentIPv4: {{release: closedTestGate()}},
		cachedIPv6:  {{release: closedTestGate()}},
	})

	conn, err := directProgressiveDialContext(context.Background(), "tcp4", "family.example:443", option{netDialer: dial}, progressive)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dial.count(currentIPv4) != 1 || dial.count(cachedIPv6) != 0 {
		t.Fatalf("attempt counts = current:%d unavailable:%d; want current:1 unavailable:0", dial.count(currentIPv4), dial.count(cachedIPv6))
	}
	if winner, loaded := cache.Get(key); !loaded || winner != currentIPv4 {
		t.Fatalf("replacement TCP winner = %s, loaded=%v; want %s, true", winner, loaded, currentIPv4)
	}
}

func TestScopeForPrefixesUsesRequestedPrivate16Boundary(t *testing.T) {
	scopeA := scopeForPrefixes("wlan0", []netip.Prefix{netip.MustParsePrefix("192.168.12.34/24")})
	scopeB := scopeForPrefixes("wlan0", []netip.Prefix{netip.MustParsePrefix("192.168.99.8/24")})
	scopeC := scopeForPrefixes("wlan0", []netip.Prefix{netip.MustParsePrefix("192.169.1.8/24")})
	if scopeA != "ipv4-private|192.168.0.0/16" || scopeB != scopeA {
		t.Fatalf("192.168 /16 scopes: A=%q B=%q", scopeA, scopeB)
	}
	if scopeC == scopeA {
		t.Fatalf("different /16 unexpectedly shared scope %q", scopeC)
	}
}

func TestDirectNetworkScopePrefersPlatformEnvironment(t *testing.T) {
	SetDirectNetworkEnvironment("wifi-fingerprint")
	t.Cleanup(func() { SetDirectNetworkEnvironment("") })
	if got := directNetworkScope(option{interfaceName: "ignored"}); got != "environment|wifi-fingerprint" {
		t.Fatalf("direct network scope = %q", got)
	}
}

func TestProgressiveDirectRacesBothCachedWinners(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previousConcurrent) })
	SetDirectNetworkEnvironment("tcp-cache-second-test")
	t.Cleanup(func() { SetDirectNetworkEnvironment("") })

	deadIP := netip.MustParseAddr("192.0.2.2")
	spareIP := netip.MustParseAddr("192.0.2.3")
	otherIP := netip.MustParseAddr("192.0.2.1")
	key, ok := tcpConcurrentCacheScopedKey("second.example", "443", "tcp", "environment|tcp-cache-second-test")
	if !ok {
		t.Fatal("missing scoped TCP winner cache key")
	}
	cache.SetWithRTT(key, deadIP, 5*time.Millisecond)
	cache.SetWithRTT(key, spareIP, 9*time.Millisecond)

	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{otherIP, deadIP, spareIP}, Source: -1}
	close(v4)
	v6 := make(chan R.IPCandidateBatch)
	close(v6)
	progressive := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	blocked := make(chan struct{})
	t.Cleanup(func() { close(blocked) })
	dial := newTestTCPDialer(map[netip.Addr][]testDialBehavior{
		otherIP: {{release: blocked}},
		// The faster cached winner is a black hole: it never answers and
		// never reports an error, so only racing its peer can settle this.
		deadIP:  {{release: nil}},
		spareIP: {{release: closedTestGate()}},
	})

	started := time.Now()
	conn, err := directProgressiveDialContext(context.Background(), "tcp", "second.example:443", option{netDialer: dial}, progressive)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// Both winners start together, so the dead one costs nothing: waiting out
	// its budget first would have taken at least minFastPathTimeout.
	if elapsed >= minFastPathTimeout {
		t.Fatalf("dial took %s; the second winner was not raced alongside the first", elapsed)
	}
	// The black hole is dialled by a goroutine the returning dial does not wait
	// for: the spare winner answers immediately, so directProgressiveDialContext
	// can return before the dead one's attempt has been recorded. Wait for both
	// to land before asserting that each was tried exactly once.
	waitForAttemptCount(t, dial, deadIP, 1)
	waitForAttemptCount(t, dial, spareIP, 1)
	if dial.count(deadIP) != 1 || dial.count(spareIP) != 1 {
		t.Fatalf("attempt counts = dead:%d spare:%d; want 1 and 1", dial.count(deadIP), dial.count(spareIP))
	}
	// The candidates held behind the fast path are never released.
	if dial.count(otherIP) != 0 {
		t.Fatalf("attempts for the held candidate = %d, want 0", dial.count(otherIP))
	}
	// The black hole is pruned when the shared budget expires, even though
	// the destination was already settled by its peer.
	deadline := time.Now().Add(time.Second)
	for {
		winners, loaded := cache.Winners(key)
		if loaded && len(winners) == 1 && winners[0].IP == spareIP {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("winners = %v, loaded=%v; want only %s", winners, loaded, spareIP)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProgressiveDirectRecordsRunnerUpAsSecondWinner(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previousConcurrent) })
	SetDirectNetworkEnvironment("tcp-cache-runnerup-test")
	t.Cleanup(func() { SetDirectNetworkEnvironment("") })

	fastIP := netip.MustParseAddr("192.0.2.1")
	slowIP := netip.MustParseAddr("192.0.2.2")
	key, ok := tcpConcurrentCacheScopedKey("runnerup.example", "443", "tcp", "environment|tcp-cache-runnerup-test")
	if !ok {
		t.Fatal("missing scoped TCP winner cache key")
	}

	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{fastIP, slowIP}, Source: -1}
	close(v4)
	v6 := make(chan R.IPCandidateBatch)
	close(v6)
	progressive := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}

	dial := NetDialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		delay := 5 * time.Millisecond
		if host == slowIP.String() {
			delay = 25 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	})

	conn, err := directProgressiveDialContext(context.Background(), "tcp", "runnerup.example:443", option{netDialer: dial}, progressive)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	// One race has to leave both a winner and a runner-up behind, otherwise
	// the fast path never has a second address to fall back on.
	deadline := time.Now().Add(time.Second)
	for {
		winners, loaded := cache.Winners(key)
		if loaded && len(winners) == 2 && winners[0].IP == fastIP && winners[1].IP == slowIP {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("winners = %v, loaded=%v; want %s then %s", winners, loaded, fastIP, slowIP)
		}
		time.Sleep(time.Millisecond)
	}
}
