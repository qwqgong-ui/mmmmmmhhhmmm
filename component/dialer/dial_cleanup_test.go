package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
)

type cleanupTestConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *cleanupTestConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func newCleanupTestConn(t *testing.T) *cleanupTestConn {
	t.Helper()
	client, peer := net.Pipe()
	c := &cleanupTestConn{Conn: client, closed: make(chan struct{})}
	t.Cleanup(func() { _ = c.Close(); _ = peer.Close() })
	return c
}

func requireCleanupTestClosed(t *testing.T, c *cleanupTestConn) {
	t.Helper()
	select {
	case <-c.closed:
	case <-time.After(time.Second):
		t.Fatal("unselected connection was not closed")
	}
}

func TestTCPConcurrentCacheClosesLateSuccessfulLoser(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	winnerIP := netip.MustParseAddr("192.0.2.1")
	loserIP := netip.MustParseAddr("192.0.2.2")
	for i := 0; i < 16; i++ {
		key := mustTCPConcurrentCacheKey(t, "cleanup.example", "443", "tcp")
		cache.SetWithRTT(key, winnerIP, time.Millisecond)
		cache.SetWithRTT(key, loserIP, 2*time.Millisecond)
		winner := newCleanupTestConn(t)
		loser := newCleanupTestConn(t)
		loserStarted := make(chan struct{})
		dial := NetDialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(address)
			if host == winnerIP.String() {
				<-loserStarted
				return winner, nil
			}
			close(loserStarted)
			// A connect can finish successfully as cancellation arrives.
			<-ctx.Done()
			return loser, nil
		})
		result := tcpConcurrentDialContext(context.Background(), "tcp", "cleanup.example", []netip.Addr{winnerIP, loserIP}, "443", option{netDialer: dial}, func(context.Context, string, []netip.Addr, string, option) dialResult {
			t.Error("unexpected fallback")
			return dialResult{error: context.Canceled}
		})
		if result.error != nil || result.Conn != winner {
			t.Fatalf("winner = %v, error = %v", result.Conn, result.error)
		}
		requireCleanupTestClosed(t, loser)
		select {
		case <-winner.closed:
			t.Fatal("delivered connection was closed")
		default:
		}
		_ = winner.Close()
	}
}

func TestProgressiveDirectCachedWinnerClosesHeldFallback(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previous := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previous) })
	previousIPv6 := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previousIPv6) })
	cachedIP := netip.MustParseAddr("192.0.2.1")
	fallbackIP := netip.MustParseAddr("2001:db8::1")
	key := mustTCPConcurrentCacheKey(t, "held-cleanup.example", "443", "tcp")
	cache.SetWithRTT(key, cachedIP, time.Millisecond)
	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{cachedIP}}
	close(v4)
	v6 := make(chan R.IPCandidateBatch, 1)
	v6 <- R.IPCandidateBatch{IPs: []netip.Addr{fallbackIP}}
	close(v6)
	r := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	winner := newCleanupTestConn(t)
	fallback := newCleanupTestConn(t)
	releaseCached := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCached) }) }
	t.Cleanup(release)
	dial := NetDialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == cachedIP.String() {
			select {
			case <-releaseCached:
				return winner, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return fallback, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, err := directProgressiveDialContext(ctx, "tcp", "held-cleanup.example:443", option{netDialer: dial, prefer: 4}, r)
		resultCh <- dialResult{Conn: conn, error: err}
	}()
	select {
	case ip := <-r.promoted:
		if ip != fallbackIP {
			t.Fatalf("first promoted IP = %s; want fallback", ip)
		}
	case <-ctx.Done():
		t.Fatal("fallback never connected after cached budget expired")
	}
	release()
	select {
	case result := <-resultCh:
		if result.error != nil || result.Conn != winner {
			t.Fatalf("winner = %v, error = %v", result.Conn, result.error)
		}
	case <-ctx.Done():
		t.Fatal("cached winner was not delivered")
	}
	requireCleanupTestClosed(t, fallback)
	select {
	case <-winner.closed:
		t.Fatal("delivered connection was closed")
	default:
	}
}
