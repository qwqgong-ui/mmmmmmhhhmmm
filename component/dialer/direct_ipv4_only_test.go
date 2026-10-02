package dialer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
)

func TestIPv4StartsWhileHistoricalIPv6WinnerAwaitsDNS(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previous := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previous) })
	previousIPv6 := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previousIPv6) })
	cache.SetWithRTT(mustTCPConcurrentCacheKey(t, "ipv4-only.example", "443", "tcp"), netip.MustParseAddr("2001:db8::1"), time.Millisecond)
	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	close(v4)
	v6 := make(chan R.IPCandidateBatch) // unresolved AAAA must not hold IPv4 candidates
	defer close(v6)
	r := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 2)}
	started := make(chan struct{}, 1)
	dial := NetDialerFunc(func(context.Context, string, string) (net.Conn, error) {
		started <- struct{}{}
		client, peer := net.Pipe()
		_ = peer.Close()
		return client, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := directProgressiveDialContext(ctx, "tcp", "ipv4-only.example:443", option{netDialer: dial}, r)
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("IPv4 handshake waited for unrelated AAAA")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("IPv4 connection was not delivered")
	}
}

func TestIPv4OnlyDoesNotWaitIPv6PreferenceBudgetAfterNODATA(t *testing.T) {
	installTestTCPConcurrentCache(t)
	previousIPv6 := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previousIPv6) })
	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	close(v4)
	v6 := make(chan R.IPCandidateBatch, 1)
	v6 <- R.IPCandidateBatch{} // a complete, valid negative family result
	close(v6)
	r := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 2)}
	dial := NetDialerFunc(func(context.Context, string, string) (net.Conn, error) { c, p := net.Pipe(); p.Close(); return c, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	conn, err := directProgressiveDialContext(ctx, "tcp", "ipv4-only-prefer6.example:443", option{netDialer: dial, prefer: 6}, r)
	if err != nil {
		t.Fatal("completed empty AAAA should release IPv4 immediately:", err)
	}
	conn.Close()
}

type familyTestConn struct {
	net.Conn
	family string
}

func TestOtherFamilyStartsWithoutChangingIPv6Preference(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	previous := GetTcpConcurrent()
	SetTcpConcurrent(true)
	t.Cleanup(func() { SetTcpConcurrent(previous) })
	previousIPv6 := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previousIPv6) })
	ipv6 := netip.MustParseAddr("2001:db8::1")
	cache.SetWithRTT(mustTCPConcurrentCacheKey(t, "dualstack-prefer6.example", "443", "tcp"), ipv6, time.Millisecond)
	v4 := make(chan R.IPCandidateBatch, 1)
	v4 <- R.IPCandidateBatch{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	close(v4)
	v6 := make(chan R.IPCandidateBatch, 1)
	r := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
	v4Started := make(chan struct{}, 1)
	dial := NetDialerFunc(func(_ context.Context, _, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		c, p := net.Pipe()
		p.Close()
		if host != ipv6.String() {
			v4Started <- struct{}{}
		}
		return &familyTestConn{Conn: c, family: host}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan net.Conn, 1)
	go func() {
		c, _ := directProgressiveDialContext(ctx, "tcp", "dualstack-prefer6.example:443", option{netDialer: dial, prefer: 6}, r)
		done <- c
	}()
	select {
	case <-v4Started:
	case <-ctx.Done():
		t.Fatal("IPv4 did not start")
	}
	select {
	case c := <-done:
		if c != nil {
			c.Close()
		}
		t.Fatal("IPv4 bypassed explicit IPv6 preference")
	case <-time.After(20 * time.Millisecond):
	}
	v6 <- R.IPCandidateBatch{IPs: []netip.Addr{ipv6}}
	close(v6)
	select {
	case c := <-done:
		if c == nil {
			t.Fatal("no connection")
		}
		defer c.Close()
		if c.(*familyTestConn).family != ipv6.String() {
			t.Fatal("IPv6 preference was lost")
		}
	case <-ctx.Done():
		t.Fatal("preferred IPv6 did not connect")
	}
}
