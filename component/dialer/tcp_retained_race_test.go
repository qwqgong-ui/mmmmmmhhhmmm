package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetainedRaceCancellationPreservesWinner(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	ip, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	for range 100 {
		cache.Clear()
		cache.SetWithRTT("cancel", ip, time.Second)
		d := newTestTCPDialer(map[netip.Addr][]testDialBehavior{ip: {{}}})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan dialResult, 1)
		go func() {
			done <- tcpRetainedDialContext(ctx, "tcp", []netip.Addr{ip, other}, "443", option{netDialer: d}, "cancel", []tcpConcurrentWinner{{IP: ip, RTT: time.Second}})
		}()
		<-d.attempts
		cancel()
		result := <-done
		if !errors.Is(result.error, context.Canceled) {
			t.Fatal(result.error)
		}
		winners, ok := cache.Winners("cancel")
		if !ok || !winners[0].RetryAfter.IsZero() || d.count(other) != 0 {
			t.Fatalf("cancellation polluted cache or dialled: %+v other=%d", winners, d.count(other))
		}
	}
}

type retainedTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *retainedTrackedConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestRetainedRaceHeldFallbackCancellationClosesConnection(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	preferred, other := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")
	cache.SetWithRTT("held-cancel", preferred, time.Millisecond)
	connected := make(chan *retainedTrackedConn, 1)
	dial := NetDialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == preferred.String() {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		client, peer := net.Pipe()
		peer.Close()
		conn := &retainedTrackedConn{Conn: client}
		connected <- conn
		return conn, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan dialResult, 1)
	go func() {
		done <- tcpRetainedDialContext(ctx, "tcp", []netip.Addr{preferred, other}, "443", option{netDialer: dial, prefer: 6}, "held-cancel", []tcpConcurrentWinner{{IP: preferred, RTT: time.Millisecond}})
	}()
	conn := <-connected
	select {
	case result := <-done:
		t.Fatalf("nonpreferred delivered early: %+v", result)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	if result := <-done; !errors.Is(result.error, context.Canceled) {
		t.Fatal(result.error)
	}
	if !conn.closed.Load() {
		t.Fatal("held connection leaked")
	}
	entry, _ := cache.getEntry("held-cancel")
	for _, winner := range entry.winners {
		if winner.IP == other {
			t.Fatal("cancelled fallback promoted")
		}
	}
}

func TestRetainedRacePreferenceExpiryBeforeSuccessDoesNotWaitAgain(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	preferred, other := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.1")
	cache.SetWithRTT("late-fallback", preferred, time.Millisecond)
	gate := make(chan struct{})
	d := newTestTCPDialer(map[netip.Addr][]testDialBehavior{preferred: {{}}, other: {{release: gate}}})
	done := make(chan dialResult, 1)
	go func() {
		done <- tcpRetainedDialContext(t.Context(), "tcp", []netip.Addr{preferred, other}, "443", option{netDialer: d, prefer: 6}, "late-fallback", []tcpConcurrentWinner{{IP: preferred, RTT: time.Millisecond}})
	}()
	waitForAttemptCount(t, d, other, 1)
	time.Sleep(350 * time.Millisecond)
	start := time.Now()
	close(gate)
	select {
	case result := <-done:
		if result.error != nil {
			t.Fatal(result.error)
		}
		result.Conn.Close()
		t.Logf("success after preference expiry=%s", time.Since(start))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("preference window restarted")
	}
}

func TestRetainedRacePreferenceWindowStartsWithFullRace(t *testing.T) {
	for _, prefer := range []int{4, 6} {
		t.Run(map[int]string{4: "ipv4", 6: "ipv6"}[prefer], func(t *testing.T) {
			cache := installTestTCPConcurrentCache(t)
			v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
			preferred, other := v4, v6
			if prefer == 6 {
				preferred, other = v6, v4
			}
			cache.SetWithRTT("preference", preferred, time.Millisecond)
			gate := make(chan struct{})
			d := newTestTCPDialer(map[netip.Addr][]testDialBehavior{preferred: {{}}, other: {{release: gate}}})
			done := make(chan dialResult, 1)
			start := time.Now()
			go func() {
				done <- tcpRetainedDialContext(t.Context(), "tcp", []netip.Addr{v4, v6}, "443", option{netDialer: d, prefer: prefer}, "preference", []tcpConcurrentWinner{{IP: preferred, RTT: time.Millisecond}})
			}()
			waitForAttemptCount(t, d, other, 1)
			// Nonpreferred completes near the end of the original 300ms window.
			time.Sleep(250 * time.Millisecond)
			close(gate)
			result := <-done
			elapsed := time.Since(start)
			if result.error != nil || result.ip != other {
				t.Fatalf("%+v", result)
			}
			result.Conn.Close()
			if elapsed > 450*time.Millisecond {
				t.Fatalf("preference restarted after connect: %s", elapsed)
			}
			if d.count(preferred) != 1 || d.count(other) != 1 {
				t.Fatal("candidate redialled")
			}
			t.Logf("preference=%d delivered=%s", prefer, elapsed)
		})
	}
}

func TestRetainedRaceOriginalAttemptWinsAfterBudget(t *testing.T) {
	cache := installTestTCPConcurrentCache(t)
	ip, other := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	gate := make(chan struct{})
	d := newTestTCPDialer(map[netip.Addr][]testDialBehavior{ip: {{release: gate}}, other: {{}}})
	cache.SetWithRTT("retained", ip, time.Millisecond)
	done := make(chan dialResult, 1)
	go func() {
		done <- tcpRetainedDialContext(t.Context(), "tcp", []netip.Addr{ip, other, ip}, "443", option{netDialer: d}, "retained", []tcpConcurrentWinner{{IP: ip, RTT: time.Millisecond}})
	}()
	waitForAttemptCount(t, d, other, 1)
	close(gate)
	result := <-done
	if result.error != nil || result.ip != ip {
		t.Fatalf("%+v", result)
	}
	result.Conn.Close()
	if d.count(ip) != 1 {
		t.Fatalf("attempts=%d", d.count(ip))
	}
	winners, ok := cache.Winners("retained")
	if !ok || !winners[0].RetryAfter.IsZero() {
		t.Fatal("success did not restore winner")
	}
}
