package dialer

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
)

// The same fixture is run on the previous and updated connector. IPv4 DNS is
// ready immediately; AAAA completes after 30 ms for IPv4-only sites, or 2 ms
// for a dual-stack site. Each simulated TCP handshake takes 1 ms.
func BenchmarkDirectFamilyDelivery(b *testing.B) {
	previousCache := tcpConcurrentCache
	tcpConcurrentCache = NewTCPConcurrentCache(32, time.Minute)
	defer func() { tcpConcurrentCache = previousCache }()
	previousConcurrent := GetTcpConcurrent()
	SetTcpConcurrent(true)
	defer SetTcpConcurrent(previousConcurrent)
	previousIPv6 := R.DisableIPv6.Swap(false)
	defer R.DisableIPv6.Store(previousIPv6)
	for _, tc := range []struct {
		ipv4Only, history6 bool
		prefer             int
	}{
		{true, false, 0}, {true, true, 0}, {true, true, 6}, {false, false, 6},
	} {
		b.Run(fmt.Sprintf("ipv4Only=%t/history6=%t/prefer=%d", tc.ipv4Only, tc.history6, tc.prefer), func(b *testing.B) {
			key, _ := tcpConcurrentPathKey("family-bench.example", "443", "tcp", directNetworkScope(option{}), option{})
			ipv6 := netip.MustParseAddr("2001:db8::1")
			b.ReportAllocs()
			for range b.N {
				tcpConcurrentCache.Clear()
				if tc.history6 {
					tcpConcurrentCache.SetWithRTT(key, ipv6, time.Millisecond)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				v4 := make(chan R.IPCandidateBatch, 1)
				v4 <- R.IPCandidateBatch{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
				close(v4)
				v6 := make(chan R.IPCandidateBatch, 1)
				finished := make(chan struct{})
				go func() {
					defer close(finished)
					defer close(v6)
					wait := 2 * time.Millisecond
					if tc.ipv4Only {
						wait = 30 * time.Millisecond
					}
					timer := time.NewTimer(wait)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						return
					}
					if !tc.ipv4Only {
						v6 <- R.IPCandidateBatch{IPs: []netip.Addr{ipv6}}
					}
				}()
				r := &progressiveTestResolver{v4: v4, v6: v6, promoted: make(chan netip.Addr, 4)}
				dial := NetDialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
					timer := time.NewTimer(time.Millisecond)
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					c, p := net.Pipe()
					p.Close()
					return c, nil
				})
				conn, err := directProgressiveDialContext(ctx, "tcp", "family-bench.example:443", option{netDialer: dial, prefer: tc.prefer}, r)
				if conn != nil {
					conn.Close()
				}
				cancel()
				<-finished
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
