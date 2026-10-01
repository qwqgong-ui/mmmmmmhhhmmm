package dialer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestConcurrentTCPRacesEveryAddress(t *testing.T) {
	ips := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"),
	}
	previous := GetTcpConcurrent()
	t.Cleanup(func() { SetTcpConcurrent(previous) })
	for _, globalConcurrent := range []bool{false, true} {
		SetTcpConcurrent(globalConcurrent)
		for _, winner := range []netip.Addr{ips[1], ips[3]} {
			t.Run(winner.String()+"/global="+map[bool]string{false: "false", true: "true"}[globalConcurrent], func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				ready := make(chan struct{})
				attempts := make(chan netip.Addr, len(ips))
				stopped := make(chan struct{}, len(ips)-1)
				left, right := net.Pipe()
				defer left.Close()
				defer right.Close()
				lookup := &controlledLookup{v4Gate: closedGate(), v6Gate: closedGate(), v4: ips[:2], v6: ips[2:]}
				dial := NetDialerFunc(func(ctx context.Context, _, address string) (net.Conn, error) {
					host, _, _ := net.SplitHostPort(address)
					ip := netip.MustParseAddr(host)
					attempts <- ip
					if ip == winner {
						select {
						case <-ready:
							return left, nil
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					<-ctx.Done()
					stopped <- struct{}{}
					return nil, ctx.Err()
				})
				result := make(chan net.Conn, 1)
				go func() {
					conn, err := DialContext(ctx, "tcp", "dns-race.test:853", WithResolver(lookup), WithNetDialer(dial), WithConcurrentTCP(), WithPreferIPv6())
					if err != nil {
						t.Errorf("dial: %v", err)
					}
					result <- conn
				}()
				seen := make(map[netip.Addr]bool)
				for range ips {
					seen[receiveAttempt(t, attempts)] = true
				}
				if len(seen) != len(ips) {
					t.Fatalf("attempted %v, want all %v", seen, ips)
				}
				close(ready)
				select {
				case conn := <-result:
					if conn != left {
						t.Fatal("did not return the first successful connection")
					}
				case <-time.After(100 * time.Millisecond):
					t.Fatal("fastest address was held for a family preference")
				}
				for range len(ips) - 1 {
					select {
					case <-stopped:
					case <-ctx.Done():
						t.Fatal("losing attempts were not canceled")
					}
				}
			})
		}
	}
}
