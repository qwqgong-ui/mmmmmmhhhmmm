package outbound

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type delayedDirectUDPResolver struct {
	resolver.Resolver
	release chan struct{}
	done    chan struct{}
}

func (*delayedDirectUDPResolver) Invalid() bool { return true }
func (*delayedDirectUDPResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}
func (r *delayedDirectUDPResolver) LookupIPv6(ctx context.Context, _ string) ([]netip.Addr, error) {
	defer close(r.done)
	select {
	case <-r.release:
		return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestDirectUDPProgressiveStartsBeforeSlowAAAAAndReplays(t *testing.T) {
	oldResolver, oldDisabled := resolver.DirectHostResolver, resolver.DisableIPv6.Load()
	r := &delayedDirectUDPResolver{release: make(chan struct{}), done: make(chan struct{})}
	resolver.DirectHostResolver = r
	resolver.DisableIPv6.Store(false)
	t.Cleanup(func() { resolver.DirectHostResolver = oldResolver; resolver.DisableIPv6.Store(oldDisabled) })
	v4, v6 := newDirectUDPTestConn(), newDirectUDPTestConn()
	race := newDirectUDPRacePacketConn(func(_ context.Context, family int, _ netip.AddrPort) (net.PacketConn, error) {
		if family == 4 {
			return v4, nil
		}
		return v6, nil
	})
	t.Cleanup(func() { _ = race.Close() })
	metadata := &C.Metadata{Host: "progressive-udp.example", DstPort: 443}
	setup, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := NewDirect().registerProgressiveUDPTarget(setup, race, metadata); err != nil {
		cancel()
		t.Fatalf("first family waited for blocked AAAA: %v", err)
	}
	cancel() // Setup cancellation must not cancel the remaining candidate work.
	logical := metadata.AddrPort()
	payload := []byte("opening-datagram")
	if _, err := race.WriteTo(payload, net.UDPAddrFromAddrPort(logical)); err != nil {
		t.Fatal(err)
	}
	if got := v4.destinations(); len(got) != 1 || got[0] != logical {
		t.Fatalf("first datagram destinations = %v", got)
	}
	// Caller buffers can be reused immediately after WriteTo.
	for i := range payload {
		payload[i] = 'x'
	}
	close(r.release)
	deadline := time.Now().Add(time.Second)
	for len(v6.destinations()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := v6.destinations(); len(got) != 1 || got[0] != directUDPTestAddr("2001:db8::1", 443) {
		t.Fatalf("late AAAA did not receive opening datagram: %v", got)
	}
	v6.mu.Lock()
	replayed := string(v6.payloads[0])
	v6.mu.Unlock()
	if replayed != "opening-datagram" {
		t.Fatalf("replay retained caller's reused buffer: %q", replayed)
	}
	v6.inject("reply", directUDPTestAddr("2001:db8::1", 443))
	data, put, from, err := race.WaitReadFrom()
	if put != nil {
		defer put()
	}
	if err != nil || string(data) != "reply" || from.(*net.UDPAddr).AddrPort() != logical {
		t.Fatalf("late family reply = %q, %v, %v", data, from, err)
	}
}

func TestDirectUDPProgressiveCloseCancelsSlowFamily(t *testing.T) {
	oldResolver, oldDisabled := resolver.DirectHostResolver, resolver.DisableIPv6.Load()
	r := &delayedDirectUDPResolver{release: make(chan struct{}), done: make(chan struct{})}
	resolver.DirectHostResolver = r
	resolver.DisableIPv6.Store(false)
	t.Cleanup(func() { resolver.DirectHostResolver = oldResolver; resolver.DisableIPv6.Store(oldDisabled) })
	race, _ := newDirectUDPTestRace(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := NewDirect().registerProgressiveUDPTarget(ctx, race, &C.Metadata{Host: "close-udp.example", DstPort: 443}); err != nil {
		t.Fatal(err)
	}
	_ = race.Close()
	select {
	case <-r.done:
	case <-time.After(time.Second):
		t.Fatal("closing association left AAAA lookup running")
	}
}

func TestDirectUDPLateCandidatesDoNotReplayAfterWinner(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	logical := directUDPTestAddr("192.0.2.1", 443)
	if err := race.register(context.Background(), logical, []netip.AddrPort{logical}, "", ""); err != nil {
		t.Fatal(err)
	}
	race.targets[logical].collectingCandidates = true
	_, _ = race.WriteTo([]byte("opening"), net.UDPAddrFromAddrPort(logical))
	conns[4].inject("reply", logical)
	_, put, _, err := race.WaitReadFrom()
	if put != nil {
		put()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := race.register(context.Background(), logical, []netip.AddrPort{directUDPTestAddr("2001:db8::1", 443)}, "", ""); err != nil {
		t.Fatal(err)
	}
	if conns[6] != nil {
		t.Fatal("late lookup opened another family after winner was selected")
	}
}

func TestDirectUDPRegisterAfterCloseDoesNotCreateSocket(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	_ = race.Close()
	logical := directUDPTestAddr("192.0.2.1", 443)
	if err := race.register(context.Background(), logical, []netip.AddrPort{logical}, "", ""); err == nil {
		t.Fatal("register succeeded after Close")
	}
	if len(conns) != 0 {
		t.Fatal("register created socket after Close")
	}
}

func TestDirectUDPLateQUICCandidateRequiresApplicationCID(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	logical := directUDPTestAddr("192.0.2.1", 443)
	v6 := directUDPTestAddr("2001:db8::1", 443)
	if err := race.register(context.Background(), logical, []netip.AddrPort{logical}, "", ""); err != nil {
		t.Fatal(err)
	}
	race.targets[logical].collectingCandidates = true
	header := func(destination, source byte) []byte {
		return []byte{0xc0, 0, 0, 0, 1, 1, destination, 1, source}
	}
	_, _ = race.WriteTo(header('i', 'c'), net.UDPAddrFromAddrPort(logical))
	if err := race.register(context.Background(), logical, []netip.AddrPort{v6}, "", ""); err != nil {
		t.Fatal(err)
	}
	if got := len(conns[6].destinations()); got != 1 {
		t.Fatalf("late QUIC candidate received %d Initials, want 1", got)
	}
	conns[6].reads <- directUDPTestPacket{data: header('c', 's'), from: net.UDPAddrFromAddrPort(v6)}
	_, put, _, err := race.WaitReadFrom()
	if put != nil {
		put()
	}
	if err != nil {
		t.Fatal(err)
	}
	if race.targets[logical].winner.IsValid() {
		t.Fatal("server reply alone pinned the QUIC path")
	}
	_, _ = race.WriteTo(header('s', 'c'), net.UDPAddrFromAddrPort(logical))
	if race.targets[logical].winner != v6 || race.targets[logical].quicConfirmed {
		t.Fatal("application's long-header CID did not select the late path")
	}
	_, _ = race.WriteTo([]byte{0x40, 's', 0}, net.UDPAddrFromAddrPort(logical))
	if !race.targets[logical].quicConfirmed {
		t.Fatal("application's 1-RTT CID did not confirm the late path")
	}
	if got := len(conns[4].destinations()); got != 1 {
		t.Fatalf("loser received application continuation: %d writes", got)
	}
}

type progressiveDirectUDPResolver struct {
	resolver.Resolver
	v4, v6 chan resolver.IPCandidateBatch
}

func (r *progressiveDirectUDPResolver) LookupIPCandidates(_ context.Context, _ string, ipv6 bool, _ string) <-chan resolver.IPCandidateBatch {
	if ipv6 {
		return r.v6
	}
	return r.v4
}
func (*progressiveDirectUDPResolver) PromoteIP(string, bool, string, netip.Addr) {}

func TestDirectUDPProgressiveAddsLaterSourceInSameFamily(t *testing.T) {
	oldResolver, oldDisabled := resolver.DirectHostResolver, resolver.DisableIPv6.Load()
	r := &progressiveDirectUDPResolver{v4: make(chan resolver.IPCandidateBatch, 2), v6: make(chan resolver.IPCandidateBatch)}
	close(r.v6)
	r.v4 <- resolver.IPCandidateBatch{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Source: -1}
	resolver.DirectHostResolver = r
	resolver.DisableIPv6.Store(false)
	t.Cleanup(func() { resolver.DirectHostResolver = oldResolver; resolver.DisableIPv6.Store(oldDisabled) })
	race, conns := newDirectUDPTestRace(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	metadata := &C.Metadata{Host: "source-stream-udp.example", DstPort: 443}
	if err := NewDirect().registerProgressiveUDPTarget(ctx, race, metadata); err != nil {
		t.Fatal(err)
	}
	_, _ = race.WriteTo([]byte("opening"), net.UDPAddrFromAddrPort(metadata.AddrPort()))
	r.v4 <- resolver.IPCandidateBatch{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, Source: 1}
	close(r.v4)
	deadline := time.Now().Add(time.Second)
	for len(conns[4].destinations()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := conns[4].destinations(); len(got) != 2 || got[1] != directUDPTestAddr("192.0.2.2", 443) {
		t.Fatalf("later DNS source did not join existing family: %v", got)
	}
}

func TestDirectUDPClosingDuringSocketCreationClosesLateSocket(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	pc := newDirectUDPTestConn()
	race := newDirectUDPRacePacketConn(func(context.Context, int, netip.AddrPort) (net.PacketConn, error) {
		close(started)
		<-release
		return pc, nil
	})
	result := make(chan error, 1)
	logical := directUDPTestAddr("192.0.2.1", 443)
	go func() { result <- race.register(context.Background(), logical, []netip.AddrPort{logical}, "", "") }()
	<-started
	_ = race.Close()
	close(release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("late socket registered after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("late registration did not finish")
	}
	select {
	case <-pc.closed:
	default:
		t.Fatal("socket created during Close leaked")
	}
}
