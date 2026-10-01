package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type directUDPTestPacket struct {
	data []byte
	from net.Addr
}

type directUDPTestConn struct {
	mu       sync.Mutex
	writes   []netip.AddrPort
	payloads [][]byte
	reads    chan directUDPTestPacket
	errs     chan error
	closed   chan struct{}
	once     sync.Once
}

func newDirectUDPTestConn() *directUDPTestConn {
	return &directUDPTestConn{
		reads:  make(chan directUDPTestPacket, 16),
		errs:   make(chan error, 4),
		closed: make(chan struct{}),
	}
}

func (c *directUDPTestConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	select {
	case packet := <-c.reads:
		return copy(payload, packet.data), packet.from, nil
	case err := <-c.errs:
		return 0, nil, err
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *directUDPTestConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, addr.(*net.UDPAddr).AddrPort())
	c.payloads = append(c.payloads, append([]byte(nil), payload...))
	c.mu.Unlock()
	return len(payload), nil
}

func (c *directUDPTestConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *directUDPTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *directUDPTestConn) SetDeadline(time.Time) error      { return nil }
func (c *directUDPTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *directUDPTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *directUDPTestConn) inject(payload string, from netip.AddrPort) {
	c.reads <- directUDPTestPacket{data: []byte(payload), from: net.UDPAddrFromAddrPort(from)}
}
func (c *directUDPTestConn) injectError(err error) { c.errs <- err }
func (c *directUDPTestConn) destinations() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]netip.AddrPort(nil), c.writes...)
}

func newDirectUDPTestRace(t *testing.T) (*directUDPRacePacketConn, map[int]*directUDPTestConn) {
	t.Helper()
	conns := make(map[int]*directUDPTestConn)
	race := newDirectUDPRacePacketConn(func(_ context.Context, family int, _ netip.AddrPort) (net.PacketConn, error) {
		conn := newDirectUDPTestConn()
		conns[family] = conn
		return conn, nil
	})
	t.Cleanup(func() { _ = race.Close() })
	return race, conns
}

func directUDPTestAddr(address string, port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr(address), port)
}

func TestDirectUDPRaceFirstResponsePinsAndDropsLoser(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	logical := directUDPTestAddr("192.0.2.10", 443)
	v4 := logical
	v6 := directUDPTestAddr("2001:db8::10", 443)
	if err := race.register(context.Background(), logical, []netip.AddrPort{v4, v6}, "", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := race.WriteTo([]byte("p1"), net.UDPAddrFromAddrPort(logical)); err != nil {
		t.Fatal(err)
	}
	if got := len(conns[4].destinations()); got != 1 {
		t.Fatalf("IPv4 writes = %d, want 1", got)
	}
	if got := len(conns[6].destinations()); got != 1 {
		t.Fatalf("IPv6 writes = %d, want 1", got)
	}

	conns[6].inject("winner", v6)
	data, put, from, err := race.WaitReadFrom()
	if err != nil {
		t.Fatal(err)
	}
	if put != nil {
		defer put()
	}
	if string(data) != "winner" || from.(*net.UDPAddr).AddrPort() != logical {
		t.Fatalf("first response = %q from %v, want winner from logical %v", data, from, logical)
	}

	if _, err := race.WriteTo([]byte("p2"), net.UDPAddrFromAddrPort(logical)); err != nil {
		t.Fatal(err)
	}
	if got := len(conns[4].destinations()); got != 1 {
		t.Fatalf("loser received post-pin write: total IPv4 writes = %d", got)
	}
	if got := len(conns[6].destinations()); got != 2 {
		t.Fatalf("winner writes = %d, want 2", got)
	}

	conns[4].inject("late-loser", v4)
	conns[6].inject("winner-again", v6)
	data, put, _, err = race.WaitReadFrom()
	if err != nil {
		t.Fatal(err)
	}
	if put != nil {
		defer put()
	}
	if string(data) != "winner-again" {
		t.Fatalf("late loser was not dropped: got %q", data)
	}
}

func TestDirectUDPRaceDatagramBudgetPinsFallback(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	logical := directUDPTestAddr("192.0.2.20", 8443)
	v6 := directUDPTestAddr("2001:db8::20", 8443)
	if err := race.register(context.Background(), logical, []netip.AddrPort{logical, v6}, "", ""); err != nil {
		t.Fatal(err)
	}

	for range directUDPRaceDatagrams + 1 {
		if _, err := race.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(logical)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(conns[4].destinations()); got != directUDPRaceDatagrams+1 {
		t.Fatalf("fallback writes = %d, want %d", got, directUDPRaceDatagrams+1)
	}
	if got := len(conns[6].destinations()); got != directUDPRaceDatagrams {
		t.Fatalf("IPv6 replicated writes = %d, want %d", got, directUDPRaceDatagrams)
	}
}

func TestDirectUDPRaceByteAndTimeBudgetsPinFallback(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		race, conns := newDirectUDPTestRace(t)
		logical := directUDPTestAddr("192.0.2.30", 53)
		v6 := directUDPTestAddr("2001:db8::30", 53)
		if err := race.register(context.Background(), logical, []netip.AddrPort{logical, v6}, "", ""); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, directUDPRaceBytes/2+1)
		if _, err := race.WriteTo(payload, net.UDPAddrFromAddrPort(logical)); err != nil {
			t.Fatal(err)
		}
		if len(conns[4].destinations()) != 1 || len(conns[6].destinations()) != 1 {
			t.Fatal("first datagram must still probe every candidate")
		}
		if _, err := race.WriteTo([]byte("next"), net.UDPAddrFromAddrPort(logical)); err != nil {
			t.Fatal(err)
		}
		if got := len(conns[6].destinations()); got != 1 {
			t.Fatalf("byte budget did not stop replication: IPv6 writes = %d", got)
		}
	})

	t.Run("time", func(t *testing.T) {
		race, conns := newDirectUDPTestRace(t)
		logical := directUDPTestAddr("192.0.2.31", 53)
		v6 := directUDPTestAddr("2001:db8::31", 53)
		if err := race.register(context.Background(), logical, []netip.AddrPort{logical, v6}, "", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := race.WriteTo([]byte("first"), net.UDPAddrFromAddrPort(logical)); err != nil {
			t.Fatal(err)
		}
		race.mu.Lock()
		race.targets[logical].started = time.Now().Add(-directUDPRaceWindow)
		race.mu.Unlock()
		if _, err := race.WriteTo([]byte("next"), net.UDPAddrFromAddrPort(logical)); err != nil {
			t.Fatal(err)
		}
		if got := len(conns[6].destinations()); got != 1 {
			t.Fatalf("time budget did not stop replication: IPv6 writes = %d", got)
		}
	})
}

func TestDirectUDPRaceKeepsEIMTargetsSeparate(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	first := directUDPTestAddr("192.0.2.40", 1000)
	firstV6 := directUDPTestAddr("2001:db8::40", 1000)
	second := directUDPTestAddr("192.0.2.41", 2000)
	secondV6 := directUDPTestAddr("2001:db8::41", 2000)
	if err := race.register(context.Background(), first, []netip.AddrPort{first, firstV6}, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := race.register(context.Background(), second, []netip.AddrPort{second, secondV6}, "", ""); err != nil {
		t.Fatal(err)
	}
	_, _ = race.WriteTo([]byte("one"), net.UDPAddrFromAddrPort(first))
	_, _ = race.WriteTo([]byte("two"), net.UDPAddrFromAddrPort(second))

	conns[6].inject("second-response", secondV6)
	_, put, from, err := race.WaitReadFrom()
	if err != nil {
		t.Fatal(err)
	}
	if put != nil {
		defer put()
	}
	if got := from.(*net.UDPAddr).AddrPort(); got != second {
		t.Fatalf("second target restored as %v, want %v", got, second)
	}

	_, _ = race.WriteTo([]byte("one-again"), net.UDPAddrFromAddrPort(first))
	_, _ = race.WriteTo([]byte("two-again"), net.UDPAddrFromAddrPort(second))
	if got := len(conns[4].destinations()); got != 3 {
		t.Fatalf("IPv4 writes = %d, want first race twice plus second's initial race", got)
	}
	if got := len(conns[6].destinations()); got != 4 {
		t.Fatalf("IPv6 writes = %d, want first race twice plus pinned second twice", got)
	}
}

func TestDirectUDPRaceRealDualStackSockets(t *testing.T) {
	v4Server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer v4Server.Close()
	port := v4Server.LocalAddr().(*net.UDPAddr).Port
	v6Server, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: port})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer v6Server.Close()

	var v4Packets, v6Packets atomic.Int32
	echo := func(server *net.UDPConn, packets *atomic.Int32, delay time.Duration) {
		buffer := make([]byte, 1024)
		for {
			n, remote, err := server.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			packets.Add(1)
			if delay > 0 {
				time.Sleep(delay)
			}
			_, _ = server.WriteToUDP(buffer[:n], remote)
		}
	}
	go echo(v4Server, &v4Packets, 80*time.Millisecond)
	go echo(v6Server, &v6Packets, 0)

	race := newDirectUDPRacePacketConn(func(_ context.Context, family int, _ netip.AddrPort) (net.PacketConn, error) {
		network := "udp6"
		if family == 4 {
			network = "udp4"
		}
		return net.ListenPacket(network, "")
	})
	defer race.Close()
	logical := directUDPTestAddr("127.0.0.1", uint16(port))
	v6 := directUDPTestAddr("::1", uint16(port))
	if err := race.register(context.Background(), logical, []netip.AddrPort{logical, v6}, "", ""); err != nil {
		t.Fatal(err)
	}
	_ = race.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := race.WriteTo([]byte("probe"), net.UDPAddrFromAddrPort(logical)); err != nil {
		t.Fatal(err)
	}
	data, put, from, err := race.WaitReadFrom()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "probe" || from.(*net.UDPAddr).AddrPort() != logical {
		t.Fatalf("response = %q from %v, want logical %v", data, from, logical)
	}
	if put != nil {
		put()
	}
	if _, err := race.WriteTo([]byte("pinned"), net.UDPAddrFromAddrPort(logical)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for v6Packets.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := v6Packets.Load(); got != 2 {
		t.Fatalf("IPv6 winner packets = %d, want 2", got)
	}
	if got := v4Packets.Load(); got != 1 {
		t.Fatalf("IPv4 loser packets = %d, want 1", got)
	}
}

func TestDirectUDPRaceReturnsLastReaderError(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	logical := directUDPTestAddr("192.0.2.50", 443)
	v6 := directUDPTestAddr("2001:db8::50", 443)
	if err := race.register(context.Background(), logical, []netip.AddrPort{logical, v6}, "", ""); err != nil {
		t.Fatal(err)
	}
	_ = conns[4].Close()
	_ = conns[6].Close()

	done := make(chan error, 1)
	go func() {
		_, _, _, err := race.WaitReadFrom()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("last reader error was lost")
		}
	case <-time.After(time.Second):
		t.Fatal("WaitReadFrom blocked after every socket failed")
	}
}

func TestDirectUDPRaceIgnoresCandidateICMPReadError(t *testing.T) {
	race, conns := newDirectUDPTestRace(t)
	logical := directUDPTestAddr("192.0.2.60", 443)
	v6 := directUDPTestAddr("2001:db8::60", 443)
	if err := race.register(context.Background(), logical, []netip.AddrPort{logical, v6}, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := race.WriteTo([]byte("probe"), net.UDPAddrFromAddrPort(logical)); err != nil {
		t.Fatal(err)
	}
	conns[4].injectError(&net.OpError{Op: "read", Net: "udp4", Err: testDirectUDPConnectionRefusedError{}})
	conns[6].inject("winner", v6)

	done := make(chan error, 1)
	go func() {
		data, put, _, err := race.WaitReadFrom()
		if put != nil {
			defer put()
		}
		if err == nil && string(data) != "winner" {
			err = errors.New("unexpected response")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loser ICMP terminated race: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("winner response blocked after loser ICMP")
	}
}

type testDirectUDPConnectionRefusedError struct{}

func (testDirectUDPConnectionRefusedError) Error() string { return "connection refused" }
