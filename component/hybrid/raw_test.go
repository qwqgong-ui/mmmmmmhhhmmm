package hybrid

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/pool"
)

func localUDP(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func TestRawSocketConnectsAndDropsForeignSources(t *testing.T) {
	relay, pc, other := localUDP(t), localUDP(t), localUDP(t)
	s := newRawSocket(pc, netip.MustParseAddrPort(relay.LocalAddr().String()))
	if !s.connected() {
		t.Skip("this platform cannot connect a bound UDP socket")
	}

	if _, err := s.write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	b := make([]byte, 64)
	relay.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := relay.ReadFrom(b)
	if err != nil || string(b[:n]) != "ping" {
		t.Fatalf("relay received %q: %v", b[:n], err)
	}
	if _, err = relay.WriteTo([]byte("pong"), from); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(time.Second))
	n, fromRelay, err := s.read(b)
	if err != nil || !fromRelay || string(b[:n]) != "pong" {
		t.Fatalf("read %q fromRelay=%v: %v", b[:n], fromRelay, err)
	}

	// The kernel drops everyone else before the receive loop sees them.
	if _, err = other.WriteTo([]byte("spoof"), pc.LocalAddr()); err != nil {
		t.Fatalf("foreign write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err = s.read(b); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("foreign datagram %q reached a connected socket: %v", b[:n], err)
	}
}

func TestRawSocketUnconnectedRejectsForeignSources(t *testing.T) {
	relay, pc, other := localUDP(t), localUDP(t), localUDP(t)
	// The path platforms without connect(2) keep using: the socket is never
	// connected, so foreign datagrams really do arrive.
	s := unconnectedSocket(pc, netip.MustParseAddrPort(relay.LocalAddr().String()))

	if _, err := s.write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	b := make([]byte, 64)
	relay.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := relay.ReadFrom(b)
	if err != nil || string(b[:n]) != "ping" {
		t.Fatalf("relay received %q: %v", b[:n], err)
	}

	if _, err = other.WriteTo([]byte("spoof"), pc.LocalAddr()); err != nil {
		t.Fatalf("foreign write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(time.Second))
	if n, fromRelay, err := s.read(b); err != nil || fromRelay {
		t.Fatalf("foreign datagram %q accepted as the relay's: fromRelay=%v err=%v", b[:n], fromRelay, err)
	}
	if _, err = relay.WriteTo([]byte("pong"), from); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	pc.SetReadDeadline(time.Now().Add(time.Second))
	if n, fromRelay, err := s.read(b); err != nil || !fromRelay || string(b[:n]) != "pong" {
		t.Fatalf("relay datagram %q rejected: fromRelay=%v err=%v", b[:n], fromRelay, err)
	}
}

func TestTransientErrorsKeepTheRawPath(t *testing.T) {
	for _, err := range []error{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.EMSGSIZE} {
		// The shape the standard library actually returns.
		if wrapped := error(&net.OpError{Op: "read", Err: os.NewSyscallError("recvfrom", err)}); !transientError(wrapped) {
			t.Fatalf("%v not recognised as an ICMP report", err)
		}
	}
	for _, err := range []error{net.ErrClosed, os.ErrDeadlineExceeded, io.EOF, errors.New("closed")} {
		if transientError(err) {
			t.Fatalf("%v treated as an ICMP report", err)
		}
	}
}

func TestPooledDatagramIsCopiedBeforeItIsReturned(t *testing.T) {
	c := NewPacketConn(ClientOptions{})
	defer c.Close()
	p := pool.Get(4)
	copy(p, "abcd")
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 443}
	c.deliver(result{p: p, a: addr, pooled: true})
	b := make([]byte, 8)
	n, a, err := c.ReadFrom(b)
	if err != nil || n != 4 || string(b[:n]) != "abcd" || a != addr {
		t.Fatalf("n=%d b=%q a=%v err=%v", n, b[:n], a, err)
	}
}

func TestFlowCountersFollowTheChosenPath(t *testing.T) {
	relay, pc := localUDP(t), localUDP(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go io.Copy(io.Discard, server)

	d := newFlowDiagnostic("counters.test:443", "", "")
	defer d.close()
	f := &clientFlow{stream: client, raw: newRawSocket(pc, netip.MustParseAddrPort(relay.LocalAddr().String())), diagnostic: d}
	f.active.Store(true)
	f.lastRaw.Store(time.Now().UnixNano())

	short := []byte{0x40, 1, 2, 3}
	if _, err := f.write(short); err != nil {
		t.Fatalf("short write: %v", err)
	}
	if c := d.counters.snapshot(); c.RawTxPackets != 1 || c.RawTxBytes != 4 || c.StreamTxPackets != 0 {
		t.Fatalf("a short header did not take raw: %+v", c)
	}

	// Long headers stay on the stream even while raw carries the flow.
	long := []byte{0xc0, 0, 0, 0, 1, 0, 0}
	if _, err := f.write(long); err != nil {
		t.Fatalf("long write: %v", err)
	}
	if c := d.counters.snapshot(); c.StreamTxPackets != 1 || c.StreamTxBytes != 7 || c.RawTxPackets != 1 {
		t.Fatalf("a long header did not take the stream: %+v", c)
	}

	// Once raw is gone every packet is a stream packet.
	if err := f.disable(false, "test"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := f.write(short); err != nil {
		t.Fatalf("write after fallback: %v", err)
	}
	if c := d.counters.snapshot(); c.RawTxPackets != 1 || c.StreamTxPackets != 2 {
		t.Fatalf("fallback still used raw: %+v", c)
	}
}

func TestStatsCountersSurviveTheFlow(t *testing.T) {
	before := Stats().Counters
	d := newFlowDiagnostic("stats.test:443", "", "")
	d.count(rawRxPackets, rawRxBytes, 1200)
	d.countOne(rawErrors)
	live := Stats().Counters
	if live.RawRxPackets != before.RawRxPackets+1 || live.RawRxBytes != before.RawRxBytes+1200 || live.RawErrors != before.RawErrors+1 {
		t.Fatalf("a live flow is missing from the totals: %+v -> %+v", before, live)
	}
	d.close()
	after := Stats().Counters
	if after != live {
		t.Fatalf("closing the flow changed the totals: %+v -> %+v", live, after)
	}
	d.close()
	if again := Stats().Counters; again != after {
		t.Fatalf("a second close counted the flow twice: %+v", again)
	}
}

// The receive path used to spend 9 allocations and 1.5 KiB on every datagram:
// six formatting the source and the relay as text to compare them, one for the
// copy handed to the reader and two for the address reported with it.
func TestReceivePathDoesNotAllocatePerDatagram(t *testing.T) {
	s := unconnectedSocket(nil, netip.MustParseAddrPort("203.0.113.9:443"))
	a := net.Addr(net.UDPAddrFromAddrPort(s.relay))
	datagram := make([]byte, 1350)
	if n := testing.AllocsPerRun(1000, func() {
		if !s.fromRelay(a) {
			t.Fatal("the relay's own address was rejected")
		}
		p := pool.Get(len(datagram))
		copy(p, datagram)
		pool.Put(p)
	}); n >= 1 {
		t.Fatalf("%v allocations per received datagram", n)
	}
}

func TestStreamFrameDoesNotAllocatePerPacket(t *testing.T) {
	datagram := make([]byte, 1350)
	if n := testing.AllocsPerRun(1000, func() {
		if err := WriteFrame(io.Discard, datagram); err != nil {
			t.Fatal(err)
		}
	}); n >= 1 {
		t.Fatalf("%v allocations per framed packet", n)
	}
}
