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

// flowHarness drives one flow's send path without a registration handshake and
// records the frames it puts on the stream. relay stands in for the terminal's
// raw endpoint.
type flowHarness struct {
	flow   *clientFlow
	relay  net.PacketConn
	frames chan []byte
}

func newFlowHarness(t *testing.T) *flowHarness {
	t.Helper()
	relay, pc := localUDP(t), localUDP(t)
	peer, stream := net.Pipe()
	d := newFlowDiagnostic("flow.test:443", "", "")
	f := &clientFlow{
		owner:      NewPacketConn(ClientOptions{}),
		stream:     stream,
		raw:        newRawSocket(pc, netip.MustParseAddrPort(relay.LocalAddr().String())),
		targetAddr: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 443},
		diagnostic: d,
		done:       make(chan struct{}),
	}
	h := &flowHarness{flow: f, relay: relay, frames: make(chan []byte, 64)}
	go func() {
		for {
			p, err := ReadFrame(peer)
			if err != nil {
				return
			}
			if p != nil { // a keepalive carries no frame
				h.frames <- p
			}
		}
	}()
	t.Cleanup(func() {
		close(f.done)
		f.owner.Close()
		stream.Close()
		peer.Close()
		d.close()
	})
	return h
}

// frame returns the next frame the flow put on the stream; an empty one is the
// pause that tells the terminal to stop sending raw.
func (h *flowHarness) frame(t *testing.T) []byte {
	t.Helper()
	select {
	case p := <-h.frames:
		return p
	case <-time.After(time.Second):
		t.Fatal("no frame reached the stream")
		return nil
	}
}

func (h *flowHarness) expectRaw(t *testing.T, want []byte) {
	t.Helper()
	b := make([]byte, 64)
	h.relay.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := h.relay.ReadFrom(b)
	if err != nil || string(b[:n]) != string(want) {
		t.Fatalf("relay received %q: %v", b[:n], err)
	}
}

func (h *flowHarness) expectNoRaw(t *testing.T) {
	t.Helper()
	b := make([]byte, 64)
	h.relay.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := h.relay.ReadFrom(b); err == nil {
		t.Fatalf("the flow probed raw when it should not have: %q", b[:n])
	}
}

func (h *flowHarness) state(t *testing.T) (retries int, retryAt time.Time, reason string, permanent bool) {
	t.Helper()
	h.flow.writeMu.Lock()
	retries, retryAt = h.flow.retries, h.flow.retryAt
	h.flow.writeMu.Unlock()
	d := h.flow.diagnostic
	d.mu.Lock()
	defer d.mu.Unlock()
	return retries, retryAt, d.Reason, d.Permanent
}

var shortPacket = []byte{0x40, 1, 2, 3}

func TestIdleSilenceCostsNothingAndProbesAgain(t *testing.T) {
	h := newFlowHarness(t)
	f := h.flow
	idle := time.Now().Add(-2 * rawSilence)
	f.active.Store(true)
	f.lastRaw.Store(idle.UnixNano())
	f.diagnostic.touch(idle) // the flow carried nothing while raw went quiet

	if _, err := f.write(shortPacket); err != nil {
		t.Fatalf("write: %v", err)
	}
	if p := h.frame(t); len(p) == 0 {
		t.Fatal("an idle flow told the terminal to stop sending raw")
	}
	retries, retryAt, reason, permanent := h.state(t)
	if retries != 0 || !retryAt.IsZero() || reason != "raw_idle" || permanent {
		t.Fatalf("idle silence charged an attempt: retries=%d retryAt=%v reason=%q permanent=%v", retries, retryAt, reason, permanent)
	}

	// With nothing charged there is nothing to wait for: the next packet
	// probes raw again while it travels the stream.
	if _, err := f.write(shortPacket); err != nil {
		t.Fatalf("write: %v", err)
	}
	h.frame(t)
	h.expectRaw(t, shortPacket)
}

func TestBusySilenceStopsTheTerminalAndBacksOff(t *testing.T) {
	h := newFlowHarness(t)
	f := h.flow
	f.active.Store(true)
	f.lastRaw.Store(time.Now().Add(-2 * rawSilence).UnixNano())
	f.diagnostic.touch(time.Now()) // traffic was flowing, so raw really broke

	start := time.Now()
	if _, err := f.write(shortPacket); err != nil {
		t.Fatalf("write: %v", err)
	}
	if p := h.frame(t); len(p) != 0 {
		t.Fatalf("the terminal was not told to stop sending raw: %q", p)
	}
	h.frame(t) // the packet itself, on the stream
	retries, retryAt, reason, permanent := h.state(t)
	if retries != 1 || retryAt.Sub(start) < rawRetryBase || reason != "raw_silence" || permanent {
		t.Fatalf("retries=%d retryAt=+%v reason=%q permanent=%v", retries, retryAt.Sub(start), reason, permanent)
	}

	// Nothing probes again before the backoff expires.
	if _, err := f.write(shortPacket); err != nil {
		t.Fatalf("write: %v", err)
	}
	h.frame(t)
	h.expectNoRaw(t)
}

func TestRepeatedFailuresGiveRawUpForGood(t *testing.T) {
	h := newFlowHarness(t)
	f := h.flow
	for i := range rawRetryLimit + 1 {
		f.writeMu.Lock()
		// Arrive at a probe window that has already run out.
		f.retryAt = time.Time{}
		f.probeEnd = time.Now().Add(-time.Second)
		f.writeMu.Unlock()
		if _, err := f.write(shortPacket); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		h.frame(t) // the pause
		h.frame(t) // the packet
		if retries, _, _, _ := h.state(t); f.disabled.Load() != (retries > rawRetryLimit) {
			t.Fatalf("attempt %d: disabled=%v retries=%d", i, f.disabled.Load(), retries)
		}
	}
	if !f.disabled.Load() {
		t.Fatal("raw was never given up")
	}
	if _, _, reason, permanent := h.state(t); reason != "probe_timeout" || !permanent {
		t.Fatalf("reason=%q permanent=%v", reason, permanent)
	}
}

func TestLateRawPacketRecoversTheFlow(t *testing.T) {
	h := newFlowHarness(t)
	f := h.flow
	f.confirmedRaw.Store(true) // a real flow reached raw before entering backoff
	go f.readRaw()
	// A flow waiting out a backoff, with no probe due for a long time.
	f.writeMu.Lock()
	f.retries, f.retryAt = 1, time.Now().Add(time.Hour)
	f.writeMu.Unlock()

	if _, err := h.relay.WriteTo(shortPacket, h.flow.raw.pc.LocalAddr()); err != nil {
		t.Fatalf("relay write: %v", err)
	}
	for deadline := time.Now().Add(time.Second); !f.active.Load(); {
		if time.Now().After(deadline) {
			t.Fatal("a raw packet from the terminal did not revive the flow")
		}
		time.Sleep(time.Millisecond)
	}

	// Raw carries the next packet again, without waiting out the backoff.
	if _, err := f.write(shortPacket); err != nil {
		t.Fatalf("write: %v", err)
	}
	h.expectRaw(t, shortPacket)
	if c := f.diagnostic.counters.snapshot(); c.RawActivations != 1 || c.RawTxPackets != 1 {
		t.Fatalf("counters %+v", c)
	}
}

func TestRawActivationRejectsUnknownCID(t *testing.T) {
	h := newFlowHarness(t)
	f := h.flow
	clientCID := []byte("client01")
	initial := append([]byte{0xc0, 0, 0, 0, 1, 1, 's', byte(len(clientCID))}, clientCID...)
	if _, err := f.write(initial); err != nil {
		t.Fatal(err)
	}
	h.frame(t)
	go f.readRaw()

	// A 42-byte short-header packet is what the shared HY2 listener sends as
	// a stateless reset for an unclaimed raw probe. Its random CID must not
	// activate raw even though the source address and short header match.
	reset := make([]byte, 42)
	reset[0] = 0x40
	copy(reset[1:], "unknown1")
	if _, err := h.relay.WriteTo(reset, f.raw.pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); ; {
		if f.diagnostic.counters.snapshot().RawDropped == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unknown-CID raw reply was not dropped")
		}
		time.Sleep(time.Millisecond)
	}
	if f.active.Load() || f.confirmedRaw.Load() {
		t.Fatal("stateless reset activated raw")
	}

	reply := append(append([]byte{0x40}, clientCID...), 1)
	if _, err := h.relay.WriteTo(reply, f.raw.pc.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); !f.active.Load(); {
		if time.Now().After(deadline) {
			t.Fatal("matching client CID did not activate raw")
		}
		time.Sleep(time.Millisecond)
	}
	if c := f.diagnostic.counters.snapshot(); c.RawActivations != 1 || c.RawRxPackets != 1 || c.RawDropped != 1 {
		t.Fatalf("unexpected counters after valid reply: %+v", c)
	}
}
