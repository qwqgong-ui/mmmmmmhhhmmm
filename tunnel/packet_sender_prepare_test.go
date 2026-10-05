package tunnel

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type preparingTestConn struct {
	recordingPacketConn
	concurrent  bool
	slow        string
	begun       chan struct{}
	release     chan struct{}
	cancelled   chan struct{}
	writes      chan string
	once        sync.Once
	mu          sync.Mutex
	resolutions map[udpPrepareKey]int
	writing     atomic.Int32
	overlapping atomic.Bool
	writeErr    error
}

func (c *preparingTestConn) ConcurrentResolveUDP() bool { return c.concurrent }
func (c *preparingTestConn) ResolveUDP(ctx context.Context, m *C.Metadata) error {
	c.mu.Lock()
	c.resolutions[udpPacketKey(m)]++
	c.mu.Unlock()
	if m.Host == c.slow {
		c.once.Do(func() { close(c.begun) })
		select {
		case <-c.release:
		case <-ctx.Done():
			if c.cancelled != nil {
				close(c.cancelled)
			}
			return ctx.Err()
		}
	}
	m.DstIP = netip.MustParseAddr("192.0.2.2")
	return nil
}
func (c *preparingTestConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.writing.Add(1) != 1 {
		c.overlapping.Store(true)
	}
	defer c.writing.Add(-1)
	c.writes <- string(p)
	return len(p), c.writeErr
}

type preparingTestPacket struct {
	mappingTestPacket
	drops    atomic.Int32
	reported chan C.ICMPError
}

func (p *preparingTestPacket) Drop() { p.drops.Add(1) }
func (p *preparingTestPacket) ReportICMPError(err C.ICMPError, _ uint32) error {
	p.reported <- err
	return nil
}
func preparationPacket(host, data string, port uint16) (C.PacketAdapter, *preparingTestPacket) {
	p := &preparingTestPacket{mappingTestPacket: mappingTestPacket{data: []byte(data)}}
	return C.NewPacketAdapter(p, udpMetadata("", host, port)), p
}
func startPreparingTestSender(t *testing.T, c *preparingTestConn) (*packetSender, <-chan struct{}) {
	t.Helper()
	s := newPacketSender().(*packetSender)
	done := make(chan struct{})
	go func() { defer close(done); s.Process(c, nil) }()
	t.Cleanup(func() {
		s.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("sender did not stop")
		}
	})
	return s, done
}
func nextPreparedWrite(t *testing.T, c *preparingTestConn) string {
	t.Helper()
	select {
	case s := <-c.writes:
		return s
	case <-time.After(time.Second):
		t.Fatal("write blocked")
		return ""
	}
}

func TestUDPPreparedIPTargetsKeepPortAndAddressIdentity(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "2001:db8::1", "fe80::1%eth0", "::ffff:192.0.2.1"} {
		t.Run(ip, func(t *testing.T) {
			sender := newMappingTestSender(t)
			origin := udpMetadata(ip, "", 443)
			sender.AddMapping(origin, udpMetadata("192.0.2.10", "", 443))
			sender.AddMapping(udpMetadata(ip, "", 8443), udpMetadata("192.0.2.20", "", 8443))
			conn := &recordingPacketConn{}
			for _, target := range []struct {
				port uint16
				ip   string
			}{{443, "192.0.2.10"}, {8443, "192.0.2.20"}} {
				packet := C.NewPacketAdapter(&mappingTestPacket{data: []byte("payload")}, udpMetadata(ip, "", target.port))
				sender.processPacket(conn, packet)
				addr, ok := conn.written.(*net.UDPAddr)
				if !ok || addr.AddrPort() != netip.AddrPortFrom(netip.MustParseAddr(target.ip), target.port) {
					t.Fatalf("cached destination = %v, want %s:%d", conn.written, target.ip, target.port)
				}
			}
			withHost := udpMetadata(ip, "example.com", 443)
			changedIP := udpMetadata("192.0.2.99", "example.com", 443)
			if udpPacketKey(withHost) != udpPacketKey(changedIP) {
				t.Fatal("a retained host must take precedence over IP changes")
			}
		})
	}
}

func TestUDPSlowTargetDoesNotBlockPreparedOrConcurrentTargets(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "serialized-resolver", true: "parallel-resolver"}[concurrent], func(t *testing.T) {
			c := &preparingTestConn{concurrent: concurrent, slow: "slow.test", begun: make(chan struct{}), release: make(chan struct{}), writes: make(chan string, 256), resolutions: make(map[udpPrepareKey]int)}
			s, _ := startPreparingTestSender(t, c)
			s.AddMapping(udpMetadata("", "ready.test", 443), udpMetadata("192.0.2.1", "ready.test", 443))
			var packets []*preparingTestPacket
			send := func(host, data string, port uint16) {
				a, p := preparationPacket(host, data, port)
				packets = append(packets, p)
				s.Send(a)
			}
			send("slow.test", "slow-1", 443)
			<-c.begun
			send("slow.test", "slow-2", 443)
			started := time.Now()
			send("ready.test", "ready", 443)
			if got := nextPreparedWrite(t, c); got != "ready" {
				t.Fatal(got)
			}
			t.Logf("prepared target delivery while DNS blocked=%s", time.Since(started))
			send("fresh.test", "fresh", 443)
			if concurrent {
				if got := nextPreparedWrite(t, c); got != "fresh" {
					t.Fatal(got)
				}
			}
			close(c.release)
			if got := nextPreparedWrite(t, c); got != "slow-1" {
				t.Fatal(got)
			}
			if got := nextPreparedWrite(t, c); got != "slow-2" {
				t.Fatal(got)
			}
			if !concurrent {
				if got := nextPreparedWrite(t, c); got != "fresh" {
					t.Fatal(got)
				}
			}
			// The same host on a new port must go through ResolveUDP again.
			send("fresh.test", "other-port", 8443)
			if got := nextPreparedWrite(t, c); got != "other-port" {
				t.Fatal(got)
			}
			s.Close()
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.resolutions[udpPacketKey(udpMetadata("", "fresh.test", 443))] != 1 || c.resolutions[udpPacketKey(udpMetadata("", "fresh.test", 8443))] != 1 {
				t.Fatal(c.resolutions)
			}
			if c.overlapping.Load() {
				t.Fatal("socket writes overlapped")
			}
		})
	}
}

func TestUDPPendingBudgetAndCloseReleaseEveryPacketOnce(t *testing.T) {
	c := &preparingTestConn{slow: "slow.test", begun: make(chan struct{}), release: make(chan struct{}), cancelled: make(chan struct{}), writes: make(chan string, 256), resolutions: make(map[udpPrepareKey]int)}
	s, done := startPreparingTestSender(t, c)
	var packets []*preparingTestPacket
	for i := range 256 {
		a, p := preparationPacket("slow.test", "data", 443)
		packets = append(packets, p)
		s.Send(a)
		if i == 0 {
			<-c.begun
		}
	}
	if n := len(s.slots); n != 128 {
		t.Fatalf("total pending=%d", n)
	}
	s.Close()
	<-done
	select {
	case <-c.cancelled:
	case <-time.After(time.Second):
		t.Fatal("resolver was not cancelled")
	}
	if len(s.slots) != 0 {
		t.Fatal("pending slots leaked")
	}
	for i, p := range packets {
		if p.drops.Load() != 1 {
			t.Fatalf("packet %d drops=%d", i, p.drops.Load())
		}
	}
	a, p := preparationPacket("slow.test", "after-close", 443)
	s.Send(a)
	if p.drops.Load() != 1 {
		t.Fatal("packet accepted after close")
	}
}

func TestUDPQueuedWrapperPreservesICMPErrorReporting(t *testing.T) {
	c := &preparingTestConn{writes: make(chan string, 2), resolutions: make(map[udpPrepareKey]int), writeErr: syscall.ECONNREFUSED}
	s, _ := startPreparingTestSender(t, c)
	a, p := preparationPacket("icmp.test", "data", 443)
	p.reported = make(chan C.ICMPError, 1)
	s.Send(a)
	nextPreparedWrite(t, c)
	select {
	case err := <-p.reported:
		if err != C.ICMPErrorPortUnreachable {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued PacketAdapter lost ICMP capability")
	}
}

func TestUDPConcurrentSendAndCloseReleaseExactlyOnce(t *testing.T) {
	c := &preparingTestConn{writes: make(chan string, 2048), resolutions: make(map[udpPrepareKey]int)}
	s, done := startPreparingTestSender(t, c)
	packets := make([]*preparingTestPacket, 1024)
	var wg sync.WaitGroup
	for i := range packets {
		a, p := preparationPacket("close.test", "data", 443)
		packets[i] = p
		wg.Go(func() { s.Send(a) })
	}
	s.Close()
	wg.Wait()
	<-done
	for i, p := range packets {
		if p.drops.Load() != 1 {
			t.Fatalf("packet %d drops=%d", i, p.drops.Load())
		}
	}
	if len(s.slots) != 0 {
		t.Fatal("slots leaked")
	}
}
