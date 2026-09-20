package tunnel

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	M "github.com/metacubex/sing/common/metadata"
)

type recordingPacketConn struct {
	written    net.Addr
	resolvedIP netip.Addr
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (c *recordingPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	return nil, nil, nil, net.ErrClosed
}
func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.written = addr
	return len(p), nil
}
func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr              { return udpAddr("127.0.0.1", 12345) }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingPacketConn) Chains() C.Chain                  { return nil }
func (c *recordingPacketConn) ProviderChains() C.Chain          { return nil }
func (c *recordingPacketConn) AppendToChains(C.ProxyAdapter)    {}
func (c *recordingPacketConn) RemoteDestination() string        { return "" }
func (c *recordingPacketConn) ResolveUDP(_ context.Context, metadata *C.Metadata) error {
	if c.resolvedIP.IsValid() {
		metadata.DstIP = c.resolvedIP
	}
	return nil
}

type mappingTestPacket struct {
	data    []byte
	dropped bool
}

func (p *mappingTestPacket) Data() []byte { return p.data }
func (p *mappingTestPacket) WriteBack(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}
func (p *mappingTestPacket) Drop()               { p.dropped = true }
func (p *mappingTestPacket) LocalAddr() net.Addr { return udpAddr("192.0.2.1", 23456) }

func newMappingTestSender(t *testing.T) *packetSender {
	t.Helper()
	sender := newPacketSender().(*packetSender)
	t.Cleanup(sender.Close)
	return sender
}

func udpMetadata(ip, host string, port uint16) *C.Metadata {
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Host:    host,
		DstPort: port,
	}
	if ip != "" {
		metadata.DstIP = netip.MustParseAddr(ip)
	}
	return metadata
}

func udpAddr(ip string, port uint16) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), port))
}

func TestPacketSenderSendsUnresolvedHostToRemoteDNS(t *testing.T) {
	sender := newMappingTestSender(t)
	packet := &mappingTestPacket{data: []byte("payload")}
	metadata := udpMetadata("", "quic.example", 443)
	metadata.DNSMode = C.DNSFakeIP
	adapter := C.NewPacketAdapter(packet, metadata)
	conn := &recordingPacketConn{}

	sender.processPacket(conn, adapter)

	destination := M.SocksaddrFromNet(conn.written)
	if !destination.IsFqdn() || destination.Fqdn != "quic.example" || destination.Port != 443 {
		t.Fatalf("WriteTo() destination = %#v, want quic.example:443", destination)
	}
	if !packet.dropped {
		t.Fatal("processPacket() did not release input packet")
	}
}

func TestPacketSenderUsesResolvedIPForDirect(t *testing.T) {
	sender := newMappingTestSender(t)
	packet := &mappingTestPacket{data: []byte("payload")}
	metadata := udpMetadata("", "game.example", 443)
	metadata.DNSMode = C.DNSFakeIP
	adapter := C.NewPacketAdapter(packet, metadata)
	resolvedIP := netip.MustParseAddr("203.0.113.6")
	conn := &recordingPacketConn{resolvedIP: resolvedIP}

	sender.processPacket(conn, adapter)

	directAddr, ok := conn.written.(*net.UDPAddr)
	if !ok {
		t.Fatalf("WriteTo() destination type = %T, want *net.UDPAddr", conn.written)
	}
	destination := M.SocksaddrFromNet(directAddr).Unwrap()
	if destination.IsFqdn() || destination.Addr != resolvedIP || destination.Port != 443 {
		t.Fatalf("WriteTo() destination = %#v, want %s:443", destination, resolvedIP)
	}

	// The cached path must keep the same native DIRECT address semantics.
	cachedPacket := &mappingTestPacket{data: []byte("cached payload")}
	cachedAdapter := C.NewPacketAdapter(cachedPacket, udpMetadata("", "game.example", 443))
	conn.resolvedIP = netip.Addr{}
	sender.processPacket(conn, cachedAdapter)
	if _, ok := conn.written.(*net.UDPAddr); !ok {
		t.Fatalf("cached WriteTo() destination type = %T, want *net.UDPAddr", conn.written)
	}
	if !cachedPacket.dropped {
		t.Fatal("cached processPacket() did not release input packet")
	}
	if !packet.dropped {
		t.Fatal("processPacket() did not release input packet")
	}
}

func TestUDPSocksaddrFromNetAcceptsTypedNil(t *testing.T) {
	var addr *net.UDPAddr
	if got := udpSocksaddrFromNet(addr); got.IsValid() {
		t.Fatalf("udpSocksaddrFromNet(typed nil) = %#v, want invalid", got)
	}
}

func TestPacketSenderRestoresRemoteDomainReply(t *testing.T) {
	sender := newMappingTestSender(t)
	origin := udpMetadata("198.18.0.7", "", 443)
	target := udpMetadata("", "Quic.Example", 443)
	sender.AddMapping(origin, target)

	got := sender.RestoreReadFrom(M.ParseSocksaddrHostPort("quic.example", 443))
	if got != origin.DstIP {
		t.Fatalf("RestoreReadFrom() = %s, want Fake-IP %s", got, origin.DstIP)
	}
	if got := sender.RestoreReadFrom(M.ParseSocksaddrHostPort("unknown.example", 443)); got.IsValid() {
		t.Fatalf("unknown domain restored to %s; want invalid instead of guessed FakeIP", got)
	}

	cached := sender.originToTarget[origin.String()]
	if !cached.IsFqdn() || canonicalUDPDomain(cached.Fqdn) != "quic.example" {
		t.Fatalf("cached target = %#v, want quic.example", cached)
	}
}

func TestPacketSenderLearnsEveryRemoteIPOfOneDomain(t *testing.T) {
	sender := newMappingTestSender(t)
	origin := udpMetadata("198.18.0.8", "", 443)
	sender.AddMapping(origin, udpMetadata("", "video.example", 443))

	wrongPort := udpAddr("203.0.113.9", 8443)
	if got := sender.RestoreReadFrom(wrongPort); got != wrongPort.AddrPort().Addr() {
		t.Fatalf("wrong-port reply = %s, want actual source %s", got, wrongPort.IP)
	}

	primary := udpAddr("203.0.113.10", 443)
	if got := sender.RestoreReadFrom(primary); got != origin.DstIP {
		t.Fatalf("primary reply = %s, want Fake-IP %s", got, origin.DstIP)
	}
	if got := sender.RestoreReadFrom(primary); got != origin.DstIP {
		t.Fatalf("cached primary reply = %s, want Fake-IP %s", got, origin.DstIP)
	}

	// A second A record of the same domain is not ambiguous and must restore
	// too; the earlier single-entry table stopped after the first reply.
	alternate := udpAddr("203.0.113.11", 443)
	if got := sender.RestoreReadFrom(alternate); got != origin.DstIP {
		t.Fatalf("alternate reply = %s, want Fake-IP %s", got, origin.DstIP)
	}
}

func TestPacketSenderRestoresEachDomainSharingOnePort(t *testing.T) {
	// The BitTorrent shape: one source port, several tracker FQDNs on the same
	// remote port, each answered before the next request goes out.
	sender := newMappingTestSender(t)
	firstOrigin := udpMetadata("198.18.0.9", "", 1337)
	secondOrigin := udpMetadata("198.18.0.10", "", 1337)

	sender.AddMapping(firstOrigin, udpMetadata("", "first.example", 1337))
	firstIP := udpAddr("203.0.113.12", 1337)
	if got := sender.RestoreReadFrom(firstIP); got != firstOrigin.DstIP {
		t.Fatalf("first tracker reply = %s, want Fake-IP %s", got, firstOrigin.DstIP)
	}

	sender.AddMapping(secondOrigin, udpMetadata("", "second.example", 1337))
	secondIP := udpAddr("203.0.113.13", 1337)
	if got := sender.RestoreReadFrom(secondIP); got != secondOrigin.DstIP {
		t.Fatalf("second tracker reply = %s, want Fake-IP %s", got, secondOrigin.DstIP)
	}

	// A later request must not steal an already-bound IP from its domain.
	if got := sender.RestoreReadFrom(firstIP); got != firstOrigin.DstIP {
		t.Fatalf("re-read first tracker reply = %s, want Fake-IP %s", got, firstOrigin.DstIP)
	}

	if got := sender.RestoreReadFrom(M.ParseSocksaddrHostPort("first.example", 1337)); got != firstOrigin.DstIP {
		t.Fatalf("first domain reply = %s, want %s", got, firstOrigin.DstIP)
	}
	if got := sender.RestoreReadFrom(M.ParseSocksaddrHostPort("second.example", 1337)); got != secondOrigin.DstIP {
		t.Fatalf("second domain reply = %s, want %s", got, secondOrigin.DstIP)
	}
}

func TestPacketSenderPrefersExactIPMappingOverGuess(t *testing.T) {
	sender := newMappingTestSender(t)
	domainOrigin := udpMetadata("198.18.0.12", "", 443)
	sender.AddMapping(domainOrigin, udpMetadata("", "domain.example", 443))

	domainIP := udpAddr("203.0.113.14", 443)
	if got := sender.RestoreReadFrom(domainIP); got != domainOrigin.DstIP {
		t.Fatalf("single-domain reply = %s, want %s", got, domainOrigin.DstIP)
	}

	// A direct IP target coexists with domain targets: its exact mapping wins,
	// and it must not revoke what the domain already learned.
	direct := udpMetadata("203.0.113.15", "", 443)
	sender.AddMapping(direct, direct)
	if got := sender.RestoreReadFrom(udpAddr("203.0.113.15", 443)); got != direct.DstIP {
		t.Fatalf("direct reply = %s, want %s", got, direct.DstIP)
	}
	if got := sender.RestoreReadFrom(domainIP); got != domainOrigin.DstIP {
		t.Fatalf("domain reply after direct target = %s, want %s", got, domainOrigin.DstIP)
	}
}

func TestPacketSenderForgetsGuessesForRecycledFakeIP(t *testing.T) {
	sender := newMappingTestSender(t)
	oldOrigin := udpMetadata("198.18.0.20", "", 1337)
	sender.AddMapping(oldOrigin, udpMetadata("", "recycled.example", 1337))

	remote := udpAddr("203.0.113.20", 1337)
	if got := sender.RestoreReadFrom(remote); got != oldOrigin.DstIP {
		t.Fatalf("initial reply = %s, want %s", got, oldOrigin.DstIP)
	}

	// The Fake-IP pool handed the same domain a new address; the stale guess
	// must not survive.
	newOrigin := udpMetadata("198.18.0.21", "", 1337)
	sender.AddMapping(newOrigin, udpMetadata("", "recycled.example", 1337))
	if got := sender.RestoreReadFrom(remote); got != newOrigin.DstIP {
		t.Fatalf("reply after recycle = %s, want %s", got, newOrigin.DstIP)
	}
}

func TestPacketSenderRestoresResolvedAndIPv6Targets(t *testing.T) {
	t.Run("resolved IPv4", func(t *testing.T) {
		sender := newMappingTestSender(t)
		origin := udpMetadata("198.18.0.11", "", 3478)
		target := udpMetadata("203.0.113.13", "game.example", 3478)
		sender.AddMapping(origin, target)
		cached := sender.originToTarget[origin.String()]
		if cached.IsFqdn() || cached.Addr != target.DstIP {
			t.Fatalf("cached target = %#v, want resolved IP %s", cached, target.DstIP)
		}
		if got := sender.RestoreReadFrom(udpAddr("203.0.113.13", 3478)); got != origin.DstIP {
			t.Fatalf("RestoreReadFrom() = %s, want %s", got, origin.DstIP)
		}
	})

	t.Run("remote IPv6", func(t *testing.T) {
		sender := newMappingTestSender(t)
		origin := udpMetadata("2001:2::7", "", 443)
		sender.AddMapping(origin, udpMetadata("", "ipv6.example", 443))
		if got := sender.RestoreReadFrom(udpAddr("2001:db8::7", 443)); got != origin.DstIP {
			t.Fatalf("RestoreReadFrom() = %s, want %s", got, origin.DstIP)
		}
	})
}

// TestUDPResolveFailureLogThrottle pins the behaviour that motivated the
// throttle: a destination that keeps failing must warn once, not once per
// retry. Without it a single black-holed FQDN produced tens of thousands of
// warn lines per hour and evicted the rest of the journal.
func TestUDPResolveFailureLogThrottle(t *testing.T) {
	t.Cleanup(func() {
		udpResolveFailureLog.Clear()
	})
	udpResolveFailureLog.Clear()

	const host = "stun6.example.invalid"

	if _, seen := udpResolveFailureLog.GetOrStore(host, func() struct{} { return struct{}{} }); seen {
		t.Fatal("first failure for a host reported as already seen, want a warn")
	}
	for i := range 100 {
		if _, seen := udpResolveFailureLog.GetOrStore(host, func() struct{} { return struct{}{} }); !seen {
			t.Fatalf("retry %d reported as unseen, want suppression inside the window", i)
		}
	}

	// A different destination is throttled independently, so one noisy peer
	// cannot hide another host's first failure.
	if _, seen := udpResolveFailureLog.GetOrStore("other.example.invalid", func() struct{} { return struct{}{} }); seen {
		t.Fatal("unrelated host reported as already seen, want its own warn")
	}
}
