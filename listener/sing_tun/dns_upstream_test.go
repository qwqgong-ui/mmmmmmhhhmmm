package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

type upstreamDNSConn struct {
	net.Conn
	source, destination netip.AddrPort
}

func (c upstreamDNSConn) LocalAddr() net.Addr  { return net.UDPAddrFromAddrPort(c.source) }
func (c upstreamDNSConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.destination) }

func TestTUNDoesNotAnswerItsOwnUpstreamDNS(t *testing.T) {
	for _, pair := range [][2]string{
		{"10.144.170.158:39666", "112.5.230.54:53"},
		{"[2001:db8::1]:51364", "[2001:db8::53]:53"},
	} {
		t.Run(pair[0], func(t *testing.T) {
			source, destination := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
			defer resolver.TrackDNSUpstream(upstreamDNSConn{source: source, destination: destination})()
			handler := ListenerHandler{DnsAddrPorts: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:53")}}
			packet := buf.New()
			_, _ = packet.Write([]byte{0x12, 0x34, 0x01, 0x00})
			handler.NewPacket(context.Background(), source, packet, M.Metadata{
				Source: M.SocksaddrFromNetIP(source), Destination: M.SocksaddrFromNetIP(destination),
			}, func(network.PacketConn) network.PacketWriter {
				t.Fatal("recirculated upstream query reached the client DNS responder")
				return nil
			})
		})
	}
}
