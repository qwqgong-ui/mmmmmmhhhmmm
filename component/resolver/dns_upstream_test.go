package resolver

import (
	"net"
	"net/netip"
	"testing"
)

type upstreamTestConn struct {
	net.Conn
	local, remote net.Addr
}

func (c upstreamTestConn) LocalAddr() net.Addr  { return c.local }
func (c upstreamTestConn) RemoteAddr() net.Addr { return c.remote }

func TestDNSUpstreamTupleAndLifetime(t *testing.T) {
	for _, pair := range [][2]string{
		{"10.0.0.2:41325", "223.5.5.5:53"},
		{"[2001:db8::1]:41325", "[2001:db8::53]:53"},
		{"[::ffff:10.0.0.2]:41325", "[::ffff:223.5.5.5]:53"},
		{"[fe80::1%wlan0]:41325", "[fe80::53%wlan0]:53"},
	} {
		t.Run(pair[0], func(t *testing.T) {
			source, destination := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
			conn := upstreamTestConn{local: net.UDPAddrFromAddrPort(source), remote: net.UDPAddrFromAddrPort(destination)}
			release := TrackDNSUpstream(conn)
			if !IsDNSUpstream(normalizedDNSAddr(source), normalizedDNSAddr(destination)) {
				t.Fatal("active upstream query not recognized")
			}
			if IsDNSUpstream(destination, source) || IsDNSUpstream(netip.AddrPortFrom(source.Addr(), source.Port()+1), destination) {
				t.Fatal("response or unrelated client query matched upstream")
			}
			otherRelease := TrackDNSUpstream(conn)
			release()
			release() // Cleanup must not remove another owner's registration.
			if !IsDNSUpstream(source, destination) {
				t.Fatal("overlapping registration removed early")
			}
			otherRelease()
			if IsDNSUpstream(source, destination) {
				t.Fatal("closed query tuple retained")
			}
		})
	}
}

func TestDNSUpstreamDoesNotTrackTCP(t *testing.T) {
	source := netip.MustParseAddrPort("10.0.0.2:41325")
	destination := netip.MustParseAddrPort("223.5.5.5:53")
	conn := upstreamTestConn{local: net.TCPAddrFromAddrPort(source), remote: net.TCPAddrFromAddrPort(destination)}
	defer TrackDNSUpstream(conn)()
	if IsDNSUpstream(source, destination) {
		t.Fatal("TCP connection registered as UDP")
	}
}
