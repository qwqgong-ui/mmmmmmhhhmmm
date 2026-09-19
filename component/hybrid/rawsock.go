package hybrid

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// rawSocketBuffer sizes the raw path's socket buffers. A browser's inner QUIC
// connection bursts well past the system defaults on a fast link, and whatever
// the kernel drops there looks like real loss to it. The kernel clamps the
// request to its own maximum (net.core.rmem_max on Linux), so a small limit
// simply keeps the previous behaviour.
const rawSocketBuffer = 1 << 20

// rawSocket is one flow's raw UDP path.
//
// The socket is connected to the relay wherever the platform allows it. The
// kernel then keeps the route with the socket instead of looking it up per
// datagram, drops every other source before it reaches us, and reports this
// path's ICMP errors, so sending needs no destination address and receiving no
// source check. Where connect fails the unconnected socket is kept and the
// source is compared as an addr:port, never as text.
type rawSocket struct {
	pc        net.PacketConn
	relay     netip.AddrPort
	relayAddr netip.Addr
	relayUDP  *net.UDPAddr
	conn      connectedConn
}

// connectedConn is the connected-socket subset of *net.UDPConn. Read and Write
// are plain read(2)/write(2), which a socket connected behind the standard
// library's back accepts everywhere; sendto(2) with an address does not.
type connectedConn interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
}

func newRawSocket(pc net.PacketConn, relay netip.AddrPort) *rawSocket {
	s := unconnectedSocket(pc, relay)
	if udp, ok := pc.(*net.UDPConn); ok {
		// Both are best effort: the system maximum wins where it is lower.
		udp.SetReadBuffer(rawSocketBuffer)
		udp.SetWriteBuffer(rawSocketBuffer)
		if connectSocket(udp, relay) == nil {
			s.conn = udp
		}
	}
	return s
}

// unconnectedSocket is the state every raw socket starts from, and all a
// platform without connect(2) ever has.
func unconnectedSocket(pc net.PacketConn, relay netip.AddrPort) *rawSocket {
	return &rawSocket{pc: pc, relay: relay, relayAddr: relay.Addr().Unmap(), relayUDP: net.UDPAddrFromAddrPort(relay)}
}

func (s *rawSocket) connected() bool { return s.conn != nil }

func (s *rawSocket) write(p []byte) (int, error) {
	if s.conn != nil {
		return s.conn.Write(p)
	}
	return s.pc.WriteTo(p, s.relayUDP)
}

// read returns the next datagram and whether it came from the relay. Only an
// unconnected socket can see another source.
func (s *rawSocket) read(b []byte) (int, bool, error) {
	if s.conn != nil {
		n, err := s.conn.Read(b)
		return n, err == nil, err
	}
	n, a, err := s.pc.ReadFrom(b)
	if err != nil {
		return n, false, err
	}
	return n, s.fromRelay(a), nil
}

func (s *rawSocket) fromRelay(a net.Addr) bool {
	u, ok := a.(*net.UDPAddr)
	if !ok {
		return a != nil && a.String() == s.relayUDP.String()
	}
	ap := u.AddrPort()
	return ap.Port() == s.relay.Port() && ap.Addr().Unmap() == s.relayAddr
}

func (s *rawSocket) Close() error                       { return s.pc.Close() }
func (s *rawSocket) SetWriteDeadline(t time.Time) error { return s.pc.SetWriteDeadline(t) }

// transientError reports whether an error came from an ICMP message about one
// datagram rather than from the socket itself. The kernel reports one per
// offending datagram and the socket keeps working, so the raw path must not
// give up on them: an unconnected socket never saw them at all, and the probe
// and silence timeouts remain the only reasons to fall back.
func transientError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.EMSGSIZE)
}
