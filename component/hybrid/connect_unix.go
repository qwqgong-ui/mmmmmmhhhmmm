//go:build unix

package hybrid

import (
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// connectSocket connects an already bound UDP socket to the relay, keeping the
// interface binding and routing mark the dialer applied when it was created.
// connect(2) on a datagram socket only records the peer, so there is nothing
// to wait for and no blocking call inside Control.
func connectSocket(c *net.UDPConn, relay netip.AddrPort) error {
	var sa unix.Sockaddr
	if addr := relay.Addr(); addr.Is4() {
		s := &unix.SockaddrInet4{Port: int(relay.Port())}
		s.Addr = addr.As4()
		sa = s
	} else {
		s := &unix.SockaddrInet6{Port: int(relay.Port())}
		s.Addr = addr.As16()
		sa = s
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var connErr error
	if err = rc.Control(func(fd uintptr) { connErr = unix.Connect(int(fd), sa) }); err != nil {
		return err
	}
	return connErr
}
