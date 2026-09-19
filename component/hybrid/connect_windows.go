//go:build windows

package hybrid

import (
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
)

func connectSocket(c *net.UDPConn, relay netip.AddrPort) error {
	var sa windows.Sockaddr
	if addr := relay.Addr(); addr.Is4() {
		s := &windows.SockaddrInet4{Port: int(relay.Port())}
		s.Addr = addr.As4()
		sa = s
	} else {
		s := &windows.SockaddrInet6{Port: int(relay.Port())}
		s.Addr = addr.As16()
		sa = s
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var connErr error
	if err = rc.Control(func(fd uintptr) { connErr = windows.Connect(windows.Handle(fd), sa) }); err != nil {
		return err
	}
	return connErr
}
