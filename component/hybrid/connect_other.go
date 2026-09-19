//go:build !unix && !windows

package hybrid

import (
	"errors"
	"net"
	"net/netip"
)

func connectSocket(c *net.UDPConn, relay netip.AddrPort) error {
	return errors.New("hybrid: connecting a raw socket is unsupported here")
}
