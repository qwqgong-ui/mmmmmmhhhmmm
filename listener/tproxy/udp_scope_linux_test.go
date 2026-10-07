//go:build linux

package tproxy

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestUDPAddrToSockAddrIPv6Zone(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{iface.Name, strconv.Itoa(iface.Index)} {
		t.Run(zone, func(t *testing.T) {
			addr := netip.AddrPortFrom(netip.MustParseAddr("fe80::53").WithZone(zone), 53)
			sa, err := udpAddrToSockAddr(addr)
			if err != nil {
				t.Fatal(err)
			}
			got := sa.(*syscall.SockaddrInet6)
			if got.ZoneId != uint32(iface.Index) || got.Port != 53 || got.Addr != addr.Addr().As16() {
				t.Fatalf("incorrect scoped sockaddr: %+v", got)
			}
		})
	}
	addr := netip.MustParseAddrPort("[fe80::53%no-such-tproxy]:53")
	if _, err := udpAddrToSockAddr(addr); err == nil {
		t.Fatal("unknown interface was silently converted to an unscoped IPv6 address")
	}
}

func TestGetOrigDstPreservesIPv6Scope(t *testing.T) {
	for _, zone := range []uint32{0, 3} {
		oob := make([]byte, unix.CmsgSpace(unix.SizeofSockaddrInet6))
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		header.SetLen(unix.CmsgLen(unix.SizeofSockaddrInet6))
		header.Level = unix.SOL_IPV6
		header.Type = IPV6_RECVORIGDSTADDR
		data := oob[unix.CmsgLen(0):]
		binary.NativeEndian.PutUint16(data, unix.AF_INET6)
		binary.BigEndian.PutUint16(data[2:4], 53)
		ip := netip.MustParseAddr("fe80::53")
		raw := ip.As16()
		copy(data[8:24], raw[:])
		binary.NativeEndian.PutUint32(data[24:28], zone)
		got, err := getOrigDst(oob)
		if err != nil {
			t.Fatal(err)
		}
		if zone != 0 {
			ip = ip.WithZone(strconv.FormatUint(uint64(zone), 10))
		}
		want := netip.AddrPortFrom(ip, 53)
		if got != want {
			t.Fatalf("original destination = %s, want %s", got, want)
		}
	}
}

func TestTProxyReplyRestoresLinkLocalScope(t *testing.T) {
	for _, tc := range []struct {
		original, client, reply, want string
	}{
		{"[fe80::53%3]:53", "[fe80::1%wlan0]:40000", "[fe80::53]:53", "[fe80::53%3]:53"},
		{"[fe80::53]:53", "[fe80::1%wlan0]:40000", "[fe80::53]:53", "[fe80::53%wlan0]:53"},
		{"[fe80::53%3]:53", "[fe80::1%wlan0]:40000", "[fe80::54%4]:54", "[fe80::54%4]:54"},
		{"[fe80::53%3]:53", "[fe80::1%wlan0]:40000", "[2001:db8::53]:53", "[2001:db8::53]:53"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			p := &packet{rAddr: netip.MustParseAddrPort(tc.original), lAddr: netip.MustParseAddrPort(tc.client)}
			got := p.scopedReplyAddr(netip.MustParseAddrPort(tc.reply))
			if got != netip.MustParseAddrPort(tc.want) {
				t.Fatalf("reply address = %s, want %s", got, tc.want)
			}
		})
	}
}
