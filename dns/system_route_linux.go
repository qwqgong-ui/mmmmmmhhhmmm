//go:build linux

package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/dialer"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func linuxDefaultPhysicalInterface() (string, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return "", err
	}
	// Use the same mark as upstream sockets, so policy routing skips our local
	// TPROXY routes. RTM_GETROUTE only queries the kernel; it sends no probe traffic.
	return systemRouteInterface(conn, uint32(dialer.DefaultRoutingMark.Load()), net.InterfaceByIndex)
}

func systemRouteInterface(conn *netlink.Conn, mark uint32, lookup func(int) (*net.Interface, error)) (string, error) {
	var lastErr error
	for _, destination := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		index, err := systemRouteInterfaceIndex(conn, netip.MustParseAddr(destination), mark)
		if err != nil {
			lastErr = err
			continue
		}
		iface, err := lookup(index)
		if err != nil {
			lastErr = err
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			lastErr = fmt.Errorf("route selects an unavailable or loopback interface %q", iface.Name)
			continue
		}
		return iface.Name, nil
	}
	return "", fmt.Errorf("no usable upstream route: %w", lastErr)
}

func systemRouteInterfaceIndex(conn *netlink.Conn, destination netip.Addr, mark uint32) (int, error) {
	request := netlink.Message{Header: netlink.Header{Type: unix.RTM_GETROUTE, Flags: netlink.Request}}
	request.Data = make([]byte, unix.SizeofRtMsg)
	request.Data[0] = unix.AF_INET6
	if destination.Is4() {
		request.Data[0] = unix.AF_INET
	}
	request.Data[1] = byte(destination.BitLen())
	attributes := netlink.NewAttributeEncoder()
	attributes.Bytes(unix.RTA_DST, destination.AsSlice())
	attributes.Uint32(unix.RTA_MARK, mark)
	data, err := attributes.Encode()
	if err != nil {
		return 0, err
	}
	request.Data = append(request.Data, data...)
	messages, err := conn.Execute(request)
	if err != nil {
		return 0, err
	}
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWROUTE || len(message.Data) < unix.SizeofRtMsg ||
			message.Data[0] != request.Data[0] || message.Data[7] != unix.RTN_UNICAST {
			continue
		}
		decoder, err := netlink.NewAttributeDecoder(message.Data[unix.SizeofRtMsg:])
		if err != nil {
			return 0, err
		}
		var index uint32
		for decoder.Next() {
			if decoder.Type() == unix.RTA_OIF {
				index = decoder.Uint32()
			}
		}
		if err := decoder.Err(); err != nil {
			return 0, err
		}
		if index != 0 {
			return int(index), nil
		}
	}
	return 0, errors.New("route has no unicast output interface")
}
