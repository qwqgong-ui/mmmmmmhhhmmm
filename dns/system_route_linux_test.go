//go:build linux

package dns

import (
	"net"
	"net/netip"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func systemRouteReply(t *testing.T, request netlink.Message, kind byte, index uint32) netlink.Message {
	t.Helper()
	data := make([]byte, unix.SizeofRtMsg)
	data[0] = request.Data[0]
	data[7] = kind
	encoder := netlink.NewAttributeEncoder()
	encoder.Uint32(unix.RTA_OIF, index)
	attributes, err := encoder.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return netlink.Message{Header: netlink.Header{
		Type: unix.RTM_NEWROUTE, Sequence: request.Header.Sequence, PID: request.Header.PID,
	}, Data: append(data, attributes...)}
}

func TestSystemRouteInterfaceWithoutTunUsesBypassMark(t *testing.T) {
	conn := nltest.Dial(func(requests []netlink.Message) ([]netlink.Message, error) {
		request := requests[0]
		if request.Header.Type != unix.RTM_GETROUTE || request.Data[0] != unix.AF_INET || request.Data[1] != 32 {
			t.Fatalf("unexpected route request: %+v", request)
		}
		decoder, err := netlink.NewAttributeDecoder(request.Data[unix.SizeofRtMsg:])
		if err != nil {
			t.Fatal(err)
		}
		var mark uint32
		var destination netip.Addr
		for decoder.Next() {
			switch decoder.Type() {
			case unix.RTA_MARK:
				mark = decoder.Uint32()
			case unix.RTA_DST:
				destination, _ = netip.AddrFromSlice(decoder.Bytes())
			}
		}
		if err := decoder.Err(); err != nil {
			t.Fatal(err)
		}
		if mark != 666 || destination != netip.MustParseAddr("1.1.1.1") {
			t.Fatalf("upstream route query lost its mark or destination: %d, %s", mark, destination)
		}
		return []netlink.Message{systemRouteReply(t, request, unix.RTN_UNICAST, 10)}, nil
	})
	defer conn.Close()
	got, err := systemRouteInterface(conn, 666, func(index int) (*net.Interface, error) {
		if index != 10 {
			t.Fatalf("looked up the wrong interface: %d", index)
		}
		return &net.Interface{Name: "wlan-test", Flags: net.FlagUp}, nil
	})
	if err != nil || got != "wlan-test" {
		t.Fatalf("physical interface = %q, %v", got, err)
	}
}

func TestSystemRouteInterfaceRejectsTProxyLocalRouteAndUsesIPv6(t *testing.T) {
	var queries int
	conn := nltest.Dial(func(requests []netlink.Message) ([]netlink.Message, error) {
		queries++
		request := requests[0]
		kind := byte(unix.RTN_LOCAL)
		if request.Data[0] == unix.AF_INET6 {
			kind = unix.RTN_UNICAST
		}
		return []netlink.Message{systemRouteReply(t, request, kind, 10)}, nil
	})
	defer conn.Close()
	got, err := systemRouteInterface(conn, 666, func(int) (*net.Interface, error) {
		return &net.Interface{Name: "eth-test", Flags: net.FlagUp}, nil
	})
	if err != nil || got != "eth-test" || queries != 2 {
		t.Fatalf("physical interface = %q, %v; queried %d families", got, err, queries)
	}
}

func TestSystemRouteInterfaceRejectsLoopbackAndDownDevices(t *testing.T) {
	conn := nltest.Dial(func(requests []netlink.Message) ([]netlink.Message, error) {
		return []netlink.Message{systemRouteReply(t, requests[0], unix.RTN_UNICAST, 10)}, nil
	})
	defer conn.Close()
	for _, flags := range []net.Flags{net.FlagUp | net.FlagLoopback, 0} {
		got, err := systemRouteInterface(conn, 666, func(int) (*net.Interface, error) {
			return &net.Interface{Name: "unusable", Flags: flags}, nil
		})
		if err == nil || got != "" {
			t.Fatalf("selected an unusable physical interface: %q, %v", got, err)
		}
	}
}
