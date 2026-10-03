//go:build linux

package tproxy

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type integrityTunnel struct {
	C.Tunnel
	packets chan C.UDPPacket
}

func (t *integrityTunnel) HandleUDPPacket(packet C.UDPPacket, _ *C.Metadata) {
	t.packets <- packet
}

func TestTProxyPreservesLargeDatagrams(t *testing.T) {
	tunnel := &integrityTunnel{packets: make(chan C.UDPPacket, 1)}
	listener, err := NewUDP("127.0.0.1:0", tunnel)
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skip("IP_TRANSPARENT requires CAP_NET_ADMIN or CAP_NET_RAW")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target := listener.packetConn.LocalAddr().(*net.UDPAddr).AddrPort()
	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	check := func(size int) {
		t.Helper()
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		if _, err := client.Write(payload); err != nil {
			t.Fatal(err)
		}
		select {
		case packet := <-tunnel.packets:
			got := len(packet.Data())
			equal := bytes.Equal(packet.Data(), payload)
			packet.Drop()
			if !equal {
				t.Fatalf("sent %d bytes, received %d", size, got)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out receiving %d-byte datagram", size)
		}
	}
	for _, size := range []int{1200, 16385, 32000, 65507} {
		check(size)
	}
	// Exercise the connected transparent socket used for subsequent packets,
	// independently of the original listener.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	local := client.LocalAddr().(*net.UDPAddr).AddrPort()
	conn, err := listenLocalConn(netip.AddrPortFrom(target.Addr(), target.Port()), local, tunnel)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, size := range []int{1200, 16385, 32000, 65507} {
		check(size)
	}
}
