package packet

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestWaitReadFromRecoversAfterTimeoutAndEmptyDatagram(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	reader := NewEnhancePacketConn(listener)
	if err := reader.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	data, put, _, err := reader.WaitReadFrom()
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || data != nil || put != nil {
		t.Fatalf("unexpected timed-out read: %q, %v", data, err)
	}
	writer, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, payload := range [][]byte{nil, []byte("after empty packet")} {
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		data, put, _, err := reader.WaitReadFrom()
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatalf("read = %q, %v; want %q", data, err, payload)
		}
		if len(payload) == 0 {
			if put != nil {
				t.Fatal("empty datagram exposed a release callback")
			}
		} else {
			if put == nil {
				t.Fatal("missing release callback")
			}
			put()
		}
	}
}

// Hide *net.UDPConn to exercise the generic PacketConn reader as well.
type plainIntegrityPacketConn struct{ net.PacketConn }

func TestWaitReadFromPreservesLargeDatagrams(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, generic := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/generic=%v", network, generic), func(t *testing.T) {
				host := "127.0.0.1"
				if network == "udp6" {
					host = "::1"
				}
				listener, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
				if err != nil {
					if network == "udp6" {
						t.Skipf("IPv6 unavailable: %v", err)
					}
					t.Fatal(err)
				}
				defer listener.Close()
				var pc net.PacketConn = listener
				if generic {
					pc = plainIntegrityPacketConn{listener}
				}
				reader := NewEnhancePacketConn(pc)
				writer, err := net.Dial(network, listener.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				for _, size := range []int{1200, 8192, 16384, 16385, 32000, 65507} {
					payload := make([]byte, size)
					for i := range payload {
						payload[i] = byte(i % 251)
					}
					if _, err := writer.Write(payload); err != nil {
						t.Fatal(err)
					}
					if err := reader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
						t.Fatal(err)
					}
					data, put, _, err := reader.WaitReadFrom()
					if err != nil {
						if put != nil {
							put()
						}
						t.Fatal(err)
					}
					equal := bytes.Equal(data, payload)
					got := len(data)
					if put != nil {
						put()
					}
					if !equal {
						t.Fatalf("datagram corrupted: sent %d bytes, received %d", size, got)
					}
				}
			})
		}
	}
}
