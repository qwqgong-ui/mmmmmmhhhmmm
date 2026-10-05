//go:build !windows

package packet

import (
	"net"
	"syscall"
	"testing"
)

// Send only after the empty socket returns EAGAIN. This makes both versions
// exercise the same failed and successful raw read, without arbitrary sleeps.
type coldBenchmarkRawConn struct {
	syscall.RawConn
	writer  net.Conn
	payload []byte
	err     error
}

func (c *coldBenchmarkRawConn) Read(read func(uintptr) bool) error {
	return c.RawConn.Read(func(fd uintptr) bool {
		if read(fd) {
			return true
		}
		_, c.err = c.writer.Write(c.payload)
		return c.err != nil
	})
}

func BenchmarkUDPReadAfterEAGAIN(b *testing.B) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer listener.Close()
	writer, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer writer.Close()
	raw, err := listener.SyscallConn()
	if err != nil {
		b.Fatal(err)
	}
	source := &coldBenchmarkRawConn{RawConn: raw, writer: writer, payload: make([]byte, 1200)}
	reader := &enhanceUDPConn{UDPConn: listener, rawConn: source}
	benchmarkPacketReadLatency(b, func() {
		data, put, _, err := reader.WaitReadFrom()
		if err != nil || source.err != nil || len(data) != len(source.payload) || put == nil {
			b.Fatal("unexpected cold packet", len(data), err, source.err)
		}
		put()
	})
}
