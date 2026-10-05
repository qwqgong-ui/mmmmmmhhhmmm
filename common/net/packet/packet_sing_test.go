package packet

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type initializedWaiterConn struct {
	SingPacketConn
	initializations int
	payload         []byte
	err             error
	options         N.ReadWaitOptions
	lastBuffer      *buf.Buffer
	address         M.Socksaddr
}

func (c *initializedWaiterConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.initializations++
	c.options = options
	return false
}

func (c *initializedWaiterConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	c.lastBuffer = c.options.NewPacketBuffer()
	_, _ = c.lastBuffer.Write(c.payload)
	return c.lastBuffer, c.address, c.err
}

func TestSingPacketWaiterInitializedOnceAcrossReads(t *testing.T) {
	source := &initializedWaiterConn{address: M.ParseSocksaddr("example.com:443")}
	reader := newEnhanceSingPacketConn(source)
	for _, step := range []struct {
		payload []byte
		err     error
	}{{[]byte("first"), nil}, {nil, nil}, {nil, io.ErrUnexpectedEOF}, {[]byte("last"), nil}} {
		source.payload, source.err = step.payload, step.err
		data, put, addr, err := reader.WaitReadFrom()
		if !errors.Is(err, step.err) || !bytes.Equal(data, step.payload) {
			t.Fatalf("read = %q, %v; want %q, %v", data, err, step.payload, step.err)
		}
		if step.err == nil && len(step.payload) != 0 {
			if put == nil || addr.String() != "example.com:443" {
				t.Fatalf("missing release or destination: %v", addr)
			}
			put()
		} else if put != nil {
			t.Fatal("empty/failed read exposed a release callback")
		}
		if source.lastBuffer.Len() != 0 {
			t.Fatal("read buffer was not released")
		}
	}
	if source.initializations != 1 {
		t.Fatalf("waiter initialized %d times", source.initializations)
	}
}

type fallbackSingConn struct {
	SingPacketConn
	payload []byte
}

func (c *fallbackSingConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	_, err := buffer.Write(c.payload)
	return M.SocksaddrFromNet(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}), err
}

func TestSingPacketReadWithoutWaiter(t *testing.T) {
	source := &fallbackSingConn{payload: []byte("fallback")}
	reader := newEnhanceSingPacketConn(source)
	if reader.packetReadWaiter != nil {
		t.Fatal("unexpected read waiter")
	}
	data, put, addr, err := reader.WaitReadFrom()
	if err != nil || !bytes.Equal(data, source.payload) || put == nil || addr.String() != "192.0.2.1:443" {
		t.Fatalf("unexpected fallback read: %q, %v, %v", data, addr, err)
	}
	put()
}
