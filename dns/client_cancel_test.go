package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestDNSUDPTruncatedTCPFallbackCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	pc, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	server := &D.Server{PacketConn: pc, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg)
		m.SetReply(q)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	ready := make(chan struct{})
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var size uint16
		if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
			closed <- err
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, size)); err != nil {
			closed <- err
			return
		}
		close(ready)
		_, err = conn.Read(make([]byte, 1))
		closed <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newClient(listener.Addr().String(), nil, "udp", nil, nil, "")
	done := make(chan error, 1)
	go func() {
		q := new(D.Msg)
		q.SetQuestion("example.test.", D.TypeA)
		_, err := client.ExchangeContext(ctx, q)
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("TCP retry did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("query did not cancel")
	}
	select {
	case err := <-closed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("TCP retry socket not closed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("TCP retry kept running after cancellation")
	}
}
