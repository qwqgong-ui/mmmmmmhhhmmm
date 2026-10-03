package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
)

type handshakeWriter struct {
	data  []byte
	calls int
	err   error
}

func (w *handshakeWriter) Write(p []byte) (int, error) {
	w.calls++
	w.data = append(w.data, p...)
	return len(p), w.err
}

func TestTCPHandshakeCancelsPeekAndRelaysLateData(t *testing.T) {
	for range 50 {
		client, peer := net.Pipe()
		conn := N.NewBufferedConn(client)
		var lock sync.Mutex
		lock.Lock()
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		go func() { defer lock.Unlock(); conn.Peek(1) }()
		writer := &handshakeWriter{}
		started := time.Now()
		n, err := writeBufferedHandshake(conn, &lock, writer)
		if err != nil || n != 0 || writer.calls != 1 {
			t.Fatalf("n=%d err=%v calls=%d", n, err, writer.calls)
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("waited for first byte: %s", elapsed)
		}
		sent := make(chan error, 1)
		go func() { _, err := peer.Write([]byte("late payload")); sent <- err }()
		data := make([]byte, len("late payload"))
		conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(conn, data); err != nil || string(data) != "late payload" {
			t.Fatalf("%q %v", data, err)
		}
		if err := <-sent; err != nil {
			t.Fatal(err)
		}
		client.Close()
		peer.Close()
	}
}

func TestTCPHandshakeBufferedPayloadIsSentExactlyOnce(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	conn := N.NewBufferedConn(client)
	conn.AppendData([]byte("early payload"))
	var lock sync.Mutex
	writer := &handshakeWriter{}
	n, err := writeBufferedHandshake(conn, &lock, writer)
	if err != nil || n != len("early payload") || !bytes.Equal(writer.data, []byte("early payload")) || conn.Buffered() != 0 {
		t.Fatalf("n=%d err=%v data=%q buffered=%d", n, err, writer.data, conn.Buffered())
	}
}

func TestTCPHandshakeFailureRetainsBufferedPayloadForRetry(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	conn := N.NewBufferedConn(client)
	conn.AppendData([]byte("early payload"))
	var lock sync.Mutex
	failed := &handshakeWriter{err: errors.New("write failed")}
	if _, err := writeBufferedHandshake(conn, &lock, failed); err == nil {
		t.Fatal("missing error")
	}
	retry := &handshakeWriter{}
	if n, err := writeBufferedHandshake(conn, &lock, retry); err != nil || n != len("early payload") || string(retry.data) != "early payload" {
		t.Fatalf("n=%d err=%v data=%q", n, err, retry.data)
	}
}
