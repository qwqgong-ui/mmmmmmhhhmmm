package route

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gobwas/ws"
)

// Only exists while a controller has a live log subscription; no idle timer
// or goroutine is added to normal networking. The reader handles close/ping
// even when no log events arrive, and bounds incoming controller frames.
type logWebSocket struct {
	net.Conn
	mu sync.Mutex
}

func (c *logWebSocket) write(op byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return wsWriteServerMessage(c.Conn, op, payload)
}

func (c *logWebSocket) readUntilClosed(reader io.Reader, done chan<- struct{}) {
	defer close(done)
	defer c.Close()
	for {
		header, err := ws.ReadHeader(reader)
		if err != nil || !header.Masked || header.Length < 0 || header.Length > 65536 {
			return
		}
		if header.OpCode.IsControl() {
			if !header.Fin || header.Length > 125 {
				return
			}
			payload := make([]byte, int(header.Length))
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}
			ws.Cipher(payload, header.Mask, 0)
			switch header.OpCode {
			case ws.OpClose:
				return
			case ws.OpPing:
				if err := c.write(byte(ws.OpPong), payload); err != nil {
					return
				}
			}
		} else if _, err := io.CopyN(io.Discard, reader, header.Length); err != nil {
			return
		}
	}
}
