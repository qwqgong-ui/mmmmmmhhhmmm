package tunnel

import (
	"io"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
)

// Join the opportunistic reader before accessing its buffer. A protocol
// handshake may carry already buffered data, but must also work without it.
func writeBufferedHandshake(conn *N.BufferedConn, peekMutex *sync.Mutex, remote io.Writer) (int, error) {
	_ = conn.SetReadDeadline(time.Now())
	peekMutex.Lock()
	defer peekMutex.Unlock()
	_ = conn.SetReadDeadline(time.Time{})
	data, _ := conn.Peek(conn.Buffered())
	if _, err := remote.Write(data); err != nil {
		return 0, err
	}
	if len(data) > 0 {
		_, _ = conn.Discard(len(data))
	}
	return len(data), nil
}
