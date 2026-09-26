//go:build linux

package dialer

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SocketStateForDiagnostics reads SO_MARK without modifying socket routing.
func SocketStateForDiagnostics(raw syscall.RawConn) string {
	var mark int
	var descriptor uintptr
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		descriptor = fd
		mark, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		return "unavailable:" + err.Error()
	}
	if socketErr != nil {
		return "unavailable:" + socketErr.Error()
	}
	return fmt.Sprintf("0x%x(fd=%d)", uint32(mark), descriptor)
}
