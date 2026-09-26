//go:build !linux

package dialer

import "syscall"

func SocketStateForDiagnostics(syscall.RawConn) string { return "unavailable" }
