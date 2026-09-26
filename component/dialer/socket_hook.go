package dialer

import (
	"context"
	"net"
	"strings"
	"syscall"

	"github.com/metacubex/mihomo/log"
)

// SocketControl
// never change type traits because it's used in CMFA
type SocketControl func(network, address string, conn syscall.RawConn) error

// DefaultSocketHook
// never change type traits because it's used in CMFA
var DefaultSocketHook SocketControl

func socketHookToToDialer(dialer *net.Dialer) {
	addControlToDialer(dialer, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return runSocketHook(network, address, c)
	})
}

func socketHookToListenConfig(lc *net.ListenConfig) {
	addControlToListenConfig(lc, func(ctx context.Context, network, address string, c syscall.RawConn) error {
		return runSocketHook(network, address, c)
	})
}

func runSocketHook(network, address string, c syscall.RawConn) error {
	if !log.Enabled(log.DEBUG) || !strings.HasSuffix(address, ":53") {
		return DefaultSocketHook(network, address, c)
	}
	before := SocketStateForDiagnostics(c)
	err := DefaultSocketHook(network, address, c)
	after := SocketStateForDiagnostics(c)
	log.Debugln("[DNS] socket hook network=%s remote=%s mark=%s -> %s error=%v", network, address, before, after, err)
	return err
}
