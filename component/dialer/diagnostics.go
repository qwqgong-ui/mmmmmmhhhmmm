package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/log"
)

func logDirectAttempt(host, port, scope string, ip netip.Addr, rtt time.Duration, err error, cached bool) {
	if !log.Enabled(log.DEBUG) {
		return
	}
	reason := "connected"
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		reason = "cancelled"
	case errors.Is(err, syscall.ECONNREFUSED):
		reason = "refused"
	case errors.As(err, &netErr) && netErr.Timeout():
		reason = "timeout"
	case err != nil:
		reason = "connect_error"
	}
	log.Fields(log.DEBUG, map[string]string{"subsystem": "direct", "event": "tcp_attempt", "host": host, "network_scope": scope, "reason": reason, "latency_ms": fmt.Sprint(float64(rtt) / float64(time.Millisecond))}, "DIRECT TCP %s:%s candidate=%s cached=%t RTT=%s result=%s error=%v", host, port, ip, cached, rtt, reason, err)
}
