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
	if err == nil && rtt == 0 {
		reason = "tfo_deferred"
	}
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
	fields := map[string]string{"subsystem": "direct", "event": "tcp_attempt", "host": host, "network_scope": scope, "reason": reason, "rtt_known": "false"}
	if rtt > 0 {
		fields["rtt_known"] = "true"
		fields["latency_ms"] = fmt.Sprint(float64(rtt) / float64(time.Millisecond))
	}
	log.Fields(log.DEBUG, fields, "DIRECT TCP %s:%s candidate=%s cached=%t RTT=%s result=%s error=%v", host, port, ip, cached, rtt, reason, err)
}
