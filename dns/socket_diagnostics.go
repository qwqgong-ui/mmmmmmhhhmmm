package dns

import (
	"fmt"
	"net"
	"syscall"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

// Keep the socket tuple and DNS ID together: an upstream reply alone cannot
// distinguish an external DNS answer from a request intercepted by our TUN.
func logDNSSocket(event string, conn net.Conn, query, answer *D.Msg, err error) {
	if !log.Enabled(log.DEBUG) {
		return
	}
	mark := dnsSocketMark(conn)
	answers := ""
	if answer != nil {
		answers = msgToLogString(answer)
	}
	log.Fields(log.DEBUG, map[string]string{
		"subsystem": "dns", "event": "upstream_socket_" + event,
		"host": msgToDomain(query), "dns_id": fmt.Sprint(query.Id),
		"local": conn.LocalAddr().String(), "remote": conn.RemoteAddr().String(),
		"socket_mark": mark,
	}, "DNS socket %s id=%d %s local=%s remote=%s mark=%s answers=%s error=%v",
		event, query.Id, query.Question[0].String(), conn.LocalAddr(), conn.RemoteAddr(), mark, answers, err)
}

func dnsSocketMark(conn net.Conn) string {
	socket, ok := conn.(syscall.Conn)
	if !ok {
		return "unavailable"
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return "unavailable:" + err.Error()
	}
	return dialer.SocketStateForDiagnostics(raw)
}
