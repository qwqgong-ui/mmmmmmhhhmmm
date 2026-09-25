package dns

import (
	"errors"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"
)

var errUpstreamFakeIP = errors.New("upstream DNS returned this resolver's fake-IP address")

// Fake-IP answers belong only to the client-facing DNS middleware. Accepting
// them as real upstream addresses makes DIRECT and DNS bootstrap dial the TUN
// again, and retained caches can keep that loop alive after a network handover.
func hasUpstreamFakeIP(msg *D.Msg) bool {
	if msg == nil {
		return false
	}
	for _, ip := range msgToIP(msg) {
		if resolver.IsFakeIP(ip) {
			return true
		}
	}
	return false
}

// Check retained records on read as well: earlier versions may have persisted
// a bad answer. The atomic check cannot erase a concurrent valid replacement.
// This never touches the client-facing fake-IP-to-host mapping pool.
func readUpstreamCache(c dnsCache, key string) (*D.Msg, time.Time, bool) {
	return c.GetWithExpireValidated(key, func(msg *D.Msg) bool {
		return msg != nil && !hasUpstreamFakeIP(msg)
	})
}
