package dns

import (
	"net/netip"
	"time"

	D "github.com/miekg/dns"
)

func msgToAddressIPs(msg *D.Msg, qType uint16) []netip.Addr {
	if msg == nil || msg.Rcode != D.RcodeSuccess {
		return nil
	}
	var ips []netip.Addr
	for _, ip := range msgToIP(msg) {
		if qType == D.TypeA && ip.Unmap().Is4() || qType == D.TypeAAAA && ip.Is6() && !ip.Is4In6() {
			ips = append(ips, ip.Unmap())
		}
	}
	return ips
}

func prepareDirectCachedMessage(q D.Question, msg *D.Msg) (*D.Msg, time.Time) {
	stored, due := prepareCachedMessage(q, msg)
	if len(msgToAddressIPs(stored, q.Qtype)) > 0 {
		return stored, due
	}
	// Cache complete per-source NODATA/NXDOMAIN answers independently of the
	// other family. Honor authoritative negative TTLs, including zero; when SOA
	// is absent, use the existing short local cooldown to avoid repeat queries.
	ttl := negativeCacheTTL
	for _, rr := range stored.Ns {
		if soa, ok := rr.(*D.SOA); ok {
			ttl = min(soa.Hdr.Ttl, soa.Minttl)
			break
		}
	}
	if len(stored.Answer) > 0 {
		ttl = min(ttl, minimalTTL(stored.Answer))
	}
	return stored, time.Now().Add(time.Duration(ttl) * time.Second)
}
