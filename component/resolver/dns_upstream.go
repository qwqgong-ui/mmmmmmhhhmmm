package resolver

import (
	"net"
	"net/netip"
	"sync"
)

type dnsUpstreamTuple struct {
	source, destination netip.AddrPort
}

var activeDNSUpstreams = struct {
	sync.RWMutex
	entries map[dnsUpstreamTuple]int
}{entries: make(map[dnsUpstreamTuple]int)}

func normalizedDNSAddr(addr netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(addr.Addr().Unmap().WithZone(""), addr.Port())
}

// TrackDNSUpstream records a connected UDP DNS socket before its first write.
// An Android network optimizer can retransmit a protected socket's packet into
// the VPN. The TUN must not answer that packet with its client-facing fake-IP
// resolver: doing so fabricates an upstream response to our own query.
// The caller must release the registration before closing the socket.
func TrackDNSUpstream(conn net.Conn) func() {
	source, sourceOK := conn.LocalAddr().(*net.UDPAddr)
	destination, destinationOK := conn.RemoteAddr().(*net.UDPAddr)
	if !sourceOK || !destinationOK || !source.AddrPort().IsValid() || !destination.AddrPort().IsValid() {
		return func() {}
	}
	key := dnsUpstreamTuple{normalizedDNSAddr(source.AddrPort()), normalizedDNSAddr(destination.AddrPort())}
	activeDNSUpstreams.Lock()
	activeDNSUpstreams.entries[key]++
	activeDNSUpstreams.Unlock()
	return sync.OnceFunc(func() {
		activeDNSUpstreams.Lock()
		defer activeDNSUpstreams.Unlock()
		if activeDNSUpstreams.entries[key] <= 1 {
			delete(activeDNSUpstreams.entries, key)
		} else {
			activeDNSUpstreams.entries[key]--
		}
	})
}

// IsDNSUpstream identifies only the exact outbound tuple of an active query.
// Ordinary client DNS, including queries to the same server, remains unaffected.
func IsDNSUpstream(source, destination netip.AddrPort) bool {
	key := dnsUpstreamTuple{normalizedDNSAddr(source), normalizedDNSAddr(destination)}
	activeDNSUpstreams.RLock()
	active := activeDNSUpstreams.entries[key] != 0
	activeDNSUpstreams.RUnlock()
	return active
}
