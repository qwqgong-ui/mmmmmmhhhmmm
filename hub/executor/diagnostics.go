package executor

import (
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"net/netip"
)

// Capture runtime-owned resolver pointers under the same lock as config
// replacement. The immutable resolver generation remains alive for the query.
func DiagnosticResolvers() (resolver.Service, resolver.Resolver, bool) {
	mux.Lock()
	defer mux.Unlock()
	fakeIP := resolver.DefaultHostMapper != nil && resolver.DefaultHostMapper.FakeIPEnabled()
	return resolver.DefaultService, resolver.DirectHostResolver, fakeIP
}

func DiagnosticPath(host string, port uint16, network C.NetWork) (tunnel.RouteDiagnostic, resolver.Service, resolver.Resolver, bool, error) {
	mux.Lock()
	defer mux.Unlock()
	var ip netip.Addr
	if node, ok := resolver.DefaultHosts.Search(host, false); ok && len(node.IPs) > 0 {
		ip = node.IPs[0]
	}
	route, err := tunnel.DiagnoseRoute(host, port, network, ip)
	fakeIP := resolver.DefaultHostMapper != nil && resolver.DefaultHostMapper.FakeIPEnabled()
	return route, resolver.DefaultService, resolver.DirectHostResolver, fakeIP, err
}
