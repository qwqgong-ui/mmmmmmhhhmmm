package androidcyaml

import (
	"syscall"

	"github.com/metacubex/mihomo/component/dev_cache"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/hub/executor"
)

// SetDirectNetworkEnvironment selects the network partition of all dev_cache
// answers, proxy bundles and TCP winners.
//
// Android cannot let the Go side discover the physical path itself, so
// AndroidCyaml supplies a privacy-preserving fingerprint of the current Wi-Fi or
// SIM combined with the interface's addresses and routes. Changing this value
// switches branches; it deliberately clears nothing, because the scoped keys are
// what keep one network's long-lived answers from being served on another.
func SetDirectNetworkEnvironment(environment string) {
	dialer.SetDirectNetworkEnvironment(environment)
}

// RetireNetworkScope drops all dev_cache entries belonging to a network the
// platform has stopped tracking, and reports how many entries were removed.
//
// Scoped keys keep a handover cheap: nothing is cleared, because each network's
// answers stay addressable under their own branch. Retirement is the case that
// leaves behind, and the platform is the only side that knows it happened. When
// AndroidCyaml drops a network profile -- aged out, or pushed past its cap --
// this removes the matching answers instead of letting them sit until their own
// expiry with nothing left to explain them.
func RetireNetworkScope(environment string) int {
	scope := dialer.EnvironmentScope(environment)
	if scope == "" {
		return 0
	}
	return dns.EvictNetworkScope(scope)
}

// SetTCPConcurrent toggles concurrent dialing across resolved addresses.
func SetTCPConcurrent(enabled bool) {
	dialer.SetTcpConcurrent(enabled)
}

// ClearTCPConcurrentCache drops the winning-address memory, which is bound to a
// physical path and meaningless once that path changes.
func ClearTCPConcurrentCache() {
	dialer.ClearTCPConcurrentCache()
}

// SetSystemIPv6Available supplies the platform's authoritative answer about
// IPv6 reachability.
//
// mihomo's own probe inspects local interfaces, which on Android sees the TUN's
// own addresses and concludes IPv6 works when the underlying network has no
// global address or default route at all. AndroidCyaml watches the real
// underlying network and answers for it.
func SetSystemIPv6Available(available bool) {
	executor.SetSystemIPv6Available(available)
}

// FlushInterfaceCache drops cached interface lookups after a physical route
// change.
func FlushInterfaceCache() {
	iface.FlushCache()
}

// ClearVolatileDNSCache requests refresh without discarding retained answers.
func ClearVolatileDNSCache() {
	dev_cache.RefreshScope(dev_cache.CurrentScope())
	resolver.ClearVolatileCache()
}

// ClearDNSCache drops every cached answer, including the scoped branches. This
// is memory reclamation, not a handover step.
func ClearDNSCache() {
	resolver.ClearCache()
	dns.FlushDevCache()
}

// ResetDNSConnections closes pooled resolver connections bound to a path that no
// longer exists.
func ResetDNSConnections() {
	resolver.ResetConnection()
}

// SocketHook receives every real outbound socket before it connects.
type SocketHook = func(network, address string, connection syscall.RawConn) error

// SetSocketHook installs the per-socket hook AndroidCyaml uses to keep upstream
// dials outside its own VPN. Passing nil removes it.
//
// Every socket the core dials for real traffic passes through here. The TUN
// stack's internal listeners do not, which is what keeps reinjected traffic on
// the TUN data path.
func SetSocketHook(hook SocketHook) {
	dialer.DefaultSocketHook = hook
}
