package dialer

import (
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/log"
)

var directNetworkEnvironment = atomic.NewTypedValue[string]("")

// SetDirectNetworkEnvironment supplies a stable platform-owned network
// identity when the Go process cannot discover the physical path itself. The
// Android VPN wrapper uses a privacy-preserving Wi-Fi/SIM fingerprint.
func SetDirectNetworkEnvironment(environment string) {
	environment = strings.TrimSpace(environment)
	old := directNetworkEnvironment.Swap(environment)
	if old == environment {
		return
	}
	log.Fields(log.INFO, map[string]string{"subsystem": "network", "event": "scope_changed", "network_scope": EnvironmentScope(environment), "old_network_scope": EnvironmentScope(old), "reason": "platform_update"}, "Network scope changed: %s -> %s", EnvironmentScope(old), EnvironmentScope(environment))
}

type NetworkStatus struct {
	Interface      string `json:"interface"`
	NetworkScope   string `json:"networkScope"`
	IPv4           bool   `json:"ipv4"`
	IPv6           bool   `json:"ipv6"`
	AddressesKnown bool   `json:"addressesKnown"`
	Reason         string `json:"reason,omitempty"`
}

func CurrentNetworkStatus() NetworkStatus {
	name := currentInterfaceName("")
	status := NetworkStatus{Interface: name, NetworkScope: "default"}
	if name != "" {
		status.NetworkScope = name
	}
	environment := EnvironmentScope(directNetworkEnvironment.Load())
	if environment != "" {
		status.NetworkScope = environment
	}
	if name == "" {
		status.Reason = "physical_interface_unknown"
		return status
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		status.Reason = err.Error()
		return status
	}
	addresses, err := iface.Addrs()
	if err != nil {
		status.Reason = err.Error()
		return status
	}
	status.AddressesKnown = true
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		prefixes = append(prefixes, prefix)
		if prefix.Addr().Is4() {
			status.IPv4 = true
		} else {
			status.IPv6 = true
		}
	}
	if environment == "" {
		status.NetworkScope = scopeForPrefixes(name, prefixes)
	}
	return status
}

// NetworkScope applies the outbound's interface choice when describing its
// path, rather than mislabelling a bound socket with the default interface.
func NetworkScope(options ...Option) string {
	var opt option
	for _, apply := range options {
		apply(&opt)
	}
	return directNetworkScope(opt)
}

// environmentScopePrefix marks a scope the platform named rather than one
// derived from local interfaces.
const environmentScopePrefix = "environment|"

// EnvironmentScope reports the scope string a given platform environment
// produces. An embedder needs it to address a branch it created earlier -- to
// evict the answers of a network it has stopped tracking, for example -- and
// deriving that string a second time by hand is how the two drift apart.
func EnvironmentScope(environment string) string {
	environment = strings.TrimSpace(environment)
	if environment == "" {
		return ""
	}
	return environmentScopePrefix + environment
}

func directNetworkScope(opt option) string {
	if environment := directNetworkEnvironment.Load(); environment != "" {
		return environmentScopePrefix + environment
	}
	interfaceName := currentInterfaceName(opt.interfaceName)
	if interfaceName == "" {
		return "default"
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return interfaceName
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return interfaceName
	}
	prefixes := make([]netip.Prefix, 0, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return scopeForPrefixes(interfaceName, prefixes)
}

func currentInterfaceName(configured string) string {
	if configured != "" {
		return configured
	}
	if name := DefaultInterface.Load(); name != "" {
		return name
	}
	if finder := DefaultInterfaceFinder.Load(); finder != nil {
		return finder.FindInterfaceName(netip.MustParseAddr("1.1.1.1"))
	}
	return ""
}

func scopeForPrefixes(interfaceName string, prefixes []netip.Prefix) string {
	parts := make([]string, 0, len(prefixes))
	private192 := netip.MustParsePrefix("192.168.0.0/16")
	for _, prefix := range prefixes {
		addr := prefix.Addr().Unmap()
		if !addr.IsValid() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		if addr.Is4() && private192.Contains(addr) {
			prefix = netip.PrefixFrom(addr, 16)
		} else if addr != prefix.Addr() {
			prefix = netip.PrefixFrom(addr, min(prefix.Bits(), addr.BitLen()))
		}
		parts = append(parts, prefix.Masked().String())
	}
	sort.Strings(parts)
	parts = compactStrings(parts)
	if len(parts) == 0 {
		return interfaceName
	}
	return interfaceName + "|" + strings.Join(parts, ",")
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] == values[write-1] {
			continue
		}
		values[write] = values[read]
		write++
	}
	return values[:write]
}
