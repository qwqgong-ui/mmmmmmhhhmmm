package dialer

import (
	"net"
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/dev_cache"
	"github.com/metacubex/mihomo/log"
)

var directNetworkEnvironment = atomic.NewTypedValue[string]("")

// SetDirectNetworkEnvironment supplies a stable platform-owned network
// identity when the Go process cannot discover the physical path itself. The
// Android VPN wrapper uses a privacy-preserving Wi-Fi/SIM fingerprint.
func SetDirectNetworkEnvironment(environment string) {
	environment = strings.TrimSpace(environment)
	old := directNetworkEnvironment.Swap(environment)
	dev_cache.SetEnvironment(environment)
	if old != environment {
		NotifyNetworkChange()
		log.Fields(log.INFO, map[string]string{"subsystem": "network", "event": "scope_changed", "network_scope": EnvironmentScope(environment), "old_network_scope": EnvironmentScope(old), "reason": "platform_update"}, "Network cache partition changed")
	}
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
	status := NetworkStatus{Interface: name, NetworkScope: directNetworkScope(option{})}
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
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.Is4() {
			status.IPv4 = true
		} else {
			status.IPv6 = true
		}
	}
	return status
}

func NetworkScope(options ...Option) string {
	var opt option
	for _, apply := range options {
		apply(&opt)
	}
	return directNetworkScope(opt)
}

func init() { dev_cache.SetDesktopScopeProvider(func() string { return directNetworkScope(option{}) }) }

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
		return dev_cache.DesktopScope(nil)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return dev_cache.DesktopScope(nil)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return dev_cache.DesktopScope(nil)
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
	return dev_cache.DesktopScope(prefixes)
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
