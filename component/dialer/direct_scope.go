package dialer

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

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
	status := cachedNetworkStatus(currentInterfaceName(""))
	if environment := directNetworkEnvironment.Load(); environment != "" {
		status.NetworkScope = EnvironmentScope(environment)
	}
	return status
}

// Events invalidate immediately. The bounded age also covers unavailable
// monitors and address updates that an embedding platform does not report.
const networkStatusMaxAge = 250 * time.Millisecond

type networkStatusSample struct {
	status     NetworkStatus
	generation uint64
	due        time.Time
}

var networkStatusCache = struct {
	sync.Mutex
	entries map[string]networkStatusSample
	loading map[string]chan struct{}
}{entries: make(map[string]networkStatusSample), loading: make(map[string]chan struct{})}

var readNetworkStatus = sampleNetworkStatus

func cachedNetworkStatus(name string) NetworkStatus {
	for changes := 0; changes < 2; {
		networkStatusCache.Lock()
		now := time.Now()
		generation := NetworkGeneration()
		entry, hit := networkStatusCache.entries[name]
		if hit && entry.generation == generation && now.Before(entry.due) {
			networkStatusCache.Unlock()
			return entry.status
		}
		if loading := networkStatusCache.loading[name]; loading != nil {
			networkStatusCache.Unlock()
			<-loading
			if NetworkGeneration() != generation {
				changes++
			}
			continue
		}
		done := make(chan struct{})
		networkStatusCache.loading[name] = done
		networkStatusCache.Unlock()
		status := readNetworkStatus(name)
		networkStatusCache.Lock()
		delete(networkStatusCache.loading, name)
		close(done)
		if generation != NetworkGeneration() {
			networkStatusCache.Unlock()
			changes++
			continue
		}
		if len(networkStatusCache.entries) >= 16 {
			clear(networkStatusCache.entries)
		}
		networkStatusCache.entries[name] = networkStatusSample{status, generation, time.Now().Add(networkStatusMaxAge)}
		networkStatusCache.Unlock()
		return status
	}
	return NetworkStatus{Interface: name, NetworkScope: "network-transition|" + name + "|" + strconv.FormatUint(NetworkGeneration(), 10), Reason: "network_changed_during_sample"}
}

func sampleNetworkStatus(name string) NetworkStatus {
	status := NetworkStatus{Interface: name, NetworkScope: dev_cache.DesktopScope(nil)}
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
		if err != nil {
			continue
		}
		prefixes = append(prefixes, prefix)
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
	status.NetworkScope = scopeForPrefixes(name, prefixes)
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
	return cachedNetworkStatus(currentInterfaceName(opt.interfaceName)).NetworkScope
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
