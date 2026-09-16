package executor

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/listener"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

// ipv6AvailabilityDebounce coalesces bursts of interface/route-change events
// (a single Wi-Fi/mobile-network switch commonly fires several) into one
// re-detection so we don't thrash the resolver/DNS/TUN state.
const ipv6AvailabilityDebounce = 500 * time.Millisecond

var (
	// configuredIPv6 mirrors the user's configured `ipv6:` intent, independent
	// of whether it is currently active on the system.
	configuredIPv6 = atomic.NewBool(true)

	// checkSystemIPv6 is a var (rather than a direct call) so tests can stub
	// it out. It intentionally reuses config.SystemIPv6Available instead of
	// re-implementing interface/address filtering here, so the config-parse
	// and runtime re-detection paths can never drift apart.
	checkSystemIPv6 = config.SystemIPv6Available

	// runtimeIPv6Controller is guarded by the package-level executor mux; it
	// must only be read or written while that mutex is held (see the
	// "Locked" suffix convention on the functions below).
	runtimeIPv6Controller runtimeIPv6State
)

// runtimeIPv6NetworkMonitor abstracts the desktop network-change monitor
// (backed by sing-tun's tun.NetworkUpdateMonitor on Linux/Windows/macOS) so
// this file has no direct sing-tun/OS dependency; see
// ipv6_monitor_desktop.go and ipv6_monitor_other.go for the two
// implementations selected by build tag.
type runtimeIPv6NetworkMonitor interface {
	Start() error
	Close() error
}

// runtimeIPv6State tracks the runtime IPv6 availability controller across
// config reloads. general/dns/tun hold the *configured* (not availability
// masked) values so a later availability flip can restore them without a
// full config reload.
type runtimeIPv6State struct {
	generation           uint64
	cancel               context.CancelFunc
	monitor              runtimeIPv6NetworkMonitor
	configured           bool
	active               bool
	initialized          bool
	systemAvailable      bool
	systemAvailableKnown bool
	general              *config.General
	dns                  *config.DNS
	tun                  LC.Tun
}

type RuntimeIPv6Status struct {
	Configured      bool   `json:"configured"`
	SystemAvailable bool   `json:"systemAvailable"`
	AvailableKnown  bool   `json:"availableKnown"`
	Active          bool   `json:"active"`
	Initialized     bool   `json:"initialized"`
	Source          string `json:"source"`
}

func IPv6Status() RuntimeIPv6Status {
	mux.Lock()
	defer mux.Unlock()
	source := "native_detection"
	if runtimeIPv6Controller.systemAvailableKnown {
		source = "platform"
	}
	return RuntimeIPv6Status{Configured: runtimeIPv6Controller.configured, SystemAvailable: runtimeIPv6Controller.currentSystemAvailable(checkSystemIPv6), AvailableKnown: true, Active: runtimeIPv6Controller.active, Initialized: runtimeIPv6Controller.initialized, Source: source}
}

// currentSystemAvailable returns the embedding platform's last authoritative
// sample when one has been supplied. Standalone hosts keep using native
// detection, so Android integration does not change their behaviour.
func (s *runtimeIPv6State) currentSystemAvailable(detect func() bool) bool {
	if s.systemAvailableKnown {
		return s.systemAvailable
	}
	return detect()
}

// setSystemAvailable recomputes active from the configured intent and the
// latest system-availability sample, reporting whether it changed. It is a
// method on a value receiver's pointer purely to keep the transition logic
// unit-testable without touching the package-level controller or mux.
func (s *runtimeIPv6State) setSystemAvailable(available bool) (changed bool, active bool) {
	active = s.configured && available
	if active == s.active {
		return false, active
	}
	s.active = active
	if s.general != nil {
		s.general.IPv6Active = active
	}
	return true, active
}

// prepareRuntimeIPv6 must be called with mux held, at the very top of
// ApplyConfig, before any other config is applied. It stops any monitor left
// over from a previous config, snapshots the newly parsed config's
// IPv6-related state, and does one fresh availability check so the config
// currently being applied starts from up-to-date state. The monitor itself
// is (re)started later, once the rest of ApplyConfig has finished wiring up
// DNS/TUN, by startRuntimeIPv6MonitorLocked.
func prepareRuntimeIPv6(cfg *config.Config) {
	stopRuntimeIPv6MonitorLocked()
	runtimeIPv6Controller.generation++
	runtimeIPv6Controller.configured = cfg.General.IPv6
	runtimeIPv6Controller.initialized = true
	runtimeIPv6Controller.general = cfg.General
	runtimeIPv6Controller.dns = cfg.DNS
	runtimeIPv6Controller.tun = cfg.General.Tun
	runtimeIPv6Controller.active = cfg.General.IPv6 && runtimeIPv6Controller.currentSystemAvailable(checkSystemIPv6)
	cfg.General.IPv6Active = runtimeIPv6Controller.active
	configuredIPv6.Store(cfg.General.IPv6)

	// temporaryUpdateGeneral's write to resolver.DisableIPv6 during
	// ParseRawConfig is rolled back before ApplyConfig ever runs, and
	// applyRuntimeIPv6AvailabilityLocked only fires on a later availability
	// *change*. Without this store, resolver.DisableIPv6 stays at its
	// zero-value true (disabled) on every fresh start/reload until some
	// network-change event happens to fire, even though DNS/TUN below are
	// already being wired up for the correct active state.
	resolver.DisableIPv6.Store(!runtimeIPv6Controller.active)
}

// startRuntimeIPv6MonitorLocked starts the OS network-change monitor when
// no monitor is already running. It also invalidates leaf QUIC path hints,
// including on IPv4-only networks. It is a no-op
// (monitor stays nil) on Android and any other platform without an
// implementation - see ipv6_monitor_other.go - since re-detection there is
// left to the host application's own network-switch handling.
func startRuntimeIPv6MonitorLocked() {
	if !runtimeIPv6Controller.initialized || runtimeIPv6Controller.monitor != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	updates := make(chan struct{}, 1)
	monitor, err := newRuntimeIPv6NetworkUpdateMonitor(func() {
		dialer.NotifyNetworkChange()
		select {
		case updates <- struct{}{}:
		default:
		}
	})
	if err != nil {
		log.Warnln("Create runtime IPv6 network monitor failed: %s", err)
		cancel()
		return
	}
	if monitor == nil {
		cancel()
		return
	}

	runtimeIPv6Controller.cancel = cancel
	runtimeIPv6Controller.monitor = monitor
	generation := runtimeIPv6Controller.generation
	go monitorRuntimeIPv6(ctx, generation, updates)
	if err = monitor.Start(); err != nil {
		stopRuntimeIPv6MonitorLocked()
		log.Warnln("Start runtime IPv6 network monitor failed: %s", err)
	}
}

// stopRuntimeIPv6MonitorLocked must be called with mux held. It is safe to
// call repeatedly / on an already-stopped controller.
func stopRuntimeIPv6MonitorLocked() {
	if runtimeIPv6Controller.cancel != nil {
		runtimeIPv6Controller.cancel()
		runtimeIPv6Controller.cancel = nil
	}
	if runtimeIPv6Controller.monitor != nil {
		_ = runtimeIPv6Controller.monitor.Close()
		runtimeIPv6Controller.monitor = nil
	}
}

// resetRuntimeIPv6Locked releases references owned by the stopped config while
// retaining the platform sample. An in-process embedding may prime the next
// ApplyConfig before it starts, and that update must not touch a stale DNS/TUN
// instance from the previous generation.
func resetRuntimeIPv6Locked() {
	stopRuntimeIPv6MonitorLocked()
	runtimeIPv6Controller.generation++
	runtimeIPv6Controller.configured = false
	runtimeIPv6Controller.active = false
	runtimeIPv6Controller.initialized = false
	runtimeIPv6Controller.general = nil
	runtimeIPv6Controller.dns = nil
	runtimeIPv6Controller.tun = LC.Tun{}
}

// monitorRuntimeIPv6 runs for the lifetime of one config generation's
// monitor. It debounces bursts of network-change callbacks and, after each
// quiet period, re-checks system IPv6 availability and applies any change
// under mux. The generation check inside the callback guards against a
// stale goroutine (from a config that has since been replaced/torn down by
// prepareRuntimeIPv6) racing a fresh one.
func monitorRuntimeIPv6(ctx context.Context, generation uint64, updates <-chan struct{}) {
	debounceNetworkUpdates(ctx, updates, ipv6AvailabilityDebounce, func() {
		available := checkSystemIPv6()
		mux.Lock()
		defer mux.Unlock()
		if generation != runtimeIPv6Controller.generation || !runtimeIPv6Controller.configured {
			return
		}
		applyRuntimeIPv6AvailabilityLocked(available)
	})
}

// debounceNetworkUpdates reads from updates until ctx is done, invoking
// callback once delay has elapsed with no further update. A burst of N
// updates therefore yields exactly one callback, roughly `delay` after the
// last one in the burst.
func debounceNetworkUpdates(ctx context.Context, updates <-chan struct{}, delay time.Duration, callback func()) {
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-updates:
			if timer == nil {
				timer = time.NewTimer(delay)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)
			}
			timerC = timer.C
		case <-timerC:
			timerC = nil
			callback()
		}
	}
}

// applyRuntimeIPv6AvailabilityLocked must be called with mux held. It brings
// the TUN/DNS IPv6 paths up before allowing new resolver lookups to use
// them when availability returns, and tears new lookups down before
// removing the TUN/DNS paths when availability is lost, so there is never a
// window where the resolver believes IPv6 works but TUN/DNS have not caught
// up (or vice versa).
func applyRuntimeIPv6AvailabilityLocked(systemAvailable bool) {
	changed, active := runtimeIPv6Controller.setSystemAvailable(systemAvailable)
	if !changed {
		return
	}

	if active {
		applyTunIPv6Availability(runtimeIPv6Controller.tun, true)
		if runtimeIPv6Controller.dns != nil {
			updateDNS(runtimeIPv6Controller.dns, true)
		}
		resolver.DisableIPv6.Store(false)
	} else {
		resolver.DisableIPv6.Store(true)
		if runtimeIPv6Controller.dns != nil {
			updateDNS(runtimeIPv6Controller.dns, false)
		}
		applyTunIPv6Availability(runtimeIPv6Controller.tun, false)
	}
	resolver.ResetConnection()

	reason := "system_unavailable"
	if active {
		reason = "system_available"
	} else if !runtimeIPv6Controller.configured {
		reason = "configuration_disabled"
	}
	log.Fields(log.INFO, map[string]string{"subsystem": "network", "event": "ipv6_state_changed", "reason": reason, "configured": fmt.Sprint(runtimeIPv6Controller.configured), "system_available": fmt.Sprint(systemAvailable), "active": fmt.Sprint(active)}, "Runtime IPv6 state changed: active=%t (%s)", active, reason)
}

// SetSystemIPv6Available lets an embedding platform provide its authoritative
// physical-network IPv6 state without reloading the configuration or rebuilding
// the platform VPN. Hosts without a native monitor, such as Android VPN apps,
// call this from their network callback. Calls made before the first ApplyConfig
// are retained and become the initial runtime state.
func SetSystemIPv6Available(available bool) {
	mux.Lock()
	defer mux.Unlock()
	runtimeIPv6Controller.systemAvailable = available
	runtimeIPv6Controller.systemAvailableKnown = true
	if !runtimeIPv6Controller.initialized {
		return
	}
	applyRuntimeIPv6AvailabilityLocked(available)
}

// SetIPv6Enabled changes the configured IPv6 intent (e.g. from the REST API)
// without losing the DNS/TUN IPv6 settings needed for a later availability
// transition, and starts/stops the network-change monitor to match.
func SetIPv6Enabled(enabled bool) {
	mux.Lock()
	defer mux.Unlock()

	configuredIPv6.Store(enabled)
	if !runtimeIPv6Controller.initialized {
		resolver.DisableIPv6.Store(!enabled)
		return
	}

	stopRuntimeIPv6MonitorLocked()
	runtimeIPv6Controller.generation++
	runtimeIPv6Controller.configured = enabled
	runtimeIPv6Controller.general.IPv6 = enabled
	available := false
	if enabled {
		available = runtimeIPv6Controller.currentSystemAvailable(checkSystemIPv6)
	}
	applyRuntimeIPv6AvailabilityLocked(available)
	startRuntimeIPv6MonitorLocked()
}

// ConfiguredTun returns the unmasked TUN configuration, i.e. what the user
// configured, not what is currently active. The active listener may
// temporarily omit IPv6 fields while the physical network has no usable
// IPv6; callers that need to show or round-trip the user's configuration
// (GetGeneral, the REST API) should use this instead of listener.GetTunConf.
func ConfiguredTun() LC.Tun {
	mux.Lock()
	defer mux.Unlock()
	if runtimeIPv6Controller.initialized {
		return runtimeIPv6Controller.tun
	}
	return listener.GetTunConf()
}

// UpdateTun replaces the configured TUN state and applies the current
// runtime IPv6 mask. Passing nil only re-applies the existing configuration
// (useful to re-run the mask after some other state changed).
func UpdateTun(tunConfig *LC.Tun) {
	mux.Lock()
	defer mux.Unlock()

	if tunConfig != nil {
		runtimeIPv6Controller.tun = *tunConfig
		if runtimeIPv6Controller.general != nil {
			runtimeIPv6Controller.general.Tun = *tunConfig
		}
	}
	if runtimeIPv6Controller.initialized {
		applyTunIPv6Availability(runtimeIPv6Controller.tun, runtimeIPv6Controller.active)
		return
	}
	if tunConfig != nil {
		listener.ReCreateTun(*tunConfig, tunnel.Tunnel)
	} else {
		listener.ReCreateTun(listener.GetTunConf(), tunnel.Tunnel)
	}
}

func applyTunIPv6Availability(tunConfig LC.Tun, active bool) {
	listener.ReCreateTun(tunConfigForIPv6Availability(tunConfig, active), tunnel.Tunnel)
}

// tunConfigForIPv6Availability returns the effective TUN config for the
// current availability state, without mutating tunConfig. When IPv6 is
// inactive it strips IPv6-only routes/addresses so the TUN device stops
// advertising IPv6 connectivity it cannot provide.
func tunConfigForIPv6Availability(tunConfig LC.Tun, active bool) LC.Tun {
	// Android and other embedded clients own the passed TUN file descriptor
	// (FileDescriptor > 0 means mihomo did not create this TUN itself).
	// Closing and recreating it here can invalidate the host's VPN session,
	// so leave that TUN dual-stack and gate IPv6 purely at the
	// resolver/DNS runtime layer instead.
	if active || tunConfig.FileDescriptor > 0 {
		return tunConfig
	}

	tunConfig.Inet6Address = nil
	tunConfig.Inet6RouteAddress = nil
	tunConfig.Inet6RouteExcludeAddress = nil
	tunConfig.RouteAddress = ipv4Prefixes(tunConfig.RouteAddress)
	tunConfig.RouteExcludeAddress = ipv4Prefixes(tunConfig.RouteExcludeAddress)
	tunConfig.LoopbackAddress = ipv4Addresses(tunConfig.LoopbackAddress)
	return tunConfig
}

func ipv4Prefixes(prefixes []netip.Prefix) []netip.Prefix {
	filtered := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() {
			filtered = append(filtered, prefix)
		}
	}
	return filtered
}

func ipv4Addresses(addresses []netip.Addr) []netip.Addr {
	filtered := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Is4() {
			filtered = append(filtered, address)
		}
	}
	return filtered
}
