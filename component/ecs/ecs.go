// Package ecs discovers the public IP address of the direct (non-proxied)
// egress — with STUN and with DNS whoami queries, whichever answers first —
// and exposes it as an EDNS Client Subnet prefix, so DNS upstreams that are
// queried directly can return geographically correct answers even when
// mihomo itself is not on the client's network path.
//
// It is on by default for `direct-nameserver` and needs no configuration; a
// nameserver carrying an explicit `ecs=` parameter keeps using that value.
//
// Discovery is event driven rather than periodic: it runs at startup / config
// reload and again whenever the default interface changes (TUN's network
// monitor), because those are the only moments the direct egress address can
// change. A round that comes up empty — at startup the network and the
// upstream DNS are usually not ready yet — is retried with a growing delay.
package ecs

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

const (
	// prefixV4 and prefixV6 keep the announced subnet coarse enough to stay
	// privacy-neutral while remaining useful to a CDN, which matches the
	// source netmask most public resolvers apply themselves.
	prefixV4 = 24
	prefixV6 = 56

	// discoverTimeout bounds one whole discovery round (resolve + STUN
	// retransmissions), which realm.Discover backs off internally.
	discoverTimeout = 15 * time.Second

	// minInterval coalesces the burst of default-interface events a single
	// network switch produces into one discovery round. Updates inside the
	// interval remain queued, with old prefixes invalidated immediately.
	minInterval = 5 * time.Second
)

// retryDelays paces the rounds that follow a completely failed one, then
// gives up until the next network event.
var retryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, 60 * time.Second}

var (
	mu          sync.Mutex
	enabled     bool
	lastRun     time.Time
	generation  uint64
	cancelRound context.CancelFunc

	running atomic.Bool
	// wake carries a trigger that arrived while a round was in flight or
	// while the retry timer was waiting, so a network change is never
	// swallowed by the round it raced with.
	wake = make(chan struct{}, 1)

	// the two families are discovered and stored independently so an A query
	// gets an IPv4 subnet and an AAAA query an IPv6 one
	prefix4 atomic.TypedValue[netip.Prefix]
	prefix6 atomic.TypedValue[netip.Prefix]
	source4 atomic.TypedValue[string]
	source6 atomic.TypedValue[string]
)

type Status struct {
	Enabled    bool   `json:"enabled"`
	Generation uint64 `json:"generation"`
	IPv4Prefix string `json:"ipv4Prefix,omitempty"`
	IPv4Source string `json:"ipv4Source,omitempty"`
	IPv6Prefix string `json:"ipv6Prefix,omitempty"`
	IPv6Source string `json:"ipv6Source,omitempty"`
}

func Snapshot() Status {
	mu.Lock()
	defer mu.Unlock()
	status := Status{Enabled: enabled, Generation: generation}
	if prefix := prefix4.Load(); prefix.IsValid() {
		status.IPv4Prefix = prefix.String()
	}
	if prefix := prefix6.Load(); prefix.IsValid() {
		status.IPv6Prefix = prefix.String()
	}
	status.IPv4Source, status.IPv6Source = source4.Load(), source6.Load()
	return status
}

// Prefix returns the most recently discovered client subnet for the requested
// family, falling back to the other family when only that one is known (a
// mismatched family still carries the right location). It returns an invalid
// prefix when discovery is disabled or has not succeeded yet, which callers
// must treat as "do not attach ECS".
func Prefix(ipv4 bool) netip.Prefix {
	primary, secondary := &prefix4, &prefix6
	if !ipv4 {
		primary, secondary = &prefix6, &prefix4
	}
	if found := primary.Load(); found.IsValid() {
		return found
	}
	return secondary.Load()
}

// Setup enables or disables discovery and, when enabled, kicks off an initial
// round. It is safe to call on every config reload.
func Setup(enable bool) {
	mu.Lock()
	enabled = enable
	lastRun = time.Time{}
	if !enable {
		generation++
		prefix4.Store(netip.Prefix{})
		prefix6.Store(netip.Prefix{})
		source4.Store("")
		source6.Store("")
		if cancelRound != nil {
			cancelRound()
		}
		signal()
	}
	mu.Unlock()
	if enable {
		trigger("startup")
	}
}

// Refresh invalidates the previous network's prefixes immediately. The worker
// coalesces rapid changes without discarding the last notification.
func Refresh() {
	trigger("network changed")
}

func signal() {
	select {
	case wake <- struct{}{}:
	default:
	}
}

func trigger(reason string) {
	mu.Lock()
	defer mu.Unlock()
	if !enabled {
		return
	}
	generation++
	prefix4.Store(netip.Prefix{})
	prefix6.Store(netip.Prefix{})
	source4.Store("")
	source6.Store("")
	if cancelRound != nil {
		cancelRound()
	}
	if running.Load() {
		signal()
		return
	}
	running.Store(true)
	go discoverLoop(reason)
}

func discoverLoop(reason string) {
	var currentGeneration uint64
	attempt := 0
	for {
		mu.Lock()
		if !enabled {
			running.Store(false)
			mu.Unlock()
			return
		}
		if currentGeneration != generation {
			currentGeneration = generation
			attempt = 0
		}
		delay := time.Duration(0)
		if attempt == 0 && !lastRun.IsZero() {
			delay = time.Until(lastRun.Add(minInterval))
		}
		select {
		case <-wake:
		default:
		}
		mu.Unlock()
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-wake:
				timer.Stop()
				reason = "network changed"
				continue
			case <-timer.C:
			}
		}

		mu.Lock()
		if !enabled || currentGeneration != generation {
			mu.Unlock()
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), discoverTimeout)
		cancelRound = cancel
		mu.Unlock()
		discover(ctx, reason, currentGeneration)
		cancel()

		mu.Lock()
		cancelRound = nil
		if currentGeneration != generation {
			mu.Unlock()
			reason = "network changed"
			continue
		}
		lastRun = time.Now()
		if !enabled || discovered() || attempt >= len(retryDelays) {
			// Serialize stopping with trigger so a final network event cannot
			// land between checking the queue and releasing worker ownership.
			running.Store(false)
			mu.Unlock()
			return
		}
		delay = retryDelays[attempt]
		attempt++
		mu.Unlock()
		log.Fields(log.INFO, map[string]string{"subsystem": "dns", "event": "ecs_retry_scheduled", "reason": reason, "ecs_generation": fmt.Sprint(currentGeneration), "retry_delay_ms": fmt.Sprint(delay.Milliseconds()), "attempt": fmt.Sprint(attempt)}, "[ECS] discovery retry %d scheduled in %s (%s)", attempt, delay, reason)
		timer := time.NewTimer(delay)
		select {
		case <-wake:
			timer.Stop()
			reason = "network changed"
		case <-timer.C:
			reason = "retry"
		}
	}
}

func discovered() bool {
	return prefix4.Load().IsValid() || prefix6.Load().IsValid()
}

// discover probes both families in parallel: an A query wants an IPv4 subnet
// and an AAAA query an IPv6 one, and a failure of one family must not hold up
// or hide the other.
func discover(ctx context.Context, reason string, generation uint64) {
	var wg sync.WaitGroup
	families := []bool{true}
	if !resolver.DisableIPv6.Load() {
		families = append(families, false)
	}
	for _, ipv4 := range families {
		wg.Go(func() {
			store(ctx, ipv4, reason, generation)
		})
	}
	wg.Wait()
}

func store(ctx context.Context, ipv4 bool, reason string, roundGeneration uint64) {
	name, target := "IPv4", &prefix4
	if !ipv4 {
		name, target = "IPv6", &prefix6
	}
	found, source, err := discoverPrefix(ctx, ipv4)
	mu.Lock()
	defer mu.Unlock()
	if !enabled || generation != roundGeneration || errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	if err != nil {
		// The worker retries an empty round; never restore a previous network's prefix.
		log.Fields(log.WARNING, map[string]string{"subsystem": "dns", "event": "ecs_discovery_failed", "reason": reason, "family": name, "ecs_generation": fmt.Sprint(roundGeneration)}, "[ECS] discover %s client subnet failed (%s): %s", name, reason, err.Error())
		return
	}
	if ctx.Err() != nil {
		return
	}
	if ipv4 {
		source4.Store(source)
	} else {
		source6.Store(source)
	}
	if old := target.Swap(found); old == found {
		log.Debugln("[ECS] %s client subnet unchanged (%s): %s", name, reason, found)
		return
	}
	log.Fields(log.INFO, map[string]string{"subsystem": "dns", "event": "ecs_updated", "reason": reason, "family": name, "source": source, "ecs_generation": fmt.Sprint(roundGeneration)}, "[ECS] %s client subnet updated (%s, %s): %s", name, reason, source, found)
}

// discoverPrefix races the two probe kinds and takes the first address that
// checks out. Both report the same thing — the public address this egress
// presents — but they fail in different places: STUN is purpose-built yet
// speaks ports (3478 and friends) that networks like to filter, while the DNS
// whoami probes need nothing but UDP/53.
func discoverPrefix(ctx context.Context, ipv4 bool) (netip.Prefix, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stop the slower probe as soon as one has answered

	type result struct {
		addr   netip.Addr
		err    error
		source string
	}
	// snapshot the probe configuration here, so the goroutines never read
	// package state concurrently
	servers, whoami := stunServers, whoamiProbes
	probes := []struct {
		name string
		run  func() (netip.Addr, error)
	}{
		{"stun", func() (netip.Addr, error) { return discoverSTUN(ctx, ipv4, servers) }},
		{"whoami", func() (netip.Addr, error) { return discoverWhoami(ctx, ipv4, whoami) }},
	}
	results := make(chan result, len(probes))
	for _, probe := range probes {
		go func() {
			addr, err := probe.run()
			results <- result{addr: addr, err: err, source: probe.name}
		}()
	}

	var errs []error
	for range probes {
		got := <-results
		if got.err == nil {
			return maskPrefix(got.addr), got.source, nil
		}
		errs = append(errs, got.err)
	}
	return netip.Prefix{}, "", errors.Join(errs...)
}

func maskPrefix(addr netip.Addr) netip.Prefix {
	bits := prefixV4
	if !addr.Is4() {
		bits = prefixV6
	}
	return netip.PrefixFrom(addr, bits).Masked()
}

// acceptAddr keeps only what a probe may report: the family must match the one
// probed with — otherwise an IPv6 address would be filed as the IPv4 client
// subnet — and the address must carry routing information a CDN can use.
func acceptAddr(addr netip.Addr, ipv4 bool) bool {
	addr = addr.Unmap()
	return addr.IsValid() && addr.Is4() == ipv4 && isPublic(addr)
}

// isPublic rejects addresses that carry no routing information for a CDN:
// anything private, loopback, link-local, CGNAT (RFC 6598) or IPv6 ULA.
func isPublic(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() ||
		addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return false
	}
	if addr.Is4() && cgnat.Contains(addr) {
		return false
	}
	return true
}

var (
	cgnat              = netip.MustParsePrefix("100.64.0.0/10")
	errNoPublicAddress = errors.New("no usable address reported")
)

// SetPrefixForTest overrides the discovered prefixes. It exists for tests in
// packages that consume [Prefix] without running STUN discovery.
func SetPrefixForTest(v4, v6 netip.Prefix) {
	mu.Lock()
	defer mu.Unlock()
	prefix4.Store(v4)
	prefix6.Store(v6)
}
