package dialer

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/dev_cache"
	"github.com/metacubex/mihomo/component/diagstats"
	"github.com/metacubex/mihomo/log"
)

const (
	defaultTCPConcurrentCacheSize = 4096
	defaultTCPConcurrentCacheTTL  = 30 * time.Minute
	// tcpConcurrentFastPathTimeout is the fast-path budget used when no RTT
	// sample is available yet for a destination (first hit after a cache
	// entry is created, or after NewTCPConcurrentCache/Set without a sample).
	tcpConcurrentFastPathTimeout = 100 * time.Millisecond

	// minFastPathTimeout/maxFastPathTimeout bound the RTT-derived fast-path
	// timeout so a very fast local RTT sample doesn't starve a slightly
	// slower retry, and a very slow sample doesn't stall the fallback race
	// for too long.
	minFastPathTimeout = 30 * time.Millisecond
	maxFastPathTimeout = 500 * time.Millisecond
	// fastPathRTTMultiplier turns one past sample into a budget for the next
	// connect. A single sample is a poor predictor on a jittery link -- Wi-Fi
	// routinely puts the same destination anywhere between one and three
	// times its median -- and every budget that expires early costs a whole
	// extra round of connects, so the multiplier is deliberately generous.
	fastPathRTTMultiplier = 3

	// tcpConcurrentWinnersKept is how many measured winners one destination
	// remembers. With a single winner the fast path has nothing to try when
	// that address goes dead, so the race restarts from the full candidate
	// set; a second one covers the common case (one CDN node withdrawn while
	// the rest of the answer stays good) for one extra connect.
	tcpConcurrentWinnersKept = 2
)

// tcpConcurrentWinner is one address that completed a connect, together with
// the latency measured for it. A non-positive RTT means no usable sample was
// captured, not that the connect was instant.
type tcpConcurrentWinner struct {
	IP         netip.Addr
	RTT        time.Duration
	RetryAfter time.Time
}

type tcpConcurrentCacheEntry struct {
	// winners is ordered fastest first, holds distinct addresses, and is
	// capped at tcpConcurrentWinnersKept. Addresses without a sample sort
	// last, since nothing is known about them yet.
	winners  []tcpConcurrentWinner
	expireAt time.Time
}

// insertWinner merges winner into winners under the invariants above. A
// non-positive RTT records no sample, so an address already present keeps the
// latency it had rather than losing it.
func insertWinner(winners []tcpConcurrentWinner, winner tcpConcurrentWinner) []tcpConcurrentWinner {
	winner.IP = winner.IP.Unmap()
	merged := make([]tcpConcurrentWinner, 0, len(winners)+1)
	for _, current := range winners {
		if current.IP == winner.IP {
			if winner.RTT <= 0 {
				winner.RTT = current.RTT
			}
			continue
		}
		merged = append(merged, current)
	}
	merged = append(merged, winner)
	slices.SortStableFunc(merged, func(a, b tcpConcurrentWinner) int {
		switch {
		case a.RTT <= 0 && b.RTT <= 0:
			return 0
		case a.RTT <= 0:
			return 1
		case b.RTT <= 0:
			return -1
		}
		return cmp.Compare(a.RTT, b.RTT)
	})
	if len(merged) > tcpConcurrentWinnersKept {
		merged = merged[:tcpConcurrentWinnersKept]
	}
	return merged
}

func sameWinners(a, b []tcpConcurrentWinner) bool {
	return slices.Equal(a, b)
}

// fastPathTimeoutFor derives the fast-path dial budget from the last
// measured connect RTT for a destination. Without a sample it falls back to
// the fixed default so first-hit behavior is unchanged.
func fastPathTimeoutFor(rtt time.Duration) time.Duration {
	if rtt <= 0 {
		return tcpConcurrentFastPathTimeout
	}
	timeout := min(max(rtt*fastPathRTTMultiplier, minFastPathTimeout), maxFastPathTimeout)
	return timeout
}

// TCPConcurrentCache stores the most recent successful address for a TCP
// destination. It is deliberately independent from the DNS cache: callers
// still have to validate a cached winner against the current DNS candidates.
type TCPConcurrentCache struct {
	entries *dev_cache.Cache[string, tcpConcurrentCacheEntry]
	ttl     time.Duration
	now     func() time.Time
}

type TCPWinnerSnapshot struct {
	Host         string    `json:"host"`
	Port         string    `json:"port"`
	Network      string    `json:"network"`
	NetworkScope string    `json:"networkScope,omitempty"`
	IP           string    `json:"ip"`
	RTTMillis    int64     `json:"rttMs,omitempty"`
	Rank         int       `json:"rank"`
	RTTKnown     bool      `json:"rttKnown"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Usable       bool      `json:"usable"`
	RefreshDue   bool      `json:"refreshDue"`
	RetryAfter   time.Time `json:"retryAfter,omitempty"`
}

// NewTCPConcurrentCache creates a bounded winner cache. Non-positive values
// use the production defaults.
func NewTCPConcurrentCache(maxSize int, ttl time.Duration) *TCPConcurrentCache {
	if maxSize <= 0 {
		maxSize = defaultTCPConcurrentCacheSize
	}
	if ttl <= 0 {
		ttl = defaultTCPConcurrentCacheTTL
	}
	return &TCPConcurrentCache{
		entries: dev_cache.New[string, tcpConcurrentCacheEntry](maxSize, "lru"),
		ttl:     ttl,
		now:     time.Now,
	}
}

func (c *TCPConcurrentCache) getEntry(key string) (tcpConcurrentCacheEntry, bool) {
	if c == nil || key == "" {
		return tcpConcurrentCacheEntry{}, false
	}
	entry, loaded := c.entries.Compute(key, func(entry tcpConcurrentCacheEntry, loaded bool) (tcpConcurrentCacheEntry, bool) {
		if !loaded {
			return tcpConcurrentCacheEntry{}, true
		}
		return entry, false
	})
	if !loaded {
		return tcpConcurrentCacheEntry{}, false
	}
	return entry, true
}

// Winners returns retained hints eligible for a fast-path attempt, fastest
// first. Failure backoff temporarily skips hints without erasing them.
func (c *TCPConcurrentCache) Winners(key string) ([]tcpConcurrentWinner, bool) {
	entry, loaded := c.getEntry(key)
	if !loaded || len(entry.winners) == 0 {
		return nil, false
	}
	winners := slices.DeleteFunc(slices.Clone(entry.winners), func(w tcpConcurrentWinner) bool { return c.now().Before(w.RetryAfter) })
	return winners, len(winners) > 0
}

// Backoff retains an unreachable winner but temporarily stops preferring it.
// DNS refresh failure and TCP timeout must not erase the last known address.
func (c *TCPConcurrentCache) Backoff(key string, ip netip.Addr) {
	if c == nil {
		return
	}
	c.entries.Compute(key, func(entry tcpConcurrentCacheEntry, loaded bool) (tcpConcurrentCacheEntry, bool) {
		if !loaded {
			return entry, true
		}
		entry.winners = slices.Clone(entry.winners)
		for i := range entry.winners {
			if entry.winners[i].IP == ip.Unmap() {
				entry.winners[i].RetryAfter = c.now().Add(dev_cache.RetryDelay)
			}
		}
		return entry, false
	})
	if log.Enabled(log.DEBUG) {
		log.Fields(log.DEBUG, map[string]string{"subsystem": "direct", "event": "winner_backoff", "host": tcpWinnerHost(key), "retained": "true"}, "TCP winner retained after failed attempt: %s", ip)
	}
}

// Get returns the fastest retained cached winner.
func (c *TCPConcurrentCache) Get(key string) (netip.Addr, bool) {
	entry, loaded := c.getEntry(key)
	if !loaded || len(entry.winners) == 0 {
		return netip.Addr{}, false
	}
	return entry.winners[0].IP, true
}

// RTT returns the connect latency observed for the fastest winner, if any
// sample was captured for it.
func (c *TCPConcurrentCache) RTT(key string) (time.Duration, bool) {
	entry, loaded := c.getEntry(key)
	if !loaded || len(entry.winners) == 0 || entry.winners[0].RTT <= 0 {
		return 0, false
	}
	return entry.winners[0].RTT, true
}

// Set records a successful TCP winner and refresh deadline, without a
// latency sample (the fast-path timeout for it falls back to the default
// until a sample is recorded via SetWithRTT).
func (c *TCPConcurrentCache) Set(key string, winner netip.Addr) {
	c.SetWithRTT(key, winner, 0)
}

// SetWithRTT records a successful TCP winner together with how long the
// winning connect took, so future fast-path attempts to this destination can
// size their timeout from real latency instead of the fixed default. The
// address joins any winner already held for the destination rather than
// replacing it, up to tcpConcurrentWinnersKept.
func (c *TCPConcurrentCache) SetWithRTT(key string, winner netip.Addr, rtt time.Duration) {
	if c == nil || key == "" || !winner.IsValid() {
		return
	}
	if rtt < 0 {
		rtt = 0
	}
	now := c.now()
	c.entries.ComputeWithExpire(key, func(current tcpConcurrentCacheEntry, _ time.Time, loaded bool) (tcpConcurrentCacheEntry, time.Time, bool) {
		winners := current.winners
		if !loaded {
			winners = nil
		}
		return tcpConcurrentCacheEntry{
			winners:  insertWinner(winners, tcpConcurrentWinner{IP: winner, RTT: rtt}),
			expireAt: now.Add(c.ttl),
		}, now.Add(c.ttl), false
	})
}

// SetIfFaster records winner only when it earns a place among the retained cached
// samples already stored for the scoped destination -- either a free slot or
// a latency better than one of the winners held.
func (c *TCPConcurrentCache) SetIfFaster(key string, winner netip.Addr, rtt time.Duration) bool {
	if c == nil || key == "" || !winner.IsValid() || rtt <= 0 {
		return false
	}
	now := c.now()
	updated := false
	c.entries.ComputeWithExpire(key, func(current tcpConcurrentCacheEntry, due time.Time, loaded bool) (tcpConcurrentCacheEntry, time.Time, bool) {
		winners := current.winners
		if !loaded {
			winners = nil
		}
		merged := insertWinner(winners, tcpConcurrentWinner{IP: winner, RTT: rtt})
		if loaded && sameWinners(merged, winners) {
			return current, due, false
		}
		updated = true
		return tcpConcurrentCacheEntry{winners: merged, expireAt: now.Add(c.ttl)}, now.Add(c.ttl), false
	})
	return updated
}

// Remove drops a single winner that has stopped working, keeping whatever
// other winner the destination still has. The destination is forgotten
// entirely once its last winner is removed.
func (c *TCPConcurrentCache) Remove(key string, winner netip.Addr) {
	if c == nil || key == "" || !winner.IsValid() {
		return
	}
	winner = winner.Unmap()
	removed, destinationInvalid := false, false
	c.entries.Compute(key, func(current tcpConcurrentCacheEntry, loaded bool) (tcpConcurrentCacheEntry, bool) {
		if !loaded {
			return current, true
		}
		remaining := slices.DeleteFunc(slices.Clone(current.winners), func(held tcpConcurrentWinner) bool {
			return held.IP == winner
		})
		removed = len(remaining) != len(current.winners)
		if len(remaining) == 0 {
			destinationInvalid = removed
			return tcpConcurrentCacheEntry{}, true
		}
		current.winners = remaining
		return current, false
	})
	if removed {
		diagstats.Add(diagstats.DirectWinnerEvicted)
		event := "winner_evicted"
		if destinationInvalid {
			event = "destination_invalidated"
		}
		if destinationInvalid && shouldLogTCPWinnerChange(key, event) {
			log.Fields(log.INFO, map[string]string{"subsystem": "direct", "event": event, "host": tcpWinnerHost(key), "reason": "connect_failed"}, "DIRECT TCP winner destination invalidated %s (failed=%s)", tcpWinnerHost(key), winner)
		} else if log.Enabled(log.DEBUG) {
			log.Fields(log.DEBUG, map[string]string{"subsystem": "direct", "event": event, "host": tcpWinnerHost(key), "reason": "connect_failed"}, "DIRECT TCP cached winner evicted %s --> %s (destination invalid=%t)", tcpWinnerHost(key), winner, destinationInvalid)
		}
	}
}

func shouldLogTCPWinnerChange(key, event string) bool {
	now := time.Now()
	logKey := key + "\x00" + event
	allowed := false
	tcpWinnerLogTimes.Compute(logKey, func(last time.Time, loaded bool) (time.Time, bool) {
		if loaded && now.Sub(last) < time.Minute {
			return last, false
		}
		allowed = true
		return now, false
	})
	return allowed
}

func tcpWinnerHost(key string) string {
	base, _ := splitTCPWinnerKey(key)
	address, _, _ := strings.Cut(base, "/")
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func splitTCPWinnerKey(key string) (base, scope string) {
	first, rest, ok := strings.Cut(key, "\x00")
	address, _, _ := strings.Cut(first, "/")
	if _, _, err := net.SplitHostPort(address); err == nil {
		return first, rest
	}
	if !ok {
		return first, ""
	}
	base, _, _ = strings.Cut(rest, "\x00")
	return base, first
}

// Delete removes a destination from the cache.
func (c *TCPConcurrentCache) Delete(key string) {
	if c == nil || key == "" {
		return
	}
	c.entries.Delete(key)
}

// Clear removes every cached TCP winner.
func (c *TCPConcurrentCache) Clear() {
	if c == nil {
		return
	}
	c.entries.Clear()
}

var tcpConcurrentCache = persistentTCPConcurrentCache()
var tcpWinnerLogTimes = lru.New(lru.WithSize[string, time.Time](defaultTCPConcurrentCacheSize))

func persistentTCPConcurrentCache() *TCPConcurrentCache {
	c := NewTCPConcurrentCache(0, 0)
	type stored struct {
		Winners   []tcpConcurrentWinner
		RefreshAt time.Time
	}
	c.entries = dev_cache.Attach("tcp-winner/v1", c.entries, func(v tcpConcurrentCacheEntry) ([]byte, error) { return json.Marshal(stored{v.winners, v.expireAt}) }, func(data []byte) (tcpConcurrentCacheEntry, error) {
		var v stored
		err := json.Unmarshal(data, &v)
		return tcpConcurrentCacheEntry{v.Winners, v.RefreshAt}, err
	})
	return c
}

// ClearTCPConcurrentCache clears the winner cache without changing DNS cache
// entries or DNS semantics.
func ClearTCPConcurrentCache() {
	tcpConcurrentCache.Clear()
}

func TCPWinnerSnapshots(host string) []TCPWinnerSnapshot {
	return tcpConcurrentCache.Snapshots(host)
}

func (c *TCPConcurrentCache) Snapshots(host string) []TCPWinnerSnapshot {
	if c == nil {
		return nil
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	now := c.now()
	result := make([]TCPWinnerSnapshot, 0)
	for _, item := range c.entries.Snapshot() {
		base, scope := splitTCPWinnerKey(item.Key)
		address, network, ok := strings.Cut(base, "/")
		cachedHost, port, err := net.SplitHostPort(address)
		if !ok || err != nil || (host != "" && cachedHost != host) {
			continue
		}
		for rank, winner := range item.Value.winners {
			result = append(result, TCPWinnerSnapshot{Host: cachedHost, Port: port, Network: network, NetworkScope: scope, IP: winner.IP.String(), RTTMillis: winner.RTT.Milliseconds(), RTTKnown: winner.RTT > 0, Rank: rank + 1, ExpiresAt: item.Value.expireAt, Usable: true, RefreshDue: !now.Before(item.Value.expireAt), RetryAfter: winner.RetryAfter})
		}
	}
	slices.SortFunc(result, func(a, b TCPWinnerSnapshot) int {
		if n := cmp.Compare(a.Host, b.Host); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Port, b.Port); n != 0 {
			return n
		}
		if n := cmp.Compare(a.NetworkScope, b.NetworkScope); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Network, b.Network); n != 0 {
			return n
		}
		return cmp.Compare(a.Rank, b.Rank)
	})
	return result
}

func tcpConcurrentCacheKey(host, port, network string) (string, bool) {
	return tcpConcurrentCacheScopedKey(host, port, network, "")
}

func tcpConcurrentCacheScopedKey(host, port, network, scope string) (string, bool) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return "", false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	key := net.JoinHostPort(host, port) + "/" + network
	if scope != "" {
		key = dev_cache.ScopedKey(scope, key)
	}
	return key, true
}

func tcpConcurrentPathKey(host, port, network, scope string, opt option) (string, bool) {
	key, ok := tcpConcurrentCacheScopedKey(host, port, network, scope)
	mark := opt.routingMark
	if mark == 0 {
		mark = int(DefaultRoutingMark.Load())
	}
	if opt.directAdapter != "" || mark != 0 {
		key += fmt.Sprintf("\x00path=%s/mark=%d", opt.directAdapter, mark)
	}
	return key, ok
}

func containsTCPConcurrentCandidate(candidates []netip.Addr, winner netip.Addr) bool {
	winner = winner.Unmap()
	for _, candidate := range candidates {
		if candidate.Unmap() == winner {
			return true
		}
	}
	return false
}

func tcpConcurrentDialContext(ctx context.Context, network, host string, ips []netip.Addr, port string, opt option, fallback dialFunc) dialResult {
	// Cached and single-candidate paths still require a real TCP handshake.
	opt.tfo = false
	key, cacheable := tcpConcurrentPathKey(host, port, network, directNetworkScope(opt), opt)
	if !cacheable {
		return fallback(ctx, network, ips, port, opt)
	}

	// Each cached winner still named by the current answer gets its own
	// budget, in order, before the full race starts. One withdrawn CDN node
	// then costs a single extra connect instead of a restart from scratch.
	winners, loaded := tcpConcurrentCache.Winners(key)
	if loaded {
		diagstats.Add(diagstats.DirectWinnerHit)
	} else {
		diagstats.Add(diagstats.DirectWinnerMiss)
	}
	if loaded {
		winners = slices.DeleteFunc(winners, func(winner tcpConcurrentWinner) bool {
			return !containsTCPConcurrentCandidate(ips, winner.IP)
		})
		if len(winners) == 0 {
			// Keep retained hints for other families and pending DNS sources.
		}
	}
	if len(winners) > 0 {
		fastCtx, cancelFast := context.WithCancel(ctx)
		fastResult := make(chan dialResult, len(winners))
		fastStart := time.Now()
		budget := time.Duration(0)
		for _, winner := range winners {
			// One shared budget covering the group follows its slowest
			// member: a faster winner's sample says nothing about when the
			// others should be given up on.
			budget = max(budget, fastPathTimeoutFor(winner.RTT))
			cachedIP := winner.IP
			go func() {
				result := dialResult{ip: cachedIP}
				result.Conn, result.error = dialContext(fastCtx, network, cachedIP, port, opt)
				select {
				case fastResult <- result:
				case <-fastCtx.Done():
					if result.Conn != nil {
						_ = result.Conn.Close()
					}
				}
			}()
		}

		fastTimer := time.NewTimer(budget)
		stopFastTimer := func() {
			if !fastTimer.Stop() {
				select {
				case <-fastTimer.C:
				default:
				}
			}
		}
		outstanding := len(winners)
	fastRace:
		for outstanding > 0 {
			select {
			case result := <-fastResult:
				outstanding--
				if result.error == nil {
					stopFastTimer()
					cancelFast()
					tcpConcurrentCache.SetWithRTT(key, result.ip, measuredDialDuration(fastStart))
					return result
				}
				if ctx.Err() != nil {
					stopFastTimer()
					cancelFast()
					return dialResult{error: ctx.Err()}
				}
				tcpConcurrentCache.Backoff(key, result.ip)
			case <-fastTimer.C:
				// Nothing the cache offered answered in time, so none of them
				// deserves to be tried first again.
				for _, winner := range winners {
					tcpConcurrentCache.Backoff(key, winner.IP)
				}
				break fastRace
			case <-ctx.Done():
				stopFastTimer()
				cancelFast()
				return dialResult{error: ctx.Err()}
			}
		}
		// Whatever is still running when the budget expires is abandoned
		// rather than joined to the race below, which redials every candidate
		// anyway.
		stopFastTimer()
		cancelFast()
	}

	result := fallback(ctx, network, ips, port, opt)
	if result.error == nil && result.ip.IsValid() {
		// Use the winning candidate's own measured connect time, never the
		// wall-clock span of the whole fallback call: when fallback is a
		// dual-stack race, a non-preferred winner can sit ready for up to
		// dualStackFallbackTimeout before being returned, and timing the call
		// would fold that unrelated waiting into the sample. dialDuration is
		// zero only when the dial was never really timed -- the lazy TFO
		// dialer returns a stub before any network I/O -- and SetWithRTT then
		// keeps the winner without recording a sample for it.
		tcpConcurrentCache.SetWithRTT(key, result.ip, result.dialDuration)
	}
	return result
}
