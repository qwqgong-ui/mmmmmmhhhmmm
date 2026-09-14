package directrace

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const winnerTTL = 30 * time.Second

type winnerKey struct {
	host    string
	adapter string
	ipv6    bool
}

type winnerEntry struct {
	ip      netip.Addr
	expires time.Time
}

type WinnerSnapshot struct {
	Host        string    `json:"host"`
	Adapter     string    `json:"proxy"`
	Family      string    `json:"family"`
	IP          string    `json:"ip"`
	ExpiresAt   time.Time `json:"expiresAt"`
	LastSuccess time.Time `json:"lastSuccess"`
	ScopeKnown  bool      `json:"scopeKnown"`
	RTTKnown    bool      `json:"rttKnown"`
}

var winners = struct {
	sync.Mutex
	entries map[winnerKey]winnerEntry
}{entries: make(map[winnerKey]winnerEntry)}

// maxWinners bounds the table. An entry is only dropped when a later lookup of
// that exact key finds it expired, so a destination visited once and never
// again would otherwise sit here for the life of the process. Winners are a
// warm preference with a 30s life; losing some of them costs a race, not
// correctness.
const maxWinners = 2048

func Store(host, adapter string, ip netip.Addr) {
	ip = ip.Unmap()
	if host == "" || adapter == "" || !ip.IsValid() {
		return
	}
	now := time.Now()
	key := winnerKey{host: canonicalHost(host), adapter: adapter, ipv6: ip.Is6()}
	winners.Lock()
	if _, replacing := winners.entries[key]; !replacing && len(winners.entries) >= maxWinners {
		sweepExpiredLocked(now)
		if len(winners.entries) >= maxWinners {
			// Everything still live: drop one arbitrary entry rather than let
			// destination names grow the table without bound.
			for existing := range winners.entries {
				delete(winners.entries, existing)
				break
			}
		}
	}
	winners.entries[key] = winnerEntry{
		ip:      ip,
		expires: now.Add(winnerTTL),
	}
	winners.Unlock()
}

// sweepExpiredLocked must be called with winners held.
func sweepExpiredLocked(now time.Time) {
	for key, entry := range winners.entries {
		if now.After(entry.expires) {
			delete(winners.entries, key)
		}
	}
}

// Prefer returns a recent path winner only while it remains in the current DNS
// RRset. Callers use it as a warm preference, never as proof that an application
// protocol is still reachable.
func Prefer(host, adapter string, candidates []netip.Addr) (netip.Addr, bool) {
	if host == "" || adapter == "" || len(candidates) == 0 {
		return netip.Addr{}, false
	}
	key := winnerKey{host: canonicalHost(host), adapter: adapter, ipv6: candidates[0].Unmap().Is6()}
	winners.Lock()
	entry, loaded := winners.entries[key]
	if loaded && time.Now().After(entry.expires) {
		delete(winners.entries, key)
		loaded = false
	}
	winners.Unlock()
	if !loaded {
		return netip.Addr{}, false
	}
	for _, candidate := range candidates {
		if candidate.Unmap() == entry.ip {
			return entry.ip, true
		}
	}
	return netip.Addr{}, false
}

// Snapshot returns a copy of every live, application-confirmed UDP/QUIC warm
// winner. Reading diagnostics does not evict entries or refresh their TTL.
func Snapshot(host string) []WinnerSnapshot {
	now := time.Now()
	host = canonicalHost(host)
	winners.Lock()
	defer winners.Unlock()
	result := make([]WinnerSnapshot, 0, len(winners.entries))
	for key, entry := range winners.entries {
		if !now.Before(entry.expires) {
			continue
		}
		if host != "" && key.host != host {
			continue
		}
		family := "ipv4"
		if key.ipv6 {
			family = "ipv6"
		}
		result = append(result, WinnerSnapshot{Host: key.host, Adapter: key.adapter, Family: family, IP: entry.ip.String(), ExpiresAt: entry.expires, LastSuccess: entry.expires.Add(-winnerTTL)})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Host != result[j].Host {
			return result[i].Host < result[j].Host
		}
		if result[i].Adapter != result[j].Adapter {
			return result[i].Adapter < result[j].Adapter
		}
		return result[i].Family < result[j].Family
	})
	return result
}

func canonicalHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}
