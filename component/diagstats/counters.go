// Package diagstats contains bounded, allocation-free downstream counters.
// No label maps, histories, background goroutines or timers run on hot paths.
package diagstats

import "sync/atomic"

type Counter uint8

const (
	DNSFresh Counter = iota
	DNSStale
	DNSMiss
	DNSUpstreamError
	DNSTCPRetry
	DirectWinnerHit
	DirectWinnerMiss
	DirectWinnerEvicted
	ICMPReported
	ICMPWriteError
	ProcessFound
	ProcessFallback
	CacheRefreshStarted
	CacheRefreshShared
	CacheRefreshSucceeded
	CacheRefreshFailed
	CacheRefreshInvalidated
	count
)

var values [count]atomic.Uint64
var names = [...]string{"dns.cache.fresh", "dns.cache.stale", "dns.cache.miss", "dns.upstream.error", "dns.udp_tcp_retry", "direct.tcp.winner_hit", "direct.tcp.winner_miss", "direct.tcp.winner_evicted", "tun.icmp.reported", "tun.icmp.write_error", "process.found", "process.fallback", "dev_cache.refresh.started", "dev_cache.refresh.shared", "dev_cache.refresh.succeeded", "dev_cache.refresh.failed", "dev_cache.refresh.invalidated"}

func Add(c Counter) { values[c].Add(1) }
func Snapshot() map[string]uint64 {
	m := make(map[string]uint64, len(names))
	for c, name := range names {
		m[name] = values[c].Load()
	}
	return m
}
