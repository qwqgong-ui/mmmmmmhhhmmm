package dns

import (
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/arc"
	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

// StoreInterval is how often the DNS answer cache is written to the cache file
// on top of the flush that runs at shutdown.
const StoreInterval = time.Hour

// arcSnapshot and lruSnapshot are the snapshot APIs of the two cache
// implementations behind cache-algorithm. They return different item types, so
// snapshotOf normalises them; a cache providing neither is simply not
// persisted.
type arcSnapshot interface {
	Snapshot() []arc.Item[string, *D.Msg]
}

type lruSnapshot interface {
	Snapshot() []lru.Item[string, *D.Msg]
}

// cacheItem is one entry from either implementation.
type cacheItem struct {
	Key     string
	Value   *D.Msg
	Expires time.Time
}

// snapshotOf returns c's entries, or ok=false when c cannot be snapshotted.
func snapshotOf(c dnsCache) (items []cacheItem, ok bool) {
	switch sc := c.(type) {
	case arcSnapshot:
		for _, item := range sc.Snapshot() {
			items = append(items, cacheItem{Key: item.Key, Value: item.Value, Expires: item.Expires})
		}
	case lruSnapshot:
		for _, item := range sc.Snapshot() {
			items = append(items, cacheItem{Key: item.Key, Value: item.Value, Expires: item.Expires})
		}
	default:
		return nil, false
	}
	return items, true
}

// keySep separates a resolver's name from the DNS question inside a persisted
// key. mihomo runs several resolvers (main, proxy-server, direct) with
// independent caches; they share one bucket, so their keys must not collide.
const keySep = "\x00"

var (
	persistMu     sync.Mutex
	persistCaches = make(map[string]dnsCache)
	storeOnce     sync.Once

	// restored guards the one-time replay of the previous run's answers.
	// updateDNS runs again on every config reload *and* on every runtime
	// IPv6 availability flip, each time building fresh caches; replaying
	// the on-disk snapshot into them would resurrect answers the user just
	// reconfigured away, and would carry one network's unscoped answers
	// (main/proxy-server/direct) across a network switch.
	restored bool
)

// registerPersistentCache remembers the live cache so StoreCache can snapshot
// it later, and restores whatever the previous run left behind.
//
// It must not touch the cache file: resolvers are built before the runtime has
// finished pointing C.Path at the -d directory, and cachefile.Cache() is a
// singleton that permanently latches whatever path it first sees. Calling it
// here made the whole process open (and fail on) the default
// $HOME/.config/mihomo/cache.db, which left the fake-ip pool with no store at
// all. LoadPersistentCache does the file work, once the runtime is ready.
func registerPersistentCache(name string, c dnsCache) {
	if _, ok := snapshotOf(c); !ok {
		return
	}

	persistMu.Lock()
	persistCaches[name] = c
	persistMu.Unlock()
}

// RegisterPersistentCaches makes one generation of resolvers the set that is
// snapshotted to the cache file, replacing whatever the previous generation
// registered.
//
// Only the runtime's own resolvers belong here. NewResolver is also used to
// build the private resolvers of individual outbounds (wireguard, masque,
// openvpn, zerotier); registering from inside the constructor filed those
// under the same names as the global ones, so an outbound's private answers
// were persisted in place of the real main resolver's and restored into it on
// the next start.
//
// The registry is replaced wholesale rather than added to: updateDNS runs
// again on every reload and on every runtime IPv6 availability flip, and a
// resolver the new configuration no longer builds would otherwise keep its
// cache -- and the resolver graph behind it -- alive and on disk forever.
func RegisterPersistentCaches(rs Resolvers) {
	persistMu.Lock()
	clear(persistCaches)
	persistMu.Unlock()

	if rs.Resolver != nil {
		registerPersistentCache("main", rs.Resolver.cache)
	}
	if rs.ProxyResolver != nil {
		registerPersistentCache("proxy-server", rs.ProxyResolver.cache)
	}
	direct := rs.DirectResolver
	if direct == nil || direct.Resolver == nil {
		return
	}
	registerPersistentCache("direct", direct.cache)
	for index, sourceCache := range direct.sourceCaches {
		if index >= len(direct.main) {
			break
		}
		// Keyed by the upstream's own address, never by its position alone:
		// reordering direct-nameserver must not hand one upstream the answers
		// persisted for another.
		registerPersistentCache(fmt.Sprintf("direct-source-%d-%s", index+1, direct.main[index].Address()), sourceCache)
	}
}

// LoadPersistentCache restores previously persisted answers into every
// registered cache and starts the periodic snapshot. Call it from the runtime
// after the DNS resolvers are in place, never during their construction.
func LoadPersistentCache() {
	persistMu.Lock()
	caches := make(map[string]dnsCache, len(persistCaches))
	maps.Copy(caches, persistCaches)
	persistMu.Unlock()

	if len(caches) == 0 {
		return
	}

	persistMu.Lock()
	replay := !restored
	restored = true
	persistMu.Unlock()
	if replay {
		entries, err := cachefile.Cache().ReadDNSCache()
		if err != nil {
			log.Fields(log.WARNING, map[string]string{"subsystem": "dns", "event": "persistent_cache_load_failed", "reason": err.Error()}, "[DNS] persistent cache load failed: %v", err)
		} else {
			for name, c := range caches {
				loadCache(name, c, entries)
			}
		}
	}
	storeOnce.Do(startStoreLoop)
}

// loadCache restores persisted answers. Entries keep their original expiry, so
// an answer that went stale while mihomo was down is restored stale: the
// optimistic-cache path serves it once and refreshes it in the background,
// exactly as it would have without a restart.
func loadCache(name string, c dnsCache, entries []cachefile.DNSEntry) {
	prefix := name + keySep
	restored := 0
	stale := 0
	invalid := 0
	now := time.Now()
	for _, entry := range entries {
		key, ok := strings.CutPrefix(entry.Key, prefix)
		if !ok {
			continue
		}
		msg := new(D.Msg)
		if err := msg.Unpack(entry.Msg); err != nil {
			invalid++
			continue
		}
		c.SetWithExpire(key, msg, entry.Expires)
		restored++
		if !now.Before(entry.Expires) {
			stale++
		}
	}
	log.Fields(log.INFO, map[string]string{"subsystem": "dns", "event": "persistent_cache_loaded", "resolver": name, "restored": fmt.Sprint(restored), "stale": fmt.Sprint(stale), "invalid": fmt.Sprint(invalid)}, "[DNS] persistent cache loaded for %s: restored=%d stale=%d invalid=%d", name, restored, stale, invalid)
}

// StoreCache writes the current DNS answer cache to the cache file. It is safe
// to call when the cache is absent or cannot be snapshotted.
func StoreCache() {
	persistMu.Lock()
	caches := make(map[string]dnsCache, len(persistCaches))
	maps.Copy(caches, persistCaches)
	persistMu.Unlock()

	var entries []cachefile.DNSEntry
	for name, c := range caches {
		items, ok := snapshotOf(c)
		if !ok {
			continue
		}
		for _, item := range items {
			if item.Value == nil {
				continue
			}
			packed, err := item.Value.Pack()
			if err != nil {
				continue
			}
			entries = append(entries, cachefile.DNSEntry{
				Key:     name + keySep + item.Key,
				Msg:     packed,
				Expires: item.Expires,
			})
		}
	}

	if err := cachefile.Cache().SetDNSCache(entries); err != nil {
		log.Fields(log.WARNING, map[string]string{"subsystem": "dns", "event": "persistent_cache_flush_failed", "reason": err.Error()}, "[DNS] persistent cache flush failed: %v", err)
		return
	}
	log.Fields(log.INFO, map[string]string{"subsystem": "dns", "event": "persistent_cache_flushed", "entries": fmt.Sprint(len(entries))}, "[DNS] flushed %d cached answers to cache file", len(entries))
}

func startStoreLoop() {
	go func() {
		ticker := time.NewTicker(StoreInterval)
		defer ticker.Stop()
		for range ticker.C {
			StoreCache()
		}
	}()
}

// cacheDeleter is implemented by the cache algorithms that can remove a single
// key. A cache without it is expired in place instead, which every read path
// already honours.
type cacheDeleter interface {
	Delete(key string)
}

// EvictNetworkScope drops every cached answer belonging to one network scope and
// reports how many were removed.
//
// The direct-nameserver candidate caches are keyed by network scope precisely so
// that one physical network's answers are never served on another, and that is
// why nothing clears them on a handover. The gap is retirement: when the
// platform stops tracking a network entirely, its branch has no owner left, yet
// the answers survive until each entry's own expiry -- with a 24-hour floor,
// long after the profile that explained them is gone. The platform knows when it
// retired a network; this lets it say so.
func EvictNetworkScope(scope string) int {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return 0
	}
	prefix := scope + keySep

	persistMu.Lock()
	caches := make([]dnsCache, 0, len(persistCaches))
	for _, c := range persistCaches {
		caches = append(caches, c)
	}
	persistMu.Unlock()

	evicted := 0
	for _, c := range caches {
		items, ok := snapshotOf(c)
		if !ok {
			continue
		}
		deleter, deletable := c.(cacheDeleter)
		for _, item := range items {
			if !strings.HasPrefix(item.Key, prefix) {
				continue
			}
			evicted++
			if deletable {
				deleter.Delete(item.Key)
				continue
			}
			c.SetWithExpire(item.Key, item.Value, time.Unix(0, 0))
		}
	}
	if evicted > 0 {
		log.Fields(log.INFO, map[string]string{"subsystem": "dns", "event": "network_scope_evicted", "network_scope": scope, "entries": fmt.Sprint(evicted), "reason": "scope_retired"}, "[DNS] evicted %d cached answers for retired network scope %s", evicted, scope)
	}
	return evicted
}
