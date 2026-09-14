package dns

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dev_cache"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

const StoreInterval = time.Hour
const keySep = dev_cache.Separator

var (
	persistMu     sync.Mutex
	persistCaches = make(map[string]dnsCache)
	storeOnce     sync.Once
	storeMu       sync.Mutex
)

func registerPersistentCache(name string, c dnsCache) {
	persistMu.Lock()
	defer persistMu.Unlock()
	persistCaches[name] = c
}

func attachDNSCache(name string, c dnsCache) dnsCache {
	return dev_cache.Attach(name, c, func(msg *D.Msg) ([]byte, error) { return msg.Pack() }, func(data []byte) (*D.Msg, error) {
		msg := new(D.Msg)
		err := msg.Unpack(data)
		return msg, err
	})
}

// Runtime resolvers reattach to their configuration namespace. Private outbound
// resolvers remain private and cannot replace the global DNS persistence owner.
func RegisterPersistentCaches(rs Resolvers) {
	persistMu.Lock()
	clear(persistCaches)
	persistMu.Unlock()
	attach := func(role string, r *Resolver) {
		if r == nil || r.cache == nil {
			return
		}
		r.cache = attachDNSCache("dns/"+r.cacheIdentity+"/"+role, r.cache)
		registerPersistentCache(role, r.cache)
	}
	attach("main", rs.Resolver)
	attach("proxy-server", rs.ProxyResolver)
	attach("bootstrap", rs.BootstrapResolver)
	if rs.DirectResolver == nil || rs.DirectResolver.Resolver == nil {
		return
	}
	direct := rs.DirectResolver.Resolver
	attach("direct", direct)
	for index, c := range direct.sourceCaches {
		name := fmt.Sprintf("direct-source-%d-%s", index+1, direct.main[index].Address())
		direct.sourceCaches[index] = attachDNSCache("dns/"+direct.cacheIdentity+"/"+name, c)
		registerPersistentCache(name, direct.sourceCaches[index])
	}
}

// Load only after C.Path is initialized. Legacy unscoped dnscache records are
// deliberately not imported: their original physical network is unknowable.
func LoadPersistentCache() {
	var records []dev_cache.Record
	data, err := cachefile.Cache().DevCache()
	if err == nil && len(data) > 0 {
		err = json.Unmarshal(data, &records)
	}
	if err != nil {
		log.Fields(log.WARNING, map[string]string{"subsystem": "dev_cache", "event": "persistent_cache_load_failed"}, "Cache restore failed: %v", err)
		return
	}
	if dev_cache.Restore(records) {
		log.Fields(log.INFO, map[string]string{"subsystem": "dev_cache", "event": "persistent_cache_restored", "entries": fmt.Sprint(len(records))}, "Restored retained cache snapshot")
	}
	storeOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(StoreInterval)
			defer ticker.Stop()
			for range ticker.C {
				StoreCache()
			}
		}()
	})
}

func StoreCache() {
	storeMu.Lock()
	defer storeMu.Unlock()
	records := dev_cache.Snapshot()
	data, err := json.Marshal(records)
	if err == nil {
		err = cachefile.Cache().SetDevCache(data)
	}
	if err != nil {
		log.Fields(log.WARNING, map[string]string{"subsystem": "dev_cache", "event": "persistent_cache_flush_failed"}, "Cache flush failed: %v", err)
		return
	}
	log.Fields(log.INFO, map[string]string{"subsystem": "dev_cache", "event": "persistent_cache_flushed", "entries": fmt.Sprint(len(records))}, "Stored retained cache snapshot")
}

// FlushDevCache is synchronous, including the on-disk snapshot. In-flight
// refreshes carry an invalidated generation and cannot undo a manual flush.
func FlushDevCache() {
	dev_cache.ClearAll()
	StoreCache()
}

func EvictNetworkScope(scope string) int {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return 0
	}
	n := dev_cache.EvictScope(scope)
	// Include unregistered/test caches and private references in this generation.
	persistMu.Lock()
	defer persistMu.Unlock()
	for _, c := range persistCaches {
		n += c.DeleteMatching(func(k string) bool { return dev_cache.InScope(k, scope) })
	}
	return n
}
