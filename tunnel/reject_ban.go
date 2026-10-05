package tunnel

import (
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	C "github.com/metacubex/mihomo/constant"
)

const (
	rejectBanThreshold = 10
	rejectBanWindow    = 10 * time.Second
	rejectBanDuration  = time.Minute
	maxRejectBanKeys   = 4096
)

// A ban belongs to one source/destination and inbound routing context. Source
// ports are deliberately excluded so reconnecting cannot evade the threshold.
type rejectBanKey struct {
	source       netip.Addr
	destination  netip.Addr
	host         string
	port         uint16
	inboundType  C.Type
	inboundIP    netip.Addr
	inboundPort  uint16
	inboundName  string
	inboundUser  string
	specialProxy string
	specialRules string
	dscp         uint8
}

func tcpRejectBanKey(metadata *C.Metadata) (rejectBanKey, bool) {
	if metadata.NetWork != C.TCP || !metadata.SrcIP.IsValid() || metadata.SrcIP.IsUnspecified() || metadata.DstPort == 0 {
		return rejectBanKey{}, false
	}
	key := rejectBanKey{
		source:       metadata.SrcIP.Unmap(),
		host:         strings.ToLower(strings.TrimSuffix(metadata.RuleHost(), ".")),
		port:         metadata.DstPort,
		inboundType:  metadata.Type,
		inboundIP:    metadata.InIP.Unmap(),
		inboundPort:  metadata.InPort,
		inboundName:  metadata.InName,
		inboundUser:  metadata.InUser,
		specialProxy: metadata.SpecialProxy,
		specialRules: metadata.SpecialRules,
		dscp:         metadata.DSCP,
	}
	if key.host == "" {
		key.destination = metadata.DstIP.Unmap()
	}
	return key, key.host != "" || key.destination.IsValid()
}

type rejectBanEntry struct {
	rejectedAt [rejectBanThreshold]time.Time
	next       int
	count      int
	lastReject time.Time
	banUntil   time.Time
	proxy      C.Proxy
}

// Expiration is checked lazily; neither counting nor banning retains a socket,
// starts a timer or needs a background goroutine. The LRU bounds all entries,
// including sources that never reach the threshold.
type rejectBanCache struct {
	mutex      sync.Mutex
	entries    *lru.LruCache[rejectBanKey, *rejectBanEntry]
	generation atomic.Uint64
}

func newRejectBanCache() *rejectBanCache {
	return &rejectBanCache{
		entries: lru.New(lru.WithSize[rejectBanKey, *rejectBanEntry](maxRejectBanKeys)),
	}
}

var defaultRejectBans = newRejectBanCache()

func rejectBanProxyActive(proxy C.Proxy, metadata *C.Metadata) bool {
	for leaf := proxy; leaf != nil; leaf = leaf.Unwrap(metadata, false) {
		switch leaf.Type() {
		case C.Reject:
			return true
		case C.RejectDrop:
			return false
		}
	}
	return false
}

// Lookup returns the matched proxy only while its ban is active. Callers must
// unwrap it outside the cache lock to check for live proxy-group selection
// changes. The generation prevents in-flight old routing results from restoring
// entries after a configuration or rule-provider update.
func (c *rejectBanCache) Lookup(key rejectBanKey, now time.Time) (C.Proxy, uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	entry, ok := c.entries.Get(key)
	if !ok {
		return nil, c.generation.Load()
	}
	if !entry.banUntil.IsZero() {
		if now.Before(entry.banUntil) {
			return entry.proxy, c.generation.Load()
		}
		c.entries.Delete(key)
	} else if now.Sub(entry.lastReject) > rejectBanWindow {
		c.entries.Delete(key)
	}
	return nil, c.generation.Load()
}

// Proxy-group validation runs outside the lock and may overlap a policy update.
func (c *rejectBanCache) Current(generation uint64) bool {
	return generation == c.generation.Load()
}

// Reject counts actual REJECT decisions in a sliding window. An active ban is
// fixed at one minute from the tenth rejection; further attempts do not extend
// it. Only the caller that creates a ban receives its deadline for logging.
func (c *rejectBanCache) Reject(key rejectBanKey, generation uint64, proxy C.Proxy, now time.Time) (time.Time, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.Current(generation) {
		return time.Time{}, false
	}
	entry, ok := c.entries.Get(key)
	if ok && !entry.banUntil.IsZero() && now.Before(entry.banUntil) {
		return time.Time{}, false
	}
	if !ok || !entry.banUntil.IsZero() || now.Sub(entry.lastReject) > rejectBanWindow {
		entry = &rejectBanEntry{}
		c.entries.Set(key, entry)
	}
	// Concurrent callers may have sampled their clock before taking this lock.
	if now.Before(entry.lastReject) {
		now = entry.lastReject
	}
	entry.lastReject = now
	entry.rejectedAt[entry.next] = now
	entry.next = (entry.next + 1) % rejectBanThreshold
	if entry.count < rejectBanThreshold {
		entry.count++
	}
	if entry.count < rejectBanThreshold || now.Sub(entry.rejectedAt[entry.next]) > rejectBanWindow {
		return time.Time{}, false
	}
	entry.banUntil = now.Add(rejectBanDuration)
	entry.proxy = proxy
	return entry.banUntil, true
}

func (c *rejectBanCache) Forget(key rejectBanKey, generation uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.Current(generation) {
		c.entries.Delete(key)
	}
}

func (c *rejectBanCache) Reset() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.generation.Add(1)
	c.entries.Clear()
}
