package common

import (
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/quic-go"
)

// MTUCache belongs to one leaf proxy, never a selector or a global endpoint map.
// A network change replaces the cache so late ACKs from old connections cannot
// repopulate the new network's hint. Port hopping preserves the same hint.
type MTUCache struct {
	mu         sync.Mutex
	generation uint64
	remote     netip.Addr
	cache      *quic.MTUDiscoveryCache
}

func (c *MTUCache) config(conf *quic.Config, remote netip.Addr) *quic.Config {
	if c == nil || conf.DisablePathMTUDiscovery {
		return conf
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	generation := dialer.NetworkGeneration()
	remote = remote.Unmap()
	if c.cache == nil || c.generation != generation || c.remote != remote {
		c.cache = new(quic.MTUDiscoveryCache)
		c.generation = generation
		c.remote = remote
	}
	conf = conf.Clone()
	conf.MTUDiscoveryCache = c.cache
	return conf
}
