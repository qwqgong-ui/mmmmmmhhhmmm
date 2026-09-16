package quic

import (
	"sync"

	"github.com/metacubex/quic-go/internal/protocol"
)

// MTUDiscoveryCache remembers a leaf proxy's acknowledged packet size across
// connections. Its owner must replace it when the network or endpoint changes.
// The hint is validated before sending larger data packets. The zero value is
// ready to use. An MTUDiscoveryCache must not be copied after first use.
type MTUDiscoveryCache struct {
	mu         sync.Mutex
	generation uint64
	result     mtuCacheResult
}

type mtuCacheResult struct {
	size protocol.ByteCount
	done bool
}

func (c *MTUDiscoveryCache) load() (mtuCacheResult, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.result, c.generation
}

func (c *MTUDiscoveryCache) store(result mtuCacheResult, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation == generation && (result.size > c.result.size ||
		(result.size == c.result.size && (!c.result.done || result.done))) {
		c.result = result
	}
}

func (c *MTUDiscoveryCache) invalidate(generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation {
		return false
	}
	c.generation++
	c.result = mtuCacheResult{}
	return true
}

func (f *mtuFinder) useCache(cache *MTUDiscoveryCache) {
	if cache == nil {
		return
	}
	f.cache = cache
	f.cached, f.cacheGeneration = cache.load()
	if f.cached.size <= f.min {
		f.cached = mtuCacheResult{}
	} else if f.cached.size > f.max() {
		f.cached.size = f.max()
	}
}

func (f *mtuFinder) remember() {
	if f.cache != nil {
		f.cache.store(mtuCacheResult{size: f.min, done: f.done()}, f.cacheGeneration)
	}
}
