package quic

import (
	"sync"
	"testing"
	"time"

	"github.com/metacubex/quic-go/internal/monotime"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func cachedMTUFinder(cache *MTUDiscoveryCache, max protocol.ByteCount) *mtuFinder {
	rtt := utils.NewRTTStats()
	rtt.UpdateRTT(10*time.Millisecond, 0)
	f := newMTUDiscoverer(rtt, 1280, max, nil)
	f.useCache(cache)
	return f
}

func TestMTUCacheReconnect(t *testing.T) {
	cache := new(MTUDiscoveryCache)
	f := cachedMTUFinder(cache, 1452)
	now := monotime.Now()
	f.Start(now)
	probes := 0
	for !f.done() {
		now = now.Add(time.Second)
		require.True(t, f.ShouldSendProbe(now))
		ping, _ := f.GetPing(now)
		ping.Handler.OnAcked(ping.Frame)
		probes++
	}
	require.Greater(t, probes, 1)
	confirmed := f.CurrentSize()
	warm := cachedMTUFinder(cache, 1452)
	require.Equal(t, protocol.ByteCount(1280), warm.CurrentSize())
	require.False(t, warm.ShouldSendProbe(now), "must wait for handshake")
	warm.Start(now)
	require.True(t, warm.ShouldSendProbe(now))
	ping, size := warm.GetPing(now)
	require.Equal(t, confirmed, size)
	require.False(t, warm.ShouldSendProbe(now.Add(time.Second)))
	ping.Handler.OnAcked(ping.Frame)
	require.Equal(t, confirmed, warm.CurrentSize())
	require.False(t, warm.ShouldSendProbe(now.Add(time.Hour)), "one ACK completes cached discovery")
}

func TestMTUCacheStaleHintAndLateACK(t *testing.T) {
	cache := new(MTUDiscoveryCache)
	cache.store(mtuCacheResult{1441, true}, 0)
	a, b := cachedMTUFinder(cache, 1452), cachedMTUFinder(cache, 1452)
	now := monotime.Now()
	pa, size := a.GetPing(now)
	require.Equal(t, protocol.ByteCount(1441), size)
	pb, _ := b.GetPing(now)
	pa.Handler.OnLost(pa.Frame)
	require.Equal(t, protocol.ByteCount(1280), a.CurrentSize())
	pb.Handler.OnAcked(pb.Frame)
	result, _ := cache.load()
	require.Zero(t, result.size, "late old-path ACK must not restore invalidated hint")
	p, size := a.GetPing(now.Add(time.Second))
	require.Equal(t, protocol.ByteCount((1280+1452)/2), size)
	p.Handler.OnAcked(p.Frame)
	result, _ = cache.load()
	require.Equal(t, size, result.size)
	require.False(t, result.done)
}

func TestMTUCacheResetAndPeerLimit(t *testing.T) {
	cache := new(MTUDiscoveryCache)
	cache.store(mtuCacheResult{1441, true}, 0)
	f := cachedMTUFinder(cache, 1350)
	now := monotime.Now()
	p, size := f.GetPing(now)
	require.Equal(t, protocol.ByteCount(1350), size)
	f.Reset(now, 1280, 1452)
	p.Handler.OnAcked(p.Frame)
	require.Equal(t, protocol.ByteCount(1280), f.CurrentSize())
	result, _ := cache.load()
	require.Zero(t, result.size)
	p, _ = f.GetPing(now.Add(time.Second))
	p.Handler.OnAcked(p.Frame)
	result, _ = cache.load()
	require.Zero(t, result.size, "migrated path must not update old cache")
}

func TestMTUCacheConfigAndConcurrency(t *testing.T) {
	cache := new(MTUDiscoveryCache)
	cache.store(mtuCacheResult{1441, true}, 0)
	cache.store(mtuCacheResult{1366, false}, 0)
	result, _ := cache.load()
	require.Equal(t, mtuCacheResult{1441, true}, result, "slower concurrent discovery must not regress the hint")
	cfg := populateConfig((&Config{MTUDiscoveryCache: cache}).Clone())
	require.Same(t, cache, cfg.MTUDiscoveryCache)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, generation := cache.load()
				cache.store(mtuCacheResult{1400, true}, generation)
				cache.invalidate(generation)
			}
		}()
	}
	wg.Wait()
}
