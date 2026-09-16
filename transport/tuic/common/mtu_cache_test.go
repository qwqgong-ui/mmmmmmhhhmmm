package common

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/quic-go"
	"github.com/stretchr/testify/require"
)

func TestLeafMTUCacheLifecycle(t *testing.T) {
	var a, b MTUCache
	cfg := new(quic.Config)
	ip := netip.MustParseAddr("192.0.2.1")
	first := a.config(cfg, ip).MTUDiscoveryCache
	require.NotNil(t, first)
	require.Nil(t, cfg.MTUDiscoveryCache, "do not mutate shared config")
	require.Same(t, first, a.config(cfg, ip).MTUDiscoveryCache)
	require.NotSame(t, first, b.config(cfg, ip).MTUDiscoveryCache, "leaf nodes are isolated")
	dialer.NotifyNetworkChange()
	second := a.config(cfg, ip).MTUDiscoveryCache
	require.NotSame(t, first, second)
	require.Same(t, second, a.config(cfg, ip).MTUDiscoveryCache)
	third := a.config(cfg, netip.MustParseAddr("2001:db8::1")).MTUDiscoveryCache
	require.NotSame(t, second, third, "changed endpoint must not inherit old path")
	other := &quic.Config{DisablePathMTUDiscovery: true}
	require.Same(t, other, a.config(other, ip))
}
