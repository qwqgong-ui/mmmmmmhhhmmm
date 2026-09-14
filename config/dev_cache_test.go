package config

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDNSCacheIdentityIsStableAndSeparatesConfiguration(t *testing.T) {
	raw := &RawConfig{DNS: RawDNS{NameServer: []string{"1.1.1.1"}, IPv6: false}, Proxy: []map[string]any{{"name": "node", "server": "first.example", "type": "socks5"}}}
	first, err := dnsCacheIdentity(raw)
	require.NoError(t, err)
	raw.DNS.IPv6 = true
	same, err := dnsCacheIdentity(raw)
	require.NoError(t, err)
	require.Equal(t, first, same)
	raw.Proxy = []map[string]any{{"type": "socks5", "server": "first.example", "name": "node"}}
	same, err = dnsCacheIdentity(raw)
	require.NoError(t, err)
	require.Equal(t, first, same)
	raw.Proxy[0]["server"] = "second.example"
	changed, err := dnsCacheIdentity(raw)
	require.NoError(t, err)
	require.NotEqual(t, first, changed)
}
