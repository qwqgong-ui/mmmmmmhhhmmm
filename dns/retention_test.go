package dns

import (
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dev_cache"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRetainCurrentCachesRetiresChangedIdentityAndDNSOrigin(t *testing.T) {
	identity := t.Name()
	q := new(D.Msg).SetQuestion("retention.example.", D.TypeA)
	key := dev_cache.ScopedKey("environment|retention-test", q.Question[0].String())
	first := NewResolver(Config{CacheIdentity: identity + "/old", Main: []NameServer{{Addr: "127.0.0.1:54191"}}, DirectServer: []NameServer{{Addr: "127.0.0.1:54192"}}})
	RegisterPersistentCaches(first)
	first.cache.SetWithExpire(key, directAnswer(q, "192.0.2.1", 60), time.Now())
	first.DirectResolver.sourceCaches[0].SetWithExpire(key, directAnswer(q, "192.0.2.2", 60), time.Now())
	config := Config{CacheIdentity: identity, Main: []NameServer{{Addr: "127.0.0.1:54191"}}, DirectServer: []NameServer{{Addr: "127.0.0.1:54192"}}}
	current := NewResolver(config)
	RegisterPersistentCaches(current)
	current.cache.SetWithExpire(key, directAnswer(q, "192.0.2.3", 60), time.Now())
	service := NewFakeIPServiceResolver(nil, current.DirectResolver.Resolver, "lru", 16, identity)
	RegisterDiagnosticService(service)
	service.domainClient.cache.SetWithExpire("bundle", directAnswer(q, "192.0.2.4", 60), time.Now())
	t.Cleanup(func() {
		RegisterPersistentCaches(Resolvers{})
		RegisterDiagnosticService(nil)
		RetainCurrentCaches()
	})
	require.Positive(t, RetainCurrentCaches())
	_, ok := first.cache.Get(key)
	require.False(t, ok)
	_, ok = current.cache.Get(key)
	require.True(t, ok)
	_, ok = service.domainClient.cache.Get("bundle")
	require.True(t, ok, "current fake-IP service cache was retired")
	oldSource := current.DirectResolver.sourceCaches[0]
	oldSource.SetWithExpire(key, directAnswer(q, "192.0.2.5", 60), time.Now())
	config.DirectServer[0].Addr = "127.0.0.1:54193"
	changedSource := NewResolver(config)
	RegisterPersistentCaches(changedSource)
	RetainCurrentCaches()
	require.Same(t, current.cache, changedSource.cache, "matching resolver cache was replaced")
	_, ok = oldSource.Get(key)
	require.False(t, ok, "retired DNS origin kept its answers")
	for _, record := range dev_cache.Snapshot() {
		require.False(t, strings.HasPrefix(record.Namespace, "dns/"+identity+"/old/"), "old identity was saved again")
	}
	RegisterPersistentCaches(Resolvers{})
	RegisterDiagnosticService(nil)
	RetainCurrentCaches()
	_, ok = changedSource.cache.Get(key)
	require.False(t, ok, "disabling DNS retained the old runtime cache")
	_, ok = service.domainClient.cache.Get("bundle")
	require.False(t, ok, "disabling DNS retained the domain bundle")
}
