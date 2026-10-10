package androidcyaml

import (
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dev_cache"
	"github.com/metacubex/mihomo/dns"
)

func TestNetworkPartitionsSurviveHandoverAndSameConfigRebuild(t *testing.T) {
	identity := t.Name()
	previousOwnership := dev_cache.PlatformNetworkPartitions()
	key := func(environment string) string {
		return dev_cache.ScopedKey("environment|"+environment, "example.test/A")
	}
	SetDirectNetworkEnvironment("wifi")
	oldWiFi := dev_cache.AttachJSON("dns/"+identity+"/direct-source-2-system(wifi)", dev_cache.New[string, string](8, "lru"))
	oldWiFi.SetWithExpire(key("wifi"), "wifi-answer", time.Now())
	sim := dev_cache.AttachJSON("dns/"+identity+"/direct-source-2-system(sim)", dev_cache.New[string, string](8, "lru"))
	sim.SetWithExpire(key("sim"), "sim-answer", time.Now())
	obsolete := dev_cache.AttachJSON("dns/"+identity+"-obsolete/direct-source-2-system(wifi)", dev_cache.New[string, string](8, "lru"))
	obsolete.SetWithExpire(key("wifi"), "obsolete-config", time.Now())
	winner := dev_cache.AttachJSON("tcp-winner/"+identity, dev_cache.New[string, string](8, "lru"))
	winner.SetWithExpire(key("wifi"), "wifi-winner", time.Now())
	winner.SetWithExpire(key("sim"), "sim-winner", time.Now())
	config := dns.Config{CacheIdentity: identity, Main: []dns.NameServer{{Addr: "127.0.0.1:54181"}}, DirectServer: []dns.NameServer{{Addr: "127.0.0.1:54182"}}}
	dns.RegisterPersistentCaches(dns.NewResolver(config))
	dns.RegisterDiagnosticService(nil)
	t.Cleanup(func() {
		SetDirectNetworkEnvironment("")
		dev_cache.SetPlatformNetworkPartitions(previousOwnership)
		dns.RegisterPersistentCaches(dns.Resolvers{})
		dns.RegisterDiagnosticService(nil)
		dns.RetainCurrentCaches()
		dev_cache.RetainNamespaces(func(name string) bool { return name != "tcp-winner/"+identity })
	})
	SetDirectNetworkEnvironment("sim")
	ClearVolatileDNSCache()
	// Android may rebuild the core with the same document after IPv6 changes.
	config.IPv6 = true
	dns.RegisterPersistentCaches(dns.NewResolver(config))
	dns.RetainCurrentCaches()
	if _, ok := oldWiFi.Get(key("wifi")); !ok {
		t.Fatal("Wi-Fi DNS origin was cleared during handover")
	}
	if _, ok := sim.Get(key("sim")); !ok {
		t.Fatal("SIM DNS origin was cleared during handover")
	}
	if _, ok := obsolete.Get(key("wifi")); ok {
		t.Fatal("an obsolete configuration was preserved")
	}
	if _, ok := sim.Get(key("wifi")); ok {
		t.Fatal("SIM returned a Wi-Fi answer")
	}
	// An outage can also restart the core with an empty network fingerprint.
	SetDirectNetworkEnvironment("")
	config.DirectServer[0].Addr = "127.0.0.1:54183"
	dns.RegisterPersistentCaches(dns.NewResolver(config))
	dns.RetainCurrentCaches()
	if _, ok := oldWiFi.Get(key("wifi")); !ok {
		t.Fatal("network outage retired a remembered Wi-Fi origin")
	}
	if _, ok := sim.Get(key("sim")); !ok {
		t.Fatal("network outage retired a remembered SIM origin")
	}
	SetDirectNetworkEnvironment("wifi")
	if v, ok := oldWiFi.Get(key("wifi")); !ok || v != "wifi-answer" {
		t.Fatal("returning to Wi-Fi lost its cached answer")
	}
	if v, ok := winner.Get(key("wifi")); !ok || v != "wifi-winner" {
		t.Fatal("handover lost TCP hints")
	}
	if n := RetireNetworkScope("wifi"); n < 2 {
		t.Fatalf("explicit retirement removed %d entries, want at least DNS and TCP", n)
	}
	if _, ok := oldWiFi.Get(key("wifi")); ok {
		t.Fatal("explicit Wi-Fi retirement did not clear its origin")
	}
	if _, ok := winner.Get(key("wifi")); ok {
		t.Fatal("explicit Wi-Fi retirement did not clear its TCP hint")
	}
	if v, ok := sim.Get(key("sim")); !ok || v != "sim-answer" {
		t.Fatal("Wi-Fi retirement cleared SIM")
	}
	if v, ok := winner.Get(key("sim")); !ok || v != "sim-winner" {
		t.Fatal("Wi-Fi retirement cleared SIM TCP hints")
	}
	for _, record := range dev_cache.Snapshot() {
		if strings.HasPrefix(record.Namespace, "dns/"+identity+"-obsolete/") {
			t.Fatal("obsolete configuration was persisted")
		}
	}
}
