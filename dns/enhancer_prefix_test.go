package dns

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	C "github.com/metacubex/mihomo/constant"
)

func TestFindHostByIPPreservesRealMappingsWithFakeIPPools(t *testing.T) {
	p4, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.0/24"), Size: 16})
	if err != nil {
		t.Fatal(err)
	}
	p6, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("2001:2::/120"), Size: 16})
	if err != nil {
		t.Fatal(err)
	}
	e := NewEnhancer(EnhancerConfig{IPv6: true, EnhancedMode: C.DNSFakeIP, FakeIPPool: p4, FakeIPPool6: p6})
	for _, addr := range []string{"127.0.0.5", "192.168.1.1", "1.1.1.1", "2606:4700:4700::1111"} {
		ip := netip.MustParseAddr(addr)
		e.InsertHostByIP(ip, "real.test")
		if host, ok := e.FindHostByIP(ip); !ok || host != "real.test" {
			t.Fatalf("real mapping lost for %s: %q %v", ip, host, ok)
		}
	}
	for _, p := range []*fakeip.Pool{p4, p6} {
		ip := p.Lookup("fake.test")
		e.InsertHostByIP(ip, "fallback.test")
		if host, ok := e.FindHostByIP(ip); !ok || host != "fake.test" {
			t.Fatalf("Fake-IP mapping lost priority for %s: %q %v", ip, host, ok)
		}
	}
	if _, ok := e.FindHostByIP(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("unknown real address resolved")
	}
}
