package tunnel

import (
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

func TestConnectionInfoLogReachesSubscriberWithWarningConsole(t *testing.T) {
	previous := log.Level()
	log.SetLevel(log.WARNING)
	t.Cleanup(func() { log.SetLevel(previous) })
	subscriber := log.SubscribeLevel(log.INFO)
	t.Cleanup(func() { log.UnSubscribe(subscriber) })
	logMetadata(udpMetadata("192.0.2.1", "example.com", 443), nil, C.Chain{"node"})
	select {
	case event := <-subscriber:
		if event.LogLevel != log.INFO || !strings.Contains(event.Payload, "example.com:443") {
			t.Fatalf("unexpected connection event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("connection INFO event missing from subscriber")
	}
}

func TestKeepResolvedFakeIP(t *testing.T) {
	tests := []struct {
		name        string
		adapterType C.AdapterType
		want        bool
	}{
		{name: "direct", adapterType: C.Direct, want: true},
		{name: "reject", adapterType: C.Reject, want: true},
		{name: "reject drop", adapterType: C.RejectDrop, want: true},
		{name: "proxy", adapterType: C.Shadowsocks, want: false},
		{name: "compatible", adapterType: C.Compatible, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := keepResolvedFakeIP(test.adapterType); got != test.want {
				t.Fatalf("keepResolvedFakeIP(%s) = %t, want %t", test.adapterType, got, test.want)
			}
		})
	}
}

func TestFakeIPRuleResolver(t *testing.T) {
	for _, test := range []struct {
		name     string
		dnsMode  C.DNSMode
		wantCall bool
	}{
		{name: "fake IP", dnsMode: C.DNSFakeIP, wantCall: false},
		{name: "mapping", dnsMode: C.DNSMapping, wantCall: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			resolveIP := fakeIPRuleResolver(&C.Metadata{DNSMode: test.dnsMode}, func() { called = true })
			if resolveIP != nil {
				resolveIP()
			}
			if called != test.wantCall {
				t.Fatalf("resolver called = %t, want %t", called, test.wantCall)
			}
		})
	}
}
