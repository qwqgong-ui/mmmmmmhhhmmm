package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

func TestHealthCheckUsesRealURLTestPath(t *testing.T) {
	const proxyCount = 3
	arrivals := make(chan string, proxyCount)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivals <- r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proxies := make([]C.Proxy, 0, proxyCount)
	for _, name := range []string{"probe-1", "probe-2", "probe-3"} {
		proxies = append(proxies, adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name})))
	}

	hc := NewHealthCheck(proxies, server.URL, 1000, 0, false, nil)
	defer hc.close()
	hc.check()

	got := make([]string, 0, proxyCount)
	for range proxyCount {
		select {
		case method := <-arrivals:
			got = append(got, method)
		case <-time.After(time.Second):
			t.Fatalf("received %d of %d real URL-test probes", len(got), proxyCount)
		}
	}

	for i, method := range got {
		if method != http.MethodHead {
			t.Errorf("probe %d method = %s, want HEAD", i, method)
		}
	}

	for _, proxy := range proxies {
		if !proxy.AliveForTestUrl(server.URL) {
			t.Errorf("proxy %s was not marked alive through the real URL-test path", proxy.Name())
		}
	}
}
