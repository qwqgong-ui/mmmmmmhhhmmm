package dns

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/fakeip"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func testBundleClient(t *testing.T) (*domainClient, *atomic.Int32, *string) {
	t.Helper()
	public := &recordingServiceClient{response: &D.Msg{}}
	client := newDomainClient(public, nil, 10)
	calls := new(atomic.Int32)
	node := "JP"
	client.prepare = func(host string) (string, func(context.Context) (net.Conn, error), error) {
		selected := node
		return selected, func(context.Context) (net.Conn, error) {
			calls.Add(1)
			conn, _ := serveOneQuery(t, func(request *D.Msg) *D.Msg {
				response := new(D.Msg)
				response.SetReply(request)
				response.Answer = []D.RR{testServiceRecord(D.TypeHTTPS, D.Fqdn(host))}
				address := "192.0.2.1"
				if selected == "US" {
					address = "192.0.2.2"
				}
				rr, _ := D.NewRR(D.Fqdn(host) + " 20 IN A " + address)
				response.Extra = []D.RR{rr}
				response.SetEdns0(1232, false)
				response.IsEdns0().Option = []D.EDNS0{&D.EDNS0_LOCAL{Code: domainBundleOption, Data: []byte{1}}}
				return response
			})
			return conn, nil
		}, nil
	}
	return client, calls, &node
}

func TestDomainBundleAddressFirstNodeIsolationAndExpiry(t *testing.T) {
	client, calls, node := testBundleClient(t)
	request := new(D.Msg)
	request.SetQuestion("EXAMPLE.com.", D.TypeA)
	answer, err := client.ExchangeContext(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1", answer.Answer[0].(*D.A).A.String())
	require.Equal(t, uint32(20), answer.Answer[0].Header().Ttl)
	service, err := client.ExchangeContext(t.Context(), httpsQuery("example.com"))
	require.NoError(t, err)
	require.Contains(t, serviceRecordValues(service.Answer[0]), D.SVCB_ECHCONFIG)
	require.EqualValues(t, 1, calls.Load())
	// Caller mutation must not poison the raw cached record.
	service.Answer[0].(*D.HTTPS).Value = nil
	service, err = client.ExchangeContext(t.Context(), httpsQuery("example.com"))
	require.NoError(t, err)
	require.NotEmpty(t, service.Answer[0].(*D.HTTPS).Value)
	*node = "US"
	answer, err = client.ExchangeContext(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.2", answer.Answer[0].(*D.A).A.String())
	require.EqualValues(t, 2, calls.Load())
	key := domainKey("US", "example.com")
	cached, ok := client.cache.Get(key)
	require.True(t, ok)
	client.cache.SetWithExpire(key, cached, time.Now().Add(-time.Second))
	_, err = client.ExchangeContext(t.Context(), httpsQuery("example.com"))
	require.NoError(t, err)
	require.Eventually(t, func() bool { return calls.Load() == 3 }, time.Second, time.Millisecond)
}

func TestFakeIPFirstAddressWarmsServiceBundle(t *testing.T) {
	client, calls, _ := testBundleClient(t)
	pool := newTestFakeIPPool(t, "198.18.0.0/16")
	handler := withFakeIP(&fakeip.Skipper{}, pool, nil, 60, &Resolver{domainClient: client})(func(*icontext.DNSContext, *D.Msg) (*D.Msg, error) { t.Fatal("unexpected fallback"); return nil, nil })
	request := new(D.Msg)
	request.SetQuestion("example.com.", D.TypeA)
	answer, err := handler(icontext.NewDNSContext(t.Context()), request)
	require.NoError(t, err)
	require.Equal(t, "198.18.0.4", answer.Answer[0].(*D.A).A.String())
	require.Equal(t, uint32(20), answer.Answer[0].Header().Ttl)
	require.EqualValues(t, 1, calls.Load())
	service, err := handler(icontext.NewDNSContext(t.Context()), httpsQuery("example.com"))
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load())
	require.Contains(t, serviceRecordValues(service.Answer[0]), D.SVCB_ECHCONFIG)
	cached, ok := client.cache.Get(domainKey("JP", "example.com"))
	require.True(t, ok)
	require.Equal(t, "192.0.2.1", cached.Extra[0].(*D.A).A.String())
	require.Equal(t, "192.0.2.50", serviceRecordValues(cached.Answer[0])[D.SVCB_IPV4HINT].(*D.SVCBIPv4Hint).Hint[0].String())
	require.LessOrEqual(t, service.Answer[0].Header().Ttl, uint32(20))
}

func TestOldServerDoesNotCausePublicAddressQueries(t *testing.T) {
	public := &recordingServiceClient{response: &D.Msg{}}
	client := newDomainClient(public, nil, 10)
	var calls atomic.Int32
	client.prepare = func(string) (string, func(context.Context) (net.Conn, error), error) {
		return "old", func(context.Context) (net.Conn, error) {
			calls.Add(1)
			conn, _ := serveOneQuery(t, func(request *D.Msg) *D.Msg {
				response := new(D.Msg)
				response.SetReply(request)
				response.Answer = []D.RR{testServiceRecord(D.TypeHTTPS, "example.com.")}
				return response
			})
			return conn, nil
		}, nil
	}
	request := new(D.Msg)
	request.SetQuestion("example.com.", D.TypeA)
	_, err := client.ExchangeContext(t.Context(), request)
	require.Error(t, err)
	_, err = client.ExchangeContext(t.Context(), request)
	require.Error(t, err)
	require.EqualValues(t, 1, calls.Load(), "old node should not be probed repeatedly")
	require.Empty(t, public.calls, "fake IP warmup must not resolve real addresses publicly")
	answer, err := client.ExchangeContext(t.Context(), httpsQuery("example.com"))
	require.NoError(t, err)
	require.Len(t, answer.Answer, 1)
	require.EqualValues(t, 2, calls.Load())
}

func TestFakeIPv6UsesBundleTTLWhenServerOnlyHasIPv4(t *testing.T) {
	client, _, _ := testBundleClient(t)
	pool := newTestFakeIPPool(t, "2001:2::/64")
	handler := withFakeIP(&fakeip.Skipper{}, nil, pool, 60, &Resolver{domainClient: client})(nil)
	request := new(D.Msg)
	request.SetQuestion("example.com.", D.TypeAAAA)
	answer, err := handler(icontext.NewDNSContext(t.Context()), request)
	require.NoError(t, err)
	require.Len(t, answer.Answer, 1)
	require.Equal(t, uint32(20), answer.Answer[0].Header().Ttl)
	require.Empty(t, answer.Extra)
}

// directOnlyClient records what the `direct-nameserver` list is asked.
type directOnlyClient struct {
	calls    []uint16
	request  *D.Msg
	response *D.Msg
}

func (c *directOnlyClient) ExchangeContext(_ context.Context, request *D.Msg) (*D.Msg, error) {
	c.calls = append(c.calls, request.Question[0].Qtype)
	c.request = request.Copy()
	response := c.response.Copy()
	response.SetReply(request)
	response.Answer = c.response.Answer
	return response, nil
}

func localNodeClient(t *testing.T, direct directExchanger) (*domainClient, *recordingServiceClient) {
	t.Helper()
	public := &recordingServiceClient{response: &D.Msg{}}
	client := newDomainClient(public, direct, 10)
	client.prepare = func(host string) (string, func(context.Context) (net.Conn, error), error) {
		return "DIRECT", nil, fmt.Errorf("%w: DIRECT", tunnel.ErrTunnelDNSDirectNode)
	}
	return client, public
}

func TestLocalDomainServiceQueryUsesDirectNameServer(t *testing.T) {
	direct := &directOnlyClient{response: &D.Msg{Answer: []D.RR{testServiceRecord(D.TypeHTTPS, "example.cn.")}}}
	client, public := localNodeClient(t, direct)

	answer, err := client.ExchangeContext(t.Context(), httpsQuery("example.cn"))
	require.NoError(t, err)
	require.Contains(t, serviceRecordValues(answer.Answer[0]), D.SVCB_ECHCONFIG)
	require.Equal(t, []uint16{D.TypeHTTPS}, direct.calls)
	require.Empty(t, public.calls, "a direct domain must not be asked of a public resolver through a proxy")

	// An address query still fails so the caller allocates a fake IP locally,
	// exactly as before, and still asks nobody.
	request := new(D.Msg)
	request.SetQuestion("example.cn.", D.TypeA)
	_, err = client.ExchangeContext(t.Context(), request)
	require.ErrorIs(t, err, tunnel.ErrTunnelDNSUnsupported)
	require.Equal(t, []uint16{D.TypeHTTPS}, direct.calls)
	require.Empty(t, public.calls)
}

func TestLocalDomainServiceQueryDropsBundleOption(t *testing.T) {
	direct := &directOnlyClient{response: &D.Msg{}}
	client, _ := localNodeClient(t, direct)
	request := httpsQuery("example.cn")
	request.SetEdns0(1232, false)
	request.IsEdns0().Option = append(request.IsEdns0().Option, &D.EDNS0_LOCAL{Code: domainBundleOption, Data: []byte{1}})

	_, err := client.ExchangeContext(t.Context(), request)
	require.NoError(t, err)
	require.NotNil(t, request.IsEdns0(), "the caller's own message must not be modified")
	require.Len(t, request.IsEdns0().Option, 1)
	require.NotNil(t, direct.request.IsEdns0())
	require.Empty(t, direct.request.IsEdns0().Option, "the direct nameserver must not receive the tunnel-only option")
}

func TestLocalDomainWithoutDirectNameServerFallsThrough(t *testing.T) {
	client, public := localNodeClient(t, nil)
	_, err := client.ExchangeContext(t.Context(), httpsQuery("example.cn"))
	require.ErrorIs(t, err, ErrNoDirectNameServer)
	require.Empty(t, public.calls)

	// withFakeIP turns that into the ordinary resolution path, which is local
	// too, rather than into a public query carried by a proxy.
	fallbacks := 0
	pool := newTestFakeIPPool(t, "198.18.0.0/16")
	handler := withFakeIP(&fakeip.Skipper{}, pool, nil, 60, &Resolver{domainClient: client})(func(_ *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
		fallbacks++
		response := new(D.Msg)
		response.SetReply(r)
		response.Answer = []D.RR{testServiceRecord(D.TypeHTTPS, "example.cn.")}
		return response, nil
	})
	answer, err := handler(icontext.NewDNSContext(t.Context()), httpsQuery("example.cn"))
	require.NoError(t, err)
	require.Equal(t, 1, fallbacks)
	require.NotEmpty(t, answer.Answer)
	require.Empty(t, public.calls)
}

func TestProxiedNodeThatCannotAnswerStillUsesPublicResolver(t *testing.T) {
	direct := &directOnlyClient{response: &D.Msg{}}
	public := &recordingServiceClient{response: &D.Msg{}}
	client := newDomainClient(public, direct, 10)
	client.prepare = func(string) (string, func(context.Context) (net.Conn, error), error) {
		return "JP", nil, fmt.Errorf("%w: JP did not answer recently", tunnel.ErrTunnelDNSUnsupported)
	}
	_, err := client.ExchangeContext(t.Context(), httpsQuery("example.com"))
	require.NoError(t, err)
	require.Equal(t, []uint16{D.TypeHTTPS}, public.calls)
	require.Empty(t, direct.calls, "only a local leaf belongs on the direct nameserver")
}

func TestRejectedDomainServiceQueryIsAnsweredLocally(t *testing.T) {
	direct := &directOnlyClient{response: &D.Msg{}}
	public := &recordingServiceClient{response: &D.Msg{}}
	client := newDomainClient(public, direct, 10)
	client.prepare = func(string) (string, func(context.Context) (net.Conn, error), error) {
		return "REJECT-DROP", nil, fmt.Errorf("%w: REJECT-DROP", tunnel.ErrTunnelDNSNoServerNode)
	}

	request := httpsQuery("ads.example")
	answer, err := client.ExchangeContext(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, D.RcodeSuccess, answer.Rcode)
	require.Empty(t, answer.Answer)
	require.Equal(t, request.Id, answer.Id)
	require.Equal(t, request.Question, answer.Question)
	require.Empty(t, public.calls, "nothing ever connects through a rejecting leaf")
	require.Empty(t, direct.calls, "and its records are not worth a local query either")

	// Address queries keep failing so fake IP is still allocated locally.
	address := new(D.Msg)
	address.SetQuestion("ads.example.", D.TypeA)
	_, err = client.ExchangeContext(t.Context(), address)
	require.ErrorIs(t, err, tunnel.ErrTunnelDNSUnsupported)
	require.Empty(t, public.calls)
	require.Empty(t, direct.calls)
}
