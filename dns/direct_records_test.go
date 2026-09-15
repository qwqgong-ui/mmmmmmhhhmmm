package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestFakeIPDirectRecordsUseOnlyDirectNameServer(t *testing.T) {
	records := map[uint16]string{
		D.TypeTXT:   `example.cn. 60 IN TXT "direct answer"`,
		D.TypeMX:    "example.cn. 60 IN MX 10 mail.example.cn.",
		D.TypeNS:    "example.cn. 60 IN NS ns.example.cn.",
		D.TypeSOA:   "example.cn. 60 IN SOA ns.example.cn. hostmaster.example.cn. 1 60 60 60 60",
		D.TypeSRV:   "example.cn. 60 IN SRV 0 1 443 service.example.cn.",
		D.TypeCAA:   `example.cn. 60 IN CAA 0 issue "ca.example"`,
		D.TypeCNAME: "example.cn. 60 IN CNAME target.example.cn.",
		D.TypeHTTPS: "example.cn. 60 IN HTTPS 1 . alpn=h2 ipv4hint=192.0.2.50",
		D.TypeSVCB:  "example.cn. 60 IN SVCB 1 . alpn=h2 ipv4hint=192.0.2.50",
	}
	for qtype, record := range records {
		for _, skipped := range []bool{false, true} {
			for _, outcome := range []string{"success", "failure", "missing"} {
				t.Run(fmt.Sprintf("%s/real-ip=%t/%s", D.TypeToString[qtype], skipped, outcome), func(t *testing.T) {
					rr, err := D.NewRR(record)
					require.NoError(t, err)
					direct := &directOnlyClient{response: &D.Msg{Answer: []D.RR{rr}}}
					var expectedErr error
					var upstream directExchanger = direct
					switch outcome {
					case "failure":
						expectedErr = errors.New("direct upstream unavailable")
						direct.err = expectedErr
					case "missing":
						expectedErr = ErrNoDirectNameServer
						upstream = nil
					}
					client, public := localNodeClient(t, upstream)
					skipper := &fakeip.Skipper{}
					if skipped {
						skipper.Mode = C.FilterWhiteList
					}
					pool := newTestFakeIPPool(t, "198.18.0.0/16")
					h := withFakeIP(skipper, pool, nil, 60, &Resolver{domainClient: client})(func(*icontext.DNSContext, *D.Msg) (*D.Msg, error) {
						t.Fatal("DIRECT record reached ordinary nameserver")
						return nil, nil
					})
					request := new(D.Msg).SetQuestion("example.cn.", qtype)
					answer, err := h(icontext.NewDNSContext(t.Context()), request)
					require.Empty(t, public.calls)
					if outcome != "missing" {
						require.Equal(t, []uint16{qtype}, direct.calls)
					}
					if expectedErr != nil {
						require.ErrorIs(t, err, expectedErr)
						require.Nil(t, answer)
						return
					}
					require.NoError(t, err)
					require.Equal(t, request.Question, answer.Question)
					require.Equal(t, request.Id, answer.Id)
					require.Len(t, answer.Answer, 1)
					if !skipped && (qtype == D.TypeHTTPS || qtype == D.TypeSVCB) {
						hints := serviceRecordValues(answer.Answer[0])[D.SVCB_IPV4HINT].(*D.SVCBIPv4Hint)
						require.Equal(t, "198.18.0.4", hints.Hint[0].String())
					} else {
						require.Equal(t, rr.String(), answer.Answer[0].String())
					}
				})
			}
		}
	}
}

func TestFakeIPNonDirectRecordsKeepExistingResolvers(t *testing.T) {
	for _, qtype := range []uint16{D.TypeTXT, D.TypeMX, D.TypeHTTPS, D.TypeSVCB} {
		for _, skipped := range []bool{false, true} {
			for _, rejected := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/real-ip=%t/reject=%t", D.TypeToString[qtype], skipped, rejected), func(t *testing.T) {
					direct := &directOnlyClient{response: &D.Msg{}}
					public := &recordingServiceClient{response: &D.Msg{}}
					client := newDomainClient(public, direct, 10)
					client.prepare = func(string) (string, func(context.Context) (net.Conn, error), error) {
						if rejected {
							return "REJECT", nil, tunnel.ErrTunnelDNSNoServerNode
						}
						return "proxy", nil, tunnel.ErrTunnelDNSUnsupported
					}
					skipper := &fakeip.Skipper{}
					if skipped {
						skipper.Mode = C.FilterWhiteList
					}
					fallbacks := 0
					h := withFakeIP(skipper, nil, nil, 60, &Resolver{domainClient: client})(func(_ *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
						fallbacks++
						return new(D.Msg).SetReply(r), nil
					})
					_, err := h(icontext.NewDNSContext(t.Context()), new(D.Msg).SetQuestion("example.com.", qtype))
					require.NoError(t, err)
					require.Empty(t, direct.calls)
					if skipped || qtype == D.TypeTXT || qtype == D.TypeMX {
						require.Equal(t, 1, fallbacks)
						require.Empty(t, public.calls)
					} else {
						require.Zero(t, fallbacks)
						if rejected {
							require.Empty(t, public.calls)
						} else {
							require.Equal(t, []uint16{qtype}, public.calls)
						}
					}
				})
			}
		}
	}
}
