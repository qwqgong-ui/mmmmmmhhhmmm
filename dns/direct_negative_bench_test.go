package dns

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// Keep this benchmark compatible with the previous implementation so the same
// upstream workload can measure both versions. A/AAAA are queried separately,
// as they are by the progressive direct connector.
func BenchmarkDirectAddressFamilies(b *testing.B) {
	for _, ipv4Only := range []bool{true, false} {
		for _, cold := range []bool{true, false} {
			b.Run(fmt.Sprintf("ipv4Only=%t/cold=%t", ipv4Only, cold), func(b *testing.B) {
				var requests atomic.Int64
				create := func() *directResolver {
					upstream := func(address string) dnsClient {
						return &directCandidateClient{address: address, exchange: func(_ context.Context, q *D.Msg) (*D.Msg, error) {
							requests.Add(1)
							time.Sleep(time.Millisecond)
							if q.Question[0].Qtype == D.TypeA {
								return directAnswer(q, "192.0.2.1", 60), nil
							}
							if !ipv4Only {
								return directAnswer(q, "2001:db8::1", 60), nil
							}
							return new(D.Msg).SetReply(q), nil
						}}
					}
					return newDirectCandidateResolver(upstream("first"), upstream("second"))
				}
				lookup := func(r *directResolver) {
					for _, ipv6 := range []bool{false, true} {
						for range r.LookupIPCandidates(context.Background(), "benchmark.example", ipv6, "bench-network") {
						}
					}
				}
				r := create()
				if !cold {
					lookup(r)
				}
				requests.Store(0)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if cold {
						r = create()
					}
					lookup(r)
				}
				b.StopTimer()
				b.ReportMetric(float64(requests.Load())/float64(b.N), "upstream/op")
			})
		}
	}
}
