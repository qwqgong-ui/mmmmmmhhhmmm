package dns

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// Use the same warm bundle workload before and after a cache-path change.
// Fixed iteration counts make the latency sample sizes comparable.
func BenchmarkDomainBundleCacheHit(b *testing.B) {
	for _, qtype := range []uint16{D.TypeA, D.TypeAAAA, D.TypeHTTPS} {
		for _, parallel := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/parallel=%t", D.TypeToString[qtype], parallel), func(b *testing.B) {
				client := newDomainClient(nil, nil, 16)
				client.prepare = func(string) (string, func(context.Context) (net.Conn, error), error) {
					return "bundle-benchmark", nil, nil
				}
				msg := &D.Msg{Answer: []D.RR{testServiceRecord(D.TypeHTTPS, "example.com.")}}
				for _, record := range []string{"example.com. 60 IN A 192.0.2.1", "example.com. 60 IN AAAA 2001:db8::1"} {
					rr, err := D.NewRR(record)
					if err != nil {
						b.Fatal(err)
					}
					msg.Extra = append(msg.Extra, rr)
				}
				msg.SetEdns0(1232, false)
				msg.IsEdns0().Option = []D.EDNS0{&D.EDNS0_LOCAL{Code: domainBundleOption, Data: []byte{1}}}
				client.cache.SetWithExpire(domainKey("bundle-benchmark", "example.com"), msg, time.Now().Add(time.Hour))
				request := new(D.Msg)
				request.SetQuestion("example.com.", qtype)
				operation := func() {
					response, err := client.ExchangeContext(context.Background(), request)
					if err != nil || response == nil || len(response.Answer) != 1 {
						b.Fatalf("unexpected cached response: %v, %v", response, err)
					}
				}
				workers := 1
				if parallel {
					workers = runtime.GOMAXPROCS(0)
				}
				samples := make([][]int64, workers)
				for i := range samples {
					samples[i] = make([]int64, 0, min(b.N, 100000))
				}
				var worker atomic.Int32
				b.ReportAllocs()
				b.ResetTimer()
				if parallel {
					b.RunParallel(func(pb *testing.PB) {
						i := int(worker.Add(1)) - 1
						local := samples[i]
						for pb.Next() {
							start := time.Now()
							operation()
							elapsed := time.Since(start).Nanoseconds()
							if len(local) < cap(local) {
								local = append(local, elapsed)
							}
						}
						samples[i] = local
					})
				} else {
					for range b.N {
						start := time.Now()
						operation()
						elapsed := time.Since(start).Nanoseconds()
						if len(samples[0]) < cap(samples[0]) {
							samples[0] = append(samples[0], elapsed)
						}
					}
				}
				b.StopTimer()
				var all []int64
				var total int64
				for _, sample := range samples {
					all = append(all, sample...)
					for _, elapsed := range sample {
						total += elapsed
					}
				}
				slices.Sort(all)
				b.ReportMetric(float64(total)/float64(len(all)), "avg-ns")
				b.ReportMetric(float64(all[(len(all)*99+99)/100-1]), "p99-ns")
				b.ReportMetric(float64(all[len(all)-1]), "p100-ns")
				b.ReportMetric(float64(len(all)), "samples")
			})
		}
	}
}
