package tunnel

import (
	"slices"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

func benchmarkTunnelLatency(b *testing.B, operation func()) {
	samples := make([]int64, 0, min(b.N, 100000))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		start := time.Now()
		operation()
		elapsed := time.Since(start).Nanoseconds()
		if len(samples) < cap(samples) {
			samples = append(samples, elapsed)
		}
	}
	b.StopTimer()
	var total int64
	for _, elapsed := range samples {
		total += elapsed
	}
	slices.Sort(samples)
	b.ReportMetric(float64(total)/float64(len(samples)), "avg-ns")
	b.ReportMetric(float64(samples[(len(samples)*99+99)/100-1]), "p99-ns")
	b.ReportMetric(float64(samples[len(samples)-1]), "p100-ns")
	b.ReportMetric(float64(len(samples)), "samples")
}

// Include both prepared-target lookups used before the socket WriteTo, while
// keeping the socket itself in memory so network timing cannot mask the work.
func BenchmarkPreparedUDP(b *testing.B) {
	for _, destination := range []struct{ name, ip, host string }{
		{"IPv4", "192.0.2.1", ""},
		{"IPv6", "2001:db8::1", ""},
		{"FQDN", "", "example.com"},
	} {
		b.Run(destination.name, func(b *testing.B) {
			sender := newPacketSender().(*packetSender)
			defer sender.Close()
			metadata := udpMetadata(destination.ip, destination.host, 443)
			sender.AddMapping(metadata, metadata)
			packet := C.NewPacketAdapter(&mappingTestPacket{data: []byte("payload")}, metadata)
			conn := &recordingPacketConn{}
			benchmarkTunnelLatency(b, func() {
				sender.mappingMutex.RLock()
				prepared := sender.preparedTargets[udpPacketKey(metadata)].IsValid()
				sender.mappingMutex.RUnlock()
				if !prepared {
					b.Fatal("prepared target missing")
				}
				sender.processPacket(conn, packet)
			})
		})
	}
}

func BenchmarkConnectionLogDisabled(b *testing.B) {
	previous := log.Level()
	log.SetLevel(log.WARNING)
	defer log.SetLevel(previous)
	metadata := udpMetadata("192.0.2.1", "example.com", 443)
	metadata.SrcIP = metadata.DstIP
	metadata.SrcPort = 12345
	metadata.Process = "browser"
	chains := C.Chain{"node", "group"}
	benchmarkTunnelLatency(b, func() { logMetadata(metadata, nil, chains) })
}

func BenchmarkTunnelDNSMatchTarget(b *testing.B) {
	for _, host := range []string{"example.com", "192.0.2.1", "2001:db8::1"} {
		b.Run(host, func(b *testing.B) {
			benchmarkTunnelLatency(b, func() {
				metadata, err := tunnelDNSMatchTarget(host)
				if err != nil || metadata.DstPort != 443 {
					b.Fatalf("unexpected DNS target: %v, %v", metadata, err)
				}
			})
		})
	}
}
