package packet

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

// Exercise Sing's real callback-backed waiter without timing a network socket.
type callbackBenchmarkConn struct {
	SingPacketConn
	payload []byte
	address netip.AddrPort
}

func (c *callbackBenchmarkConn) ReadFromUDPAddrPortWithBuffer(buffer func(int) []byte) (int, netip.AddrPort, error) {
	return copy(buffer(len(c.payload)), c.payload), c.address, nil
}

func BenchmarkSingPacketReadCallback(b *testing.B) {
	source := &callbackBenchmarkConn{payload: make([]byte, 1200), address: netip.MustParseAddrPort("192.0.2.1:443")}
	reader := newEnhanceSingPacketConn(source)
	benchmarkPacketReadLatency(b, func() {
		data, put, _, err := reader.WaitReadFrom()
		if err != nil || len(data) != len(source.payload) || put == nil {
			b.Fatal("unexpected packet", len(data), err)
		}
		put()
	})
}

func benchmarkPacketReadLatency(b *testing.B, operation func()) {
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
