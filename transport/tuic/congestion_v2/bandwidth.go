package congestion

import (
	"math"
	"time"

	"github.com/metacubex/quic-go/congestion"
)

const (
	infBandwidth = Bandwidth(math.MaxUint64)
)

// Bandwidth of a connection
type Bandwidth uint64

const (
	// BitsPerSecond is 1 bit per second
	BitsPerSecond Bandwidth = 1
	// BytesPerSecond is 1 byte per second
	BytesPerSecond = 8 * BitsPerSecond
)

// BandwidthFromDelta calculates the bandwidth from a number of bytes and a time delta
func BandwidthFromDelta(bytes congestion.ByteCount, delta time.Duration) Bandwidth {
	if bytes <= 0 {
		return 0
	}
	if delta <= 0 {
		return infBandwidth
	}
	return Bandwidth(MulDiv(uint64(bytes), uint64(time.Second)*uint64(BytesPerSecond), uint64(delta)))
}
