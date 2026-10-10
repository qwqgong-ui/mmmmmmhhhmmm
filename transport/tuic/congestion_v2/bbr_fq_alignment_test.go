package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/metacubex/quic-go/congestion"
	"github.com/metacubex/quic-go/monotime"
	"github.com/stretchr/testify/require"
)

func TestBBRPostSendFlightStartsAndRestartsSampler(t *testing.T) {
	b, _ := newECNTestSender()
	const size = congestion.ByteCount(1200)
	now := monotime.Now()
	b.OnPacketSent(now, size, 1, size, true)
	require.True(t, b.exitingQuiescence)
	state := b.sampler.connectionStateMap.GetEntry(1)
	require.Equal(t, size, state.sendTimeState.bytesInFlight)
	require.Equal(t, now, state.lastAckedPacketSentTime)
	b.OnCongestionEventEx(size, now.Add(20*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: size}}, nil)
	require.Positive(t, b.bandwidthEstimate())
	b.exitingQuiescence = false
	b.OnPacketSent(now.Add(time.Second), size, 2, size, true)
	require.True(t, b.exitingQuiescence)
	require.Equal(t, now.Add(time.Second), b.sampler.connectionStateMap.GetEntry(2).lastAckedPacketSentTime)
	b.exitingQuiescence = false
	b.OnPacketSent(now.Add(2*time.Second), 0, 3, 40, false)
	require.False(t, b.exitingQuiescence)
}

func TestBBRLossOnlyEventEntersAndExtendsRecovery(t *testing.T) {
	b, _ := newECNTestSender()
	b.isAtFullBandwidth = true
	now := monotime.Now()
	for i := congestion.PacketNumber(1); i <= 3; i++ {
		b.OnPacketSent(now, congestion.ByteCount(i)*1200, i, 1200, true)
	}
	b.OnCongestionEventEx(3600, now.Add(time.Second), nil, []congestion.LostPacketInfo{{PacketNumber: 1, BytesLost: 1200}})
	require.True(t, b.InRecovery())
	require.Equal(t, congestion.PacketNumber(3), b.endRecoveryAt)
	b.OnPacketSent(now.Add(2*time.Second), 3600, 4, 1200, true)
	b.OnCongestionEventEx(3600, now.Add(3*time.Second), nil, []congestion.LostPacketInfo{{PacketNumber: 2, BytesLost: 1200}})
	require.Equal(t, congestion.PacketNumber(4), b.endRecoveryAt)
	require.NotPanics(t, func() { b.OnCongestionEventEx(0, now, nil, nil) })
}

func TestBBREffectivePacingRatePreservesSlowLink(t *testing.T) {
	b, _ := newECNTestSender()
	b.pacingRate = 8_000
	require.Equal(t, uint64(1000), b.PacingRateBytesPerSecond())
	b.pacingRate = 1
	require.Equal(t, uint64(1), b.PacingRateBytesPerSecond())
}

func TestBBRSmallFlightACKIsNotApplicationLimited(t *testing.T) {
	b, _ := newECNTestSender()
	now := monotime.Now()
	b.OnPacketSent(now, 1200, 1, 1200, true)
	b.OnCongestionEventEx(1200, now.Add(20*time.Millisecond), []congestion.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1200}}, nil)
	require.False(t, b.sampler.IsAppLimited())
	b.OnAppLimited()
	require.True(t, b.sampler.IsAppLimited())
}

func TestBBRBandwidthArithmeticDoesNotOverflow(t *testing.T) {
	const bytes = congestion.ByteCount(1_000_000_000)
	require.Equal(t, Bandwidth(8_000_000_000), BandwidthFromDelta(bytes, time.Second))
	require.Equal(t, bytes, bytesFromBandwidthAndTimeDelta(8_000_000_000, time.Second))
	require.Equal(t, time.Second, timeDeltaFromBytesAndBandwidth(bytes, 8_000_000_000))
	require.Equal(t, congestion.ByteCount(math.MaxInt64), bytesFromBandwidthAndTimeDelta(infBandwidth, time.Hour))
	require.Equal(t, infBandwidth, BandwidthFromDelta(math.MaxInt64, time.Nanosecond))
}

func TestBBRMigrationResetsMTUAndPacer(t *testing.T) {
	b := NewBbrSender(1400, 20, ProfileAggressive)
	require.Equal(t, congestion.ByteCount(1400), b.pacer.maxDatagramSize)
	b.SetRTTStatsProvider(&ecnTestRTTStats{minRTT: 20 * time.Millisecond})
	b.SetMaxDatagramSize(1480)
	b.OnPathMigrationWithMTU(1200)
	require.Equal(t, congestion.ByteCount(1200), b.maxDatagramSize)
	require.Equal(t, congestion.ByteCount(20*1200), b.initialCongestionWindow)
	require.Equal(t, congestion.ByteCount(1200), b.pacer.maxDatagramSize)
	require.Zero(t, b.pacingRate)
	require.Equal(t, ProfileAggressive, b.profile)
}

func TestECNRestrictionsRespectRecoveryAndDrain(t *testing.T) {
	for _, mode := range []bbrMode{bbrModeDrain, bbrModeProbeRtt, bbrModeProbeBw} {
		for _, phase := range []ecnBBRPhase{ecnPhaseFreeze, ecnPhaseShrink} {
			b, _ := newECNTestSender()
			confirmZeroCE(b)
			b.OnECNFeedback(true, false, 15, 0, 1)
			if phase == ecnPhaseShrink {
				b.OnECNFeedback(true, false, 15, 0, 1)
			}
			b.mode = mode
			if mode == bbrModeProbeBw {
				b.recoveryState = bbrRecoveryStateConservation
			}
			b.pacingRate = testBandwidth / 10
			b.congestionWindow = b.minCongestionWindow
			b.applyECNPolicy(true, false)
			require.LessOrEqual(t, b.pacingRate, testBandwidth/10)
			require.Equal(t, b.minCongestionWindow, b.congestionWindow)
		}
	}
}

func TestPacerFutureTimeDoesNotCreateBudget(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 1200 })
	p.SetMaxDatagramSize(1200)
	now := monotime.Now()
	p.SentPacket(now.Add(time.Second), 12000)
	require.Zero(t, p.Budget(now))
	require.Zero(t, p.Budget(now.Add(time.Second)))
	require.Equal(t, congestion.ByteCount(1200), p.Budget(now.Add(2*time.Second)))
	require.Equal(t, now.Add(2*time.Second), p.TimeUntilSend())
}

func TestPacerLargeRateAndZeroRateDoNotOverflow(t *testing.T) {
	p := NewPacer(func() congestion.ByteCount { return 1_000_000_000 })
	now := monotime.Now()
	p.SentPacket(now, p.Budget(now))
	require.Equal(t, p.maxBurstSize(), p.Budget(now.Add(time.Hour)))
	require.Equal(t, uint64(math.MaxUint64), MulDiv(math.MaxUint64, math.MaxUint64, 1))
	zero := NewPacer(func() congestion.ByteCount { return 0 })
	zero.SentPacket(now, zero.Budget(now))
	require.True(t, zero.TimeUntilSend().After(now))
}
