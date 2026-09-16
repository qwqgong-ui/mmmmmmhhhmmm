package self_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	quicproxy "github.com/metacubex/quic-go/integrationtests/tools/proxy"
	"github.com/metacubex/quic-go/qlog"
	"github.com/metacubex/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

// Exercise the real handshake / packet sender, not just the discovery state
// machine. The third connection sees a smaller path with the old hint cached.
func TestPathMTUCacheReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ln, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{
		DisablePathMTUDiscovery: true,
	}))
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				str, err := conn.AcceptUniStream(ctx)
				if err == nil {
					_, _ = io.Copy(io.Discard, str)
				}
			}()
		}
	}()
	var limit atomic.Int64
	limit.Store(1500)
	var dropped atomic.Int64
	proxy := &quicproxy.Proxy{
		Conn:       newUDPConnLocalhost(t),
		ServerAddr: ln.Addr().(*net.UDPAddr),
		DropPacket: func(dir quicproxy.Direction, _, _ net.Addr, packet []byte) bool {
			if dir == quicproxy.DirectionIncoming && int64(len(packet)) > limit.Load() {
				dropped.Add(1)
				return true
			}
			return false
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	cache := new(quic.MTUDiscoveryCache)
	run := func(warm bool, ceiling int) int {
		tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
		defer tr.Close()
		var recorder events.Recorder
		conn, err := tr.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
			MTUDiscoveryCache: cache,
			Tracer:            newTracer(&recorder),
		}))
		require.NoError(t, err)
		defer conn.CloseWithError(0, "")
		str, err := conn.OpenUniStream()
		require.NoError(t, err)
		require.NoError(t, str.SetWriteDeadline(time.Now().Add(10*time.Second)))
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					if _, err := str.Write(make([]byte, 4096)); err != nil {
						return
					}
				}
			}
		}()
		defer func() { close(stop); str.CancelWrite(0); <-done }()
		require.Eventually(t, func() bool {
			evs := recorder.Events(qlog.MTUUpdated{})
			if len(evs) == 0 {
				return false
			}
			last := evs[len(evs)-1].(qlog.MTUUpdated)
			if ceiling > 0 {
				return last.Value >= ceiling-21 && last.Value <= ceiling
			}
			return last.Done
		}, 10*time.Second, 5*time.Millisecond)
		evs := recorder.Events(qlog.MTUUpdated{})
		if warm {
			require.Len(t, evs, 1, "warm connection should skip the binary search")
		}
		last := evs[len(evs)-1].(qlog.MTUUpdated).Value
		t.Logf("warm=%t pathLimit=%d MTU=%d acknowledgedProbes=%d", warm, limit.Load(), last, len(evs))
		return last
	}
	first := run(false, 0)
	require.Equal(t, first, run(true, 0))
	limit.Store(1350)
	require.LessOrEqual(t, run(false, 1350), 1350)
	require.Positive(t, dropped.Load(), "cached probe must encounter the smaller path")
}
