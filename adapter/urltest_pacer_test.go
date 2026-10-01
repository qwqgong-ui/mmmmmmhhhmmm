package adapter

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

func TestHealthCheckProbeStartIntervalRange(t *testing.T) {
	seen := map[time.Duration]struct{}{}
	for range 1000 {
		interval := randomHealthCheckProbeStartInterval()
		if interval < healthCheckProbeStartMin || interval > healthCheckProbeStartMax {
			t.Fatalf("probe interval %s is outside [%s, %s]", interval, healthCheckProbeStartMin, healthCheckProbeStartMax)
		}
		seen[interval] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatal("probe interval did not vary")
	}
}

func TestProbeStartPacerSpacesStarts(t *testing.T) {
	pacer := probeStartPacer{}
	var previous time.Time
	for range 3 {
		if err := pacer.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !previous.IsZero() && pacer.lastStart.Sub(previous) < healthCheckProbeStartMin {
			t.Fatal("probe start spacing fell below the configured minimum")
		}
		previous = pacer.lastStart
	}
}

type probeTestAdapter struct {
	C.ProxyAdapter
	starts chan<- time.Time
}

type probeTestConn struct {
	N.ExtendedConn
	C.Connection
}

func (p *probeTestAdapter) Name() string { return "test-probe" }

func (p *probeTestAdapter) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	p.starts <- time.Now()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err == nil {
			_, _ = io.WriteString(server, "HTTP/1.1 204 No Content\r\n\r\n")
		}
	}()
	return &probeTestConn{ExtendedConn: N.NewExtendedConn(client)}, nil
}

func TestManualURLTestsShareProbeStartSchedule(t *testing.T) {
	const count = 4
	starts := make(chan time.Time, count)
	var wg sync.WaitGroup
	for range count {
		p := NewProxy(&probeTestAdapter{starts: starts})
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := p.URLTest(ctx, "http://probe.test/", nil); err != nil {
				t.Errorf("URL test failed: %v", err)
			}
		})
	}
	wg.Wait()
	close(starts)
	var times []time.Time
	for started := range starts {
		times = append(times, started)
	}
	if len(times) != count {
		t.Fatalf("got %d probe starts, want %d", len(times), count)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	for i := 1; i < len(times); i++ {
		// Allow scheduler overhead between receiving a slot and entering DialContext.
		if gap := times[i].Sub(times[i-1]); gap < healthCheckProbeStartMin/2 {
			t.Errorf("manual probes started as a burst: gap=%s", gap)
		}
	}
}

func TestURLTestQueueCancellationPreservesHealth(t *testing.T) {
	p := NewProxy(&probeTestAdapter{starts: make(chan time.Time, 1)})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.URLTest(ctx, "http://probe.test/", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if !p.AliveForTestUrl("http://probe.test/") || len(p.DelayHistory()) != 0 {
		t.Fatal("a canceled queued test changed proxy health or history")
	}
}

func TestPreparedURLTestDoesNotWaitTwice(t *testing.T) {
	ctx, err := PrepareURLTest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareURLTest(ctx)
	if err != nil || again != ctx {
		t.Fatal("already paced probe did not reuse its start slot")
	}
}
