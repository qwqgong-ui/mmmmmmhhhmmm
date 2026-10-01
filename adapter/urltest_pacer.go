package adapter

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/randv2"
)

const (
	healthCheckProbeStartMin = 15 * time.Millisecond
	healthCheckProbeStartMax = 50 * time.Millisecond
)

type probeStartPacer struct {
	mu        sync.Mutex
	lastStart time.Time
}

// Every URL-test entry point shares the same start schedule. Probes may
// overlap while awaiting responses, but do not launch as one concurrent burst.
var urlTestProbePacer probeStartPacer

type urlTestPacedKey struct{}

func randomHealthCheckProbeStartInterval() time.Duration {
	const step = time.Millisecond
	steps := int((healthCheckProbeStartMax-healthCheckProbeStartMin)/step) + 1
	return healthCheckProbeStartMin + time.Duration(randv2.IntN(steps))*step
}

func (p *probeStartPacer) wait(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.lastStart.IsZero() {
		wait := randomHealthCheckProbeStartInterval() - time.Since(p.lastStart)
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	p.lastStart = time.Now()
	return nil
}

// PrepareURLTest waits for a shared probe-start slot. Providers call it before
// starting their per-probe timeout; URLTest also calls it for manual and group
// tests. The returned context prevents the same probe from waiting twice.
func PrepareURLTest(ctx context.Context) (context.Context, error) {
	if ctx.Value(urlTestPacedKey{}) != nil {
		return ctx, ctx.Err()
	}
	if err := urlTestProbePacer.wait(ctx); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, urlTestPacedKey{}, true), nil
}
