package outboundgroup

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type blockingHealthProvider struct {
	P.ProxyProvider
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (p *blockingHealthProvider) HealthCheck() {
	if p.calls.Add(1) == 1 {
		close(p.started)
	}
	<-p.release
}

func TestGroupFailureWindowAndSuccessReset(t *testing.T) {
	g := NewGroupBase(GroupBaseOption{Name: "test", MaxFailedTimes: 2, TestTimeout: 100})
	now := time.Now()
	if g.recordDialFailure(now) || !g.recordDialFailure(now.Add(time.Millisecond)) {
		t.Fatal("health check should trigger at the failure threshold")
	}
	g.onDialSuccess()
	if g.recordDialFailure(now.Add(2 * time.Millisecond)) {
		t.Fatal("a successful dial must reset the failure count")
	}
	if g.recordDialFailure(now.Add(time.Second)) || !g.recordDialFailure(now.Add(time.Second+time.Millisecond)) {
		t.Fatal("the new failure window must count its first failure")
	}
}

func TestGroupFailureCallbackRunsWithoutCounterLock(t *testing.T) {
	g := NewGroupBase(GroupBaseOption{Name: "test", MaxFailedTimes: 1})
	done := make(chan struct{})
	g.onDialFailed(C.Vless, errors.New("connection reset by peer"), func() {
		g.onDialSuccess()
		close(done)
	})
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("failure callback deadlocked while resetting the counter")
	}
}

func TestGroupConcurrentFailureSuccessAndHealthCheck(t *testing.T) {
	p := &blockingHealthProvider{started: make(chan struct{}), release: make(chan struct{})}
	g := NewGroupBase(GroupBaseOption{Name: "test", Providers: []P.ProxyProvider{p}, MaxFailedTimes: 2})
	done := make(chan struct{})
	go func() { g.healthCheck(); close(done) }()
	select {
	case <-p.started:
	case <-time.After(3 * time.Second):
		close(p.release)
		t.Fatal("health check did not start")
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				if g.recordDialFailure(time.Now()) {
					t.Error("failure during an active check triggered another check")
				}
				g.onDialSuccess()
				g.healthCheck()
			}
		})
	}
	wg.Wait()
	if p.calls.Load() != 1 {
		t.Errorf("provider checked %d times, want 1", p.calls.Load())
	}
	close(p.release)
	<-done
	if g.failedTimes != 0 || g.failedTesting.Load() {
		t.Fatal("completed health check did not reset state")
	}
	for range 16 {
		wg.Go(func() {
			for range 100 {
				g.recordDialFailure(time.Now())
				g.onDialSuccess()
			}
		})
	}
	wg.Wait()
}
