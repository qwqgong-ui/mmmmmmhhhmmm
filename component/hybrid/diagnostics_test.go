package hybrid

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDiagnosticRecoverableFallbackDoesNotLatch(t *testing.T) {
	before := Stats()
	d := newFlowDiagnostic("recover.test:443", "node", "scope")
	defer d.close()
	d.update("tunnel", "203.0.113.1:443", "", false, false)
	d.update("probing", "", "", true, false)
	d.update("raw", "", "", false, false)

	// A recoverable fallback names its reason and leaves the flow free to
	// probe its way back, which clears the reason again.
	d.update("tunnel", "", "raw_idle", false, false)
	got := FlowSnapshotsFor("recover.test", "443", "node")
	if len(got) != 1 || got[0].State != "tunnel" || got[0].Reason != "raw_idle" || got[0].Permanent {
		t.Fatalf("flows=%+v", got)
	}
	d.update("probing", "", "", true, false)
	d.update("raw", "", "", false, false)
	if got = FlowSnapshotsFor("recover.test", "443", "node"); len(got) != 1 || got[0].State != "raw" || got[0].Reason != "" {
		t.Fatalf("flow did not recover: %+v", got)
	}
	if after := Stats(); after.RawSuccesses != before.RawSuccesses+1 {
		t.Fatalf("a recovery counted as a second success: %d -> %d", before.RawSuccesses, after.RawSuccesses)
	}
}

func TestDiagnosticPermanentFallbackIsLatchedAndCountedOnce(t *testing.T) {
	before := Stats()
	d := newFlowDiagnostic("diag.test:443", "node", "scope")
	defer d.close()
	d.update("tunnel", "203.0.113.1:443", "", false, false)
	d.update("probing", "", "", true, false)
	d.update("raw", "", "", false, false)
	d.update("probing", "", "", true, false)
	if got := FlowSnapshotsFor("diag.test", "443", "node"); len(got) != 1 || got[0].State != "raw" {
		t.Fatalf("flows=%+v", got)
	}
	d.update("tunnel", "", "probe_timeout", false, true)
	d.update("tunnel", "", "peer_disabled_raw", false, true)
	d.update("raw", "", "", false, false)
	got := FlowSnapshotsFor("diag.test", "443", "node")
	if len(got) != 1 || got[0].State != "tunnel" || got[0].Reason != "probe_timeout" || !got[0].Permanent {
		t.Fatalf("flows=%+v", got)
	}
	after := Stats()
	if after.Fallbacks["probe_timeout"] != before.Fallbacks["probe_timeout"]+1 || after.Fallbacks["peer_disabled_raw"] != before.Fallbacks["peer_disabled_raw"] {
		t.Fatalf("counts=%+v before=%+v", after, before)
	}
	d.close()
	d.update("raw", "", "socket_read_error", false, false)
	if got := FlowSnapshotsFor("diag.test", "", ""); len(got) != 0 {
		t.Fatalf("closed flow resurrected: %+v", got)
	}
}

func TestDiagnosticActivityAndConcurrentClose(t *testing.T) {
	d := newFlowDiagnostic("activity.test:443", "", "")
	d.touch(time.Now().Add(-time.Hour))
	if got := FlowSnapshotsFor("activity.test", "", ""); got[0].IdleMillis < 3500000 {
		t.Fatal(got)
	}
	d.touch(time.Now())
	if got := FlowSnapshotsFor("activity.test", "", ""); got[0].IdleMillis > 1000 {
		t.Fatal(got)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				d.touch(time.Now())
				d.update("probing", "", "", true, false)
				FlowSnapshots()
			}
		})
	}
	d.close()
	wg.Wait()
	if got := FlowSnapshotsFor("activity.test", "", ""); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestDiagnosticRegistrationFailureRemoved(t *testing.T) {
	c := NewPacketConn(ClientOptions{Dial: func(context.Context) (net.Conn, error) { return nil, errors.New("test dial failure") }})
	defer c.Close()
	d := newFlowDiagnostic("failed.test:443", "", "")
	f := &clientFlow{owner: c, ready: make(chan struct{}), done: make(chan struct{}), diagnostic: d}
	f.open("failed.test:443")
	if f.err == nil {
		t.Fatal("expected failure")
	}
	if got := FlowSnapshotsFor("failed.test", "", ""); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestDiagnosticStreamCloseRemoved(t *testing.T) {
	client, server := net.Pipe()
	c := NewPacketConn(ClientOptions{})
	defer c.Close()
	d := newFlowDiagnostic("closed.test:443", "", "")
	f := &clientFlow{owner: c, stream: client, done: make(chan struct{}), diagnostic: d}
	go f.readStream()
	server.Close()
	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("reader did not close")
	}
	d.update("tunnel", "", "socket_read_error", false, true)
	if got := FlowSnapshotsFor("closed.test", "", ""); len(got) != 0 {
		t.Fatal(got)
	}
}
