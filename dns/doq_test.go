package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/diagstats"
	"github.com/metacubex/quic-go"
	D "github.com/miekg/dns"
)

func TestDoQConcurrentReuseAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: pc}
	listener, err := transport.Listen(raceTestTLS(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	defer listener.Close()
	var connections atomic.Int32
	blocked := make(chan struct{}, 1)
	reset := make(chan error, 1)
	otherReady := make(chan struct{}, 1)
	otherRelease := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer conn.CloseWithError(0, "")
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						var size uint16
						if binary.Read(stream, binary.BigEndian, &size) != nil {
							return
						}
						buf := make([]byte, size)
						if _, err := io.ReadFull(stream, buf); err != nil {
							return
						}
						q := new(D.Msg)
						if q.Unpack(buf) != nil {
							return
						}
						if q.Question[0].Name == "blocked.test." {
							blocked <- struct{}{}
							<-stream.Context().Done()
							_, err := stream.Write([]byte{0, 1, 0})
							reset <- err
							return
						}
						if q.Question[0].Name == "other.test." {
							otherReady <- struct{}{}
							select {
							case <-otherRelease:
							case <-ctx.Done():
								return
							}
						}
						response := new(D.Msg)
						response.SetReply(q)
						buf, _ = response.Pack()
						_ = binary.Write(stream, binary.BigEndian, uint16(len(buf)))
						_, _ = stream.Write(buf)
						_ = stream.Close()
					}()
				}
			}()
		}
	}()
	client := newDoQ(pc.LocalAddr().String(), nil, map[string]string{"skip-cert-verify": "true"}, nil, "")
	defer client.Close()
	query := func(name string) *D.Msg { q := new(D.Msg); q.SetQuestion(name, D.TypeA); return q }
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			q := query("example.test.")
			m, err := client.ExchangeContext(ctx, q)
			if err != nil || m == nil || m.Id != q.Id {
				t.Errorf("concurrent query: %v %v", m, err)
			}
		})
	}
	wg.Wait()
	if connections.Load() != 1 {
		t.Fatalf("cold queries opened %d connections", connections.Load())
	}
	work, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	before := diagstats.Snapshot()["dns.upstream.error"]
	go func() { _, err := exchangeDiagnostic(work, client, query("blocked.test."), 1); done <- err }()
	select {
	case <-blocked:
	case <-ctx.Done():
		t.Fatal("query never reached server")
	}
	otherDone := make(chan error, 1)
	go func() { _, err := client.ExchangeContext(ctx, query("other.test.")); otherDone <- err }()
	select {
	case <-otherReady:
	case <-ctx.Done():
		t.Fatal("concurrent query never reached server")
	}
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("cancellation blocked")
	}
	select {
	case err := <-reset:
		var streamErr *quic.StreamError
		if !errors.As(err, &streamErr) || streamErr.ErrorCode != QUICCodeRequestCancelled {
			t.Fatalf("server did not see request cancellation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("server stream was not canceled")
	}
	close(otherRelease)
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("cancellation interrupted concurrent query")
	}
	if got := diagstats.Snapshot()["dns.upstream.error"]; got != before {
		t.Fatalf("cancellation counted as error: %d -> %d", before, got)
	}
	if _, err := client.ExchangeContext(ctx, query("after.test.")); err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 1 {
		t.Fatal("cancellation discarded shared connection")
	}
	old, err := client.getConnection(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := client.getConnection(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	client.closeConnIfCurrent(old, errors.New("late failure on old connection"))
	if current, err := client.getConnection(ctx, true); err != nil || current != replacement {
		t.Fatalf("old failure discarded replacement: %v", err)
	}
	if _, err := client.ExchangeContext(ctx, query("replacement.test.")); err != nil {
		t.Fatal(err)
	}
}

type diagnosticFailureClient struct{ err error }

func (c diagnosticFailureClient) Address() string  { return "test" }
func (c diagnosticFailureClient) ResetConnection() {}
func (c diagnosticFailureClient) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, c.err
}

func TestDNSDiagnosticCancellationAndRealFailures(t *testing.T) {
	q := new(D.Msg)
	q.SetQuestion("example.test.", D.TypeA)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	timedOut, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		err, want error
		count     uint64
	}{
		{"canceled stream deadline", canceled, context.DeadlineExceeded, context.Canceled, 0},
		{"actual context timeout", timedOut, io.ErrUnexpectedEOF, context.DeadlineExceeded, 1},
		{"transport timeout without cancellation", context.Background(), context.DeadlineExceeded, context.DeadlineExceeded, 1},
		{"actual transport failure", context.Background(), io.ErrUnexpectedEOF, io.ErrUnexpectedEOF, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := diagstats.Snapshot()["dns.upstream.error"]
			_, err := exchangeDiagnostic(tc.ctx, diagnosticFailureClient{tc.err}, q, 1)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if delta := diagstats.Snapshot()["dns.upstream.error"] - before; delta != tc.count {
				t.Fatalf("error count delta %d, want %d", delta, tc.count)
			}
		})
	}
	if err := normalizeDNSExchangeError(canceled, nil); err != nil {
		t.Fatal("successful response became cancellation")
	}
}
