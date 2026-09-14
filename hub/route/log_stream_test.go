package route

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/log"
)

func TestLogWebSocketIdleDisconnectReleasesDebugDemand(t *testing.T) {
	old := log.Level()
	log.SetLevel(log.SILENT)
	defer log.SetLevel(old)
	server := httptest.NewServer(http.HandlerFunc(getLogs))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, _, _, err := ws.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/logs?level=debug")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(time.Second)
	for !log.Enabled(log.DEBUG) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !log.Enabled(log.DEBUG) {
		t.Fatal("subscription not installed")
	}
	conn.Close() // no subsequent log event may be required to notice EOF
	for log.Enabled(log.DEBUG) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if log.Enabled(log.DEBUG) {
		t.Fatal("idle disconnect leaked DEBUG demand")
	}
}

func TestLogHTTPContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/logs", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() { getLogs(httptest.NewRecorder(), r); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled log stream stuck")
	}
}
