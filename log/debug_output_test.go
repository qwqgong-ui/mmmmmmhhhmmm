package log

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type blockedDebugWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockedDebugWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func TestDebugConsoleCannotBlockProducerAndQueueIsBounded(t *testing.T) {
	oldLevel, oldOutput := Level(), logrus.StandardLogger().Out
	writer := &blockedDebugWriter{entered: make(chan struct{}), release: make(chan struct{})}
	logrus.SetOutput(writer)
	SetLevel(DEBUG)
	t.Cleanup(func() { SetLevel(SILENT); close(writer.release); logrus.SetOutput(oldOutput); SetLevel(oldLevel) })
	sub := SubscribeLevel(DEBUG)
	defer UnSubscribe(sub)
	Fields(DEBUG, map[string]string{"event": "first"}, "first")
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("console worker not started")
	}
	done := make(chan struct{})
	before := DroppedDebugOutput()
	start := time.Now()
	go func() {
		for range 1000 {
			Debugln("queued")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("producer blocked on console")
	}
	if DroppedDebugOutput() <= before {
		t.Fatal("full console queue did not count dropped events")
	}
	if e := <-sub; e.Fields["event"] != "first" {
		t.Fatal("subscription was delayed or corrupted")
	}
	t.Logf("1000 debug events with blocked console=%s dropped=%d", time.Since(start), DroppedDebugOutput()-before)
}

func TestDebugFieldsAreOwnedByEachSubscriber(t *testing.T) {
	old := Level()
	SetLevel(SILENT)
	defer SetLevel(old)
	a, b := Subscribe(), Subscribe()
	defer UnSubscribe(a)
	defer UnSubscribe(b)
	fields := map[string]string{"host": "original"}
	Fields(DEBUG, fields, "event")
	fields["host"] = "changed"
	first, second := <-a, <-b
	first.Fields["host"] = "subscriber changed"
	if second.Fields["host"] != "original" {
		t.Fatal(second.Fields)
	}
}

func BenchmarkDebugOutputEnqueue(b *testing.B) {
	oldLevel, oldOutput := Level(), logrus.StandardLogger().Out
	logrus.SetOutput(io.Discard)
	SetLevel(DEBUG)
	defer func() { SetLevel(oldLevel); logrus.SetOutput(oldOutput) }()
	b.ReportAllocs()
	for b.Loop() {
		Debugln("connection diagnostic")
	}
}
