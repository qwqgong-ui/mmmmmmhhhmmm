package log

import (
	"sync"
	"testing"
)

func TestDebugSubscriberIndependentOfConsole(t *testing.T) {
	old := Level()
	SetLevel(INFO)
	defer SetLevel(old)
	sub := SubscribeLevel(DEBUG)
	defer UnSubscribe(sub)
	if !Enabled(DEBUG) {
		t.Fatal("subscriber must enable debug")
	}
	Fields(DEBUG, map[string]string{"subsystem": "dns"}, "decision %d", 1)
	select {
	case e := <-sub:
		if e.Payload != "decision 1" || e.Fields["subsystem"] != "dns" {
			t.Fatal(e)
		}
	default:
		t.Fatal("debug event missing")
	}
}

func TestSlowSubscriberDoesNotBlockAndUnsubscribeIsSafe(t *testing.T) {
	old := Level()
	SetLevel(SILENT)
	defer SetLevel(old)
	sub := Subscribe()
	before := DroppedEvents()
	for range 1000 {
		Debugln("event")
	}
	if DroppedEvents() <= before {
		t.Fatal("expected bounded queue drops")
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			SetLevel(SILENT)
			Debugln("event")
		}
	})
	wg.Go(func() {
		for range 1000 {
			s := SubscribeLevel(INFO)
			UnSubscribe(s)
			UnSubscribe(s)
		}
	})
	UnSubscribe(sub)
	wg.Wait()
	if Enabled(DEBUG) {
		t.Fatal("unsubscribed debug demand leaked")
	}
}

func TestDisabledDebugDoesNotFormatOrAllocate(t *testing.T) {
	old := Level()
	SetLevel(INFO)
	defer SetLevel(old)
	if n := testing.AllocsPerRun(100, func() {
		Debugln("constant")
		if Enabled(DEBUG) {
			Fields(DEBUG, map[string]string{"host": "example.test"}, "message")
		}
	}); n != 0 {
		t.Fatalf("disabled allocations=%v", n)
	}
}

func BenchmarkDisabledDebug(b *testing.B) {
	old := Level()
	SetLevel(INFO)
	defer SetLevel(old)
	b.ReportAllocs()
	for b.Loop() {
		Debugln("constant")
		if Enabled(DEBUG) {
			Fields(DEBUG, map[string]string{"subsystem": "dns"}, "unused")
		}
	}
}
