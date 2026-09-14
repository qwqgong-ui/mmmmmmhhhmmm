package log

import (
	"fmt"
	"maps"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	level           atomic.Int32
	subscriberLevel atomic.Int32
	subscribers     = struct {
		sync.Mutex
		entries map[observable.Subscription[Event]]logSubscriber
	}{entries: make(map[observable.Subscription[Event]]logSubscriber)}
	dropped atomic.Uint64
)

type logSubscriber struct {
	channel chan Event
	level   LogLevel
}

func init() {
	level.Store(int32(INFO))
	subscriberLevel.Store(int32(SILENT))
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
	Time     time.Time
	Fields   map[string]string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	Fields(INFO, nil, format, v...)
}

func Warnln(format string, v ...any) {
	Fields(WARNING, nil, format, v...)
}

func Errorln(format string, v ...any) {
	Fields(ERROR, nil, format, v...)
}

func Debugln(format string, v ...any) {
	Fields(DEBUG, nil, format, v...)
}

// Enabled includes subscriber demand. Callers should guard expensive DEBUG
// arguments with this check; Go evaluates arguments before entering Debugln.
func Enabled(l LogLevel) bool {
	return l < SILENT && (l >= Level() || l >= LogLevel(subscriberLevel.Load()))
}

// Fields emits a log event with machine-readable diagnostic context while
// retaining the traditional text payload for existing clients.
func Fields(logLevel LogLevel, fields map[string]string, format string, v ...any) {
	if !Enabled(logLevel) {
		return
	}
	event := newLog(logLevel, format, v...)
	if len(fields) != 0 {
		event.Fields = maps.Clone(fields)
	}
	if logLevel >= LogLevel(subscriberLevel.Load()) {
		subscribers.Lock()
		for _, sub := range subscribers.entries {
			if logLevel < sub.level {
				continue
			}
			owned := event
			if len(event.Fields) > 0 {
				owned.Fields = maps.Clone(event.Fields)
			}
			select {
			case sub.channel <- owned:
			default:
				dropped.Add(1)
			}
		}
		subscribers.Unlock()
	}
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	return SubscribeLevel(DEBUG)
}

// SubscribeLevel preserves independent controller/console levels. Slow
// subscribers lose events instead of blocking the networking goroutine.
func SubscribeLevel(l LogLevel) observable.Subscription[Event] {
	subscribers.Lock()
	defer subscribers.Unlock()
	ch := make(chan Event, 200)
	sub := observable.Subscription[Event](ch)
	subscribers.entries[sub] = logSubscriber{channel: ch, level: l}
	updateSubscriberLevelLocked()
	return sub
}

func updateSubscriberLevelLocked() {
	l := SILENT
	for _, sub := range subscribers.entries {
		l = min(l, sub.level)
	}
	subscriberLevel.Store(int32(l))
}

func DroppedEvents() uint64 { return dropped.Load() }

func UnSubscribe(sub observable.Subscription[Event]) {
	subscribers.Lock()
	defer subscribers.Unlock()
	if held, ok := subscribers.entries[sub]; ok {
		delete(subscribers.entries, sub)
		close(held.channel)
		updateSubscriberLevelLocked()
	}
}

func Level() LogLevel {
	return LogLevel(level.Load())
}

func SetLevel(newLevel LogLevel) {
	level.Store(int32(newLevel))
}

func print(data Event) {
	if data.LogLevel < Level() {
		return
	}

	var output interface {
		Infoln(...any)
		Warnln(...any)
		Errorln(...any)
		Debugln(...any)
	} = log.StandardLogger()
	if len(data.Fields) > 0 {
		fields := make(log.Fields, len(data.Fields))
		for k, v := range data.Fields {
			fields[k] = v
		}
		output = log.WithFields(fields)
	}
	switch data.LogLevel {
	case INFO:
		output.Infoln(data.Payload)
	case WARNING:
		output.Warnln(data.Payload)
	case ERROR:
		output.Errorln(data.Payload)
	case DEBUG:
		output.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
		Time:     time.Now(),
	}
}
