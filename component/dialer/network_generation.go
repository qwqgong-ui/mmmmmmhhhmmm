package dialer

import "sync/atomic"

var networkGeneration atomic.Uint64

// NotifyNetworkChange invalidates connection hints tied to the physical path.
// It stores no proxy state; each leaf owns and replaces its own hint cache.
func NotifyNetworkChange() { networkGeneration.Add(1) }

func NetworkGeneration() uint64 { return networkGeneration.Load() }
