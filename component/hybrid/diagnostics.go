package hybrid

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

type FlowSnapshot struct {
	FlowID       string  `json:"flowId"`
	State        string  `json:"state"`
	Target       string  `json:"target"`
	Proxy        string  `json:"proxy,omitempty"`
	NetworkScope string  `json:"networkScope,omitempty"`
	RawEndpoint  string  `json:"rawEndpoint,omitempty"`
	IdleMillis   int64   `json:"idleMs"`
	ProbeCount   uint64  `json:"probeCount"`
	RawRTTMillis float64 `json:"rawRttMs,omitempty"`
	Reason       string  `json:"reason,omitempty"`
}

type StatsSnapshot struct {
	RegisteringFlows uint64            `json:"registeringFlows"`
	TunnelFlows      uint64            `json:"tunnelFlows"`
	ProbingFlows     uint64            `json:"probingFlows"`
	RawFlows         uint64            `json:"rawFlows"`
	FlowsStarted     uint64            `json:"flowsStarted"`
	ProbeFlows       uint64            `json:"probeFlows"`
	RawSuccesses     uint64            `json:"rawSuccesses"`
	SuccessRate      float64           `json:"successRate"`
	Fallbacks        map[string]uint64 `json:"fallbackReasons"`
}

// The registry only owns live flows. Per-packet activity updates touch a
// per-flow atomic, never the global registry or a second state machine.
type flowDiagnostic struct {
	mu sync.Mutex
	FlowSnapshot
	closed       bool
	firstProbe   time.Time
	lastActivity atomic.Int64
}

var diagnostics = struct {
	sync.RWMutex
	flows     map[string]*flowDiagnostic
	fallbacks map[string]uint64
}{flows: make(map[string]*flowDiagnostic), fallbacks: make(map[string]uint64)}
var nextFlowID atomic.Uint64
var rawSuccesses atomic.Uint64
var probeFlows atomic.Uint64

func newFlowDiagnostic(target, proxy, scope string) *flowDiagnostic {
	d := &flowDiagnostic{FlowSnapshot: FlowSnapshot{FlowID: fmt.Sprintf("hq-%x", nextFlowID.Add(1)), State: "registering", Target: target, Proxy: proxy, NetworkScope: scope}}
	d.touch(time.Now())
	diagnostics.Lock()
	diagnostics.flows[d.FlowID] = d
	diagnostics.Unlock()
	return d
}

func (d *flowDiagnostic) touch(now time.Time) { d.lastActivity.Store(now.UnixNano()) }

// Called only at transitions/probes, never on steady-state raw packets.
// Permanent fallback is latched: peer acknowledgements and late callbacks
// cannot change its reason, count twice, or resurrect a closed flow.
func (d *flowDiagnostic) update(state, endpoint, reason string, probe bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.Reason != "" {
		return
	}
	if endpoint != "" {
		d.RawEndpoint = endpoint
	}
	now := time.Now()
	if probe {
		if d.firstProbe.IsZero() {
			d.firstProbe = now
			probeFlows.Add(1)
		}
		d.ProbeCount++
	}
	old := d.State
	if state == "probing" && old == "raw" {
		state = "raw"
	}
	if state == "raw" && old != "raw" {
		rawSuccesses.Add(1)
		if !d.firstProbe.IsZero() {
			d.RawRTTMillis = float64(now.Sub(d.firstProbe)) / float64(time.Millisecond)
		}
	}
	if reason != "" {
		d.Reason = reason
		diagnostics.Lock()
		diagnostics.fallbacks[reason]++
		diagnostics.Unlock()
	}
	if state != "" {
		d.State = state
	}
	if (old != d.State && old != "registering") || reason != "" {
		host, _, _ := net.SplitHostPort(d.Target)
		log.Fields(log.INFO, map[string]string{"subsystem": "hybrid", "event": "state_transition", "flow_id": d.FlowID, "host": host, "proxy": d.Proxy, "network_scope": d.NetworkScope, "reason": reason, "from": old, "to": d.State}, "Hybrid QUIC %s: %s -> %s (%s)", d.FlowID, old, d.State, reason)
	}
	if probe && log.Enabled(log.DEBUG) {
		log.Fields(log.DEBUG, map[string]string{"subsystem": "hybrid", "event": "raw_probe", "flow_id": d.FlowID}, "Hybrid QUIC %s: raw probe #%d endpoint=%s", d.FlowID, d.ProbeCount, d.RawEndpoint)
	}
}

func (d *flowDiagnostic) close() {
	d.mu.Lock()
	d.closed = true
	diagnostics.Lock()
	delete(diagnostics.flows, d.FlowID)
	diagnostics.Unlock()
	d.mu.Unlock()
}

func FlowSnapshots() []FlowSnapshot { return FlowSnapshotsFor("", "", "") }

func FlowSnapshotsFor(host, port, proxy string) []FlowSnapshot {
	diagnostics.RLock()
	flows := make([]*flowDiagnostic, 0, len(diagnostics.flows))
	for _, d := range diagnostics.flows {
		flows = append(flows, d)
	}
	diagnostics.RUnlock()
	result := make([]FlowSnapshot, 0, len(flows))
	for _, d := range flows {
		d.mu.Lock()
		f, closed := d.FlowSnapshot, d.closed
		d.mu.Unlock()
		h, p, _ := net.SplitHostPort(f.Target)
		if closed || (host != "" && !strings.EqualFold(strings.TrimSuffix(h, "."), strings.TrimSuffix(host, "."))) || (port != "" && p != port) || (proxy != "" && f.Proxy != proxy) {
			continue
		}
		f.IdleMillis = max(0, (time.Now().UnixNano()-d.lastActivity.Load())/int64(time.Millisecond))
		result = append(result, f)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FlowID < result[j].FlowID })
	return result
}

func Stats() StatsSnapshot {
	s := StatsSnapshot{FlowsStarted: nextFlowID.Load(), ProbeFlows: probeFlows.Load(), RawSuccesses: rawSuccesses.Load(), Fallbacks: make(map[string]uint64)}
	if s.FlowsStarted > 0 {
		s.SuccessRate = float64(s.RawSuccesses) / float64(s.FlowsStarted)
	}
	for _, f := range FlowSnapshots() {
		switch f.State {
		case "raw":
			s.RawFlows++
		case "probing":
			s.ProbingFlows++
		case "registering":
			s.RegisteringFlows++
		case "tunnel":
			s.TunnelFlows++
		}
	}
	diagnostics.RLock()
	for k, v := range diagnostics.fallbacks {
		s.Fallbacks[k] = v
	}
	diagnostics.RUnlock()
	return s
}
