// Package tunneldns remembers which proxy servers answer DNS on the reserved
// tunnel destination.
//
// The reserved destination is answered inside the proxy server, so a server
// that has not implemented it simply refuses the question or never accepts the
// connection at all. That costs one attempt to discover; repeating it for
// every query would turn a fallback into a tax. One answer per node is enough,
// and an unsupported verdict expires so a server that has since been upgraded
// is picked up again.
package tunneldns

import (
	"sort"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"
)

// UnsupportedTTL is how long a node that could not answer is left alone.
const UnsupportedTTL = 5 * time.Minute

// Registry records per node whether the reserved destination is served there.
type Registry struct {
	mu    sync.RWMutex
	nodes map[string]Capability
	now   func() time.Time
	kind  string
}

type Capability struct {
	Kind      string    `json:"capability"`
	Node      string    `json:"node"`
	State     string    `json:"state"`
	LastProbe time.Time `json:"lastProbe"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return NewRegistryFor("server_dns")
}

func NewRegistryFor(kind string) *Registry {
	return &Registry{nodes: make(map[string]Capability), now: time.Now, kind: kind}
}

var defaultRegistry = NewRegistry()

// Supported reports whether node is worth asking. A node that has never been
// tried is worth asking, so the answer for an unknown node is yes.
func (r *Registry) Supported(node string) bool {
	if node == "" {
		return true
	}
	r.mu.RLock()
	entry, known := r.nodes[node]
	r.mu.RUnlock()
	if !known || entry.State != "unsupported" {
		return true
	}
	if r.now().Before(entry.ExpiresAt) {
		return false
	}
	// The verdict has expired: forget it so the node is tried again.
	r.mu.Lock()
	if current, still := r.nodes[node]; still && current.State == "unsupported" && !r.now().Before(current.ExpiresAt) {
		current.State = "expired"
		r.nodes[node] = current
		log.Fields(log.INFO, map[string]string{"subsystem": "dns", "event": "server_capability_expired", "proxy": node, "capability": r.kind, "reason": "retry_after_ttl"}, "[DNS] %s capability expired for %s; testing again on demand", r.kind, node)
	}
	allowed := r.nodes[node].State != "unsupported"
	r.mu.Unlock()
	return allowed
}

// MarkSupported records that node answered.
func (r *Registry) MarkSupported(node string) {
	if node == "" {
		return
	}
	r.mark(node, "supported")
}

// MarkUnsupported records that node could not answer, for UnsupportedTTL.
func (r *Registry) MarkUnsupported(node string) {
	if node == "" {
		return
	}
	r.mark(node, "unsupported")
}

func (r *Registry) mark(node, state string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.nodes[node]
	entry := Capability{Kind: r.kind, Node: node, State: state, LastProbe: r.now()}
	if state == "unsupported" {
		entry.ExpiresAt = entry.LastProbe.Add(UnsupportedTTL)
	}
	r.nodes[node] = entry
	if old.State != state {
		log.Fields(log.INFO, map[string]string{"subsystem": "dns", "event": "server_capability_changed", "proxy": node, "capability": r.kind, "reason": state}, "[DNS] %s capability for %s: %s -> %s", r.kind, node, old.State, state)
	}
}

// Snapshot never expires a verdict as a side effect of reading diagnostics.
func (r *Registry) Snapshot() []Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Capability, 0, len(r.nodes))
	for _, entry := range r.nodes {
		if entry.State == "unsupported" && !r.now().Before(entry.ExpiresAt) {
			entry.State = "expired"
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Node < result[j].Node })
	return result
}

func Snapshot() []Capability { return defaultRegistry.Snapshot() }

// Reset forgets every verdict. Configuration reloads replace the proxy set, so
// what was learned about the old one no longer applies.
func (r *Registry) Reset() {
	r.mu.Lock()
	clear(r.nodes)
	r.mu.Unlock()
}

// Supported reports whether node is worth asking.
func Supported(node string) bool { return defaultRegistry.Supported(node) }

// MarkSupported records that node answered.
func MarkSupported(node string) { defaultRegistry.MarkSupported(node) }

// MarkUnsupported records that node could not answer, for UnsupportedTTL.
func MarkUnsupported(node string) { defaultRegistry.MarkUnsupported(node) }

// Reset forgets every verdict.
func Reset() { defaultRegistry.Reset() }
