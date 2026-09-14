package dns

import (
	"sort"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/tunneldns"
	D "github.com/miekg/dns"
)

type BindingDiagnostic struct {
	Type      string   `json:"type"`
	Priority  uint16   `json:"priority"`
	Target    string   `json:"target"`
	ECH       bool     `json:"ech"`
	ALPN      []string `json:"alpn"`
	Mandatory []string `json:"mandatory"`
	IPv4Hint  []string `json:"ipv4Hint"`
	IPv6Hint  []string `json:"ipv6Hint"`
}

type MessageDiagnostic struct {
	Rcode             int                 `json:"rcode"`
	Addresses         []string            `json:"addresses"`
	Bindings          []BindingDiagnostic `json:"bindings"`
	AuthenticatedData bool                `json:"authenticatedData"`
	RRSIGPresent      bool                `json:"rrsigPresent"`
}

// InspectMessage reads immutable cached data and only returns owned slices.
// ECH is reported as present/absent; key material is never logged or returned.
func InspectMessage(msg *D.Msg) MessageDiagnostic {
	r := MessageDiagnostic{Addresses: []string{}, Bindings: []BindingDiagnostic{}}
	if msg == nil {
		return r
	}
	r.Rcode, r.AuthenticatedData = msg.Rcode, msg.AuthenticatedData
	owners := make(map[string]bool)
	if len(msg.Question) > 0 {
		owners[strings.ToLower(msg.Question[0].Name)] = true
	}
	for range len(msg.Answer) {
		changed := false
		for _, rr := range msg.Answer {
			if c, ok := rr.(*D.CNAME); ok && owners[strings.ToLower(c.Hdr.Name)] && !owners[strings.ToLower(c.Target)] {
				owners[strings.ToLower(c.Target)] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for _, records := range [][]D.RR{msg.Answer, msg.Extra} {
		for _, rr := range records {
			var binding *D.SVCB
			switch v := rr.(type) {
			case *D.A:
				if owners[strings.ToLower(v.Hdr.Name)] {
					r.Addresses = append(r.Addresses, v.A.String())
				}
			case *D.AAAA:
				if owners[strings.ToLower(v.Hdr.Name)] {
					r.Addresses = append(r.Addresses, v.AAAA.String())
				}
			case *D.HTTPS:
				binding = &v.SVCB
			case *D.SVCB:
				binding = v
			case *D.RRSIG:
				r.RRSIGPresent = true
			}
			if binding == nil {
				continue
			}
			b := BindingDiagnostic{Type: D.TypeToString[rr.Header().Rrtype], Priority: binding.Priority, Target: binding.Target, ALPN: []string{}, Mandatory: []string{}, IPv4Hint: []string{}, IPv6Hint: []string{}}
			for _, value := range binding.Value {
				switch v := value.(type) {
				case *D.SVCBECHConfig:
					b.ECH = len(v.ECH) > 0
				case *D.SVCBAlpn:
					b.ALPN = append(b.ALPN, v.Alpn...)
				case *D.SVCBMandatory:
					for _, code := range v.Code {
						b.Mandatory = append(b.Mandatory, code.String())
					}
				case *D.SVCBIPv4Hint:
					for _, ip := range v.Hint {
						b.IPv4Hint = append(b.IPv4Hint, ip.String())
					}
				case *D.SVCBIPv6Hint:
					for _, ip := range v.Hint {
						b.IPv6Hint = append(b.IPv6Hint, ip.String())
					}
				}
			}
			r.Bindings = append(r.Bindings, b)
		}
	}
	return r
}

type CacheDiagnostic struct {
	Resolver           string    `json:"resolver"`
	Source             string    `json:"source"`
	Node               string    `json:"node,omitempty"`
	Name               string    `json:"name"`
	Type               string    `json:"type"`
	State              string    `json:"state"`
	TTL                int64     `json:"ttl"`
	ExpiresAt          time.Time `json:"expiresAt"`
	NetworkScope       string    `json:"networkScope"`
	ECSGenerationKnown bool      `json:"ecsGenerationKnown"`
	MessageDiagnostic
}

// protected by persistMu, replaced at every runtime DNS reconfiguration
var diagnosticServiceResolver *Resolver

func RegisterDiagnosticService(r resolver.Resolver) {
	persistMu.Lock()
	diagnosticServiceResolver, _ = r.(*Resolver)
	persistMu.Unlock()
}

func CacheSnapshots(name string) []CacheDiagnostic {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	persistMu.Lock()
	caches := make(map[string]dnsCache, len(persistCaches))
	for key, c := range persistCaches {
		caches[key] = c
	}
	service := diagnosticServiceResolver
	persistMu.Unlock()
	result := make([]CacheDiagnostic, 0)
	now := time.Now()
	add := func(resolverName, source, node, key string, msg *D.Msg, expiry time.Time) {
		if msg == nil || len(msg.Question) != 1 {
			return
		}
		q := msg.Question[0]
		host := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		if name != "" && name != host {
			return
		}
		scope := ""
		if prefix, _, ok := strings.Cut(key, keySep); ok {
			scope = prefix
		}
		state := "fresh"
		if !now.Before(expiry) {
			state = "stale"
		}
		result = append(result, CacheDiagnostic{Resolver: resolverName, Source: source, Node: node, Name: host, Type: D.TypeToString[q.Qtype], State: state, TTL: max(0, int64(expiry.Sub(now)/time.Second)), ExpiresAt: expiry, NetworkScope: scope, MessageDiagnostic: InspectMessage(msg)})
	}
	for label, c := range caches {
		items, _ := snapshotOf(c)
		for _, item := range items {
			add(label, label, "", item.Key, item.Value, item.Expires)
		}
	}
	if service != nil && service.domainClient != nil {
		for _, item := range service.domainClient.cache.Snapshot() {
			add("domain-bundle", "server-dns", item.Key.node, "", item.Value, item.Expires)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Resolver != b.Resolver {
			return a.Resolver < b.Resolver
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		if a.NetworkScope != b.NetworkScope {
			return a.NetworkScope < b.NetworkScope
		}
		return a.Type < b.Type
	})
	return result
}

func CapabilitySnapshots() []tunneldns.Capability {
	result := tunneldns.Snapshot()
	persistMu.Lock()
	service := diagnosticServiceResolver
	persistMu.Unlock()
	if service != nil && service.domainClient != nil {
		result = append(result, service.domainClient.bundles.Snapshot()...)
	}
	return result
}
