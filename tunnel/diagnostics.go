package tunnel

import (
	C "github.com/metacubex/mihomo/constant"
	"net/netip"
)

type RouteDiagnostic struct {
	Proxy       string `json:"proxy,omitempty"`
	Rule        string `json:"rule,omitempty"`
	RulePayload string `json:"rulePayload,omitempty"`
	ResolvedIP  string `json:"resolvedIp,omitempty"`
	Leaf        string `json:"leaf,omitempty"`
	LeafType    string `json:"leafType,omitempty"`
	DNSSource   string `json:"dnsSource"`
	Complete    bool   `json:"complete"`
	Reason      string `json:"reason,omitempty"`
	Preview     bool   `json:"preview"`
}

// DiagnoseRoute previews the same rule matcher without DNS probes, socket
// attribution, or traffic rule counters. IP-dependent rules without a known
// address make this explicitly incomplete, not a definitive routing verdict.
func DiagnoseRoute(host string, port uint16, network C.NetWork, knownIP ...netip.Addr) (RouteDiagnostic, error) {
	metadata := &C.Metadata{Host: host, DstPort: port, NetWork: network, Type: C.INNER}
	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.Host = ""
		metadata.DstIP = ip.Unmap()
	}
	result := RouteDiagnostic{Preview: true, Complete: true, DNSSource: "unknown"}
	if len(knownIP) > 0 && knownIP[0].IsValid() {
		metadata.DstIP = knownIP[0]
	}
	configMux.RLock()
	defer configMux.RUnlock()
	helper := C.RuleMatchHelper{Diagnostic: true, ResolveIP: func() {
		if !metadata.Resolved() {
			result.Complete = false
			result.Reason = "ip_rule_requires_dns"
		}
	}, CheckPassRule: func(name string) bool {
		for p := proxies[name]; p != nil; p = p.Unwrap(metadata, false) {
			if p.Type() == C.PassRule {
				return true
			}
		}
		return false
	}}
	var proxy C.Proxy
	var rule C.Rule
	var err error
	switch Mode() {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	default:
		proxy, rule, err = matchLocked(metadata, helper)
	}
	if err != nil {
		return RouteDiagnostic{}, err
	}
	if proxy != nil {
		result.Proxy = proxy.Name()
		leaf := leafProxy(proxy, metadata)
		result.Leaf, result.LeafType = leaf.Name(), leaf.Type().String()
		switch {
		case leaf.Type() == C.Direct:
			result.DNSSource = "direct"
		case leaf.Type().CanServeTunnelDNS():
			result.DNSSource = "server-dns_or_public_fallback"
		default:
			result.DNSSource = "no_server_node"
		}
	} else {
		result.Complete = false
		result.Reason = "no_proxy_configured"
	}
	if rule != nil {
		result.Rule, result.RulePayload = rule.RuleType().String(), rule.Payload()
	}
	if metadata.DstIP.IsValid() {
		result.ResolvedIP = metadata.DstIP.String()
	}
	return result, nil
}
