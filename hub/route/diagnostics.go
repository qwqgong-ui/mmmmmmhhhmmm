package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/diagstats"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/directrace"
	"github.com/metacubex/mihomo/component/ecs"
	"github.com/metacubex/mihomo/component/hybrid"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	D "github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// Active diagnostics are explicit, bounded and never create a destination
// connection. Ordinary GET snapshots have no probes or periodic work.
var activePathQueries = make(chan struct{}, 4)

func getNetworkDiagnostic(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"network": dialer.CurrentNetworkStatus(), "ipv6": executor.IPv6Status(), "ecs": ecs.Snapshot()})
}

func winnerDiagnostics(host string) render.M {
	return render.M{"tcp": dialer.TCPWinnerSnapshots(host), "udpQuic": directrace.Snapshot(host), "notes": []string{"TCP entries retain their own scope and port; validate against current DNS before use", "QUIC warm preferences are host/proxy/family keyed; RTT, port and scope are not retained"}}
}

func getDirectWinners(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, winnerDiagnostics(r.URL.Query().Get("host")))
}
func getHybridStats(w http.ResponseWriter, r *http.Request) { render.JSON(w, r, hybrid.Stats()) }
func getHybridFlows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	render.JSON(w, r, render.M{"flows": hybrid.FlowSnapshotsFor(q.Get("host"), q.Get("port"), q.Get("proxy"))})
}
func getDNSCache(w http.ResponseWriter, r *http.Request) {
	entries := dns.CacheSnapshots(r.URL.Query().Get("name"))
	total := len(entries)
	if len(entries) > 2000 {
		entries = entries[:2000]
	}
	render.JSON(w, r, render.M{"entries": entries, "total": total, "truncated": total > len(entries), "ecs": ecs.Snapshot(), "note": "ECS generation is current runtime state; individual cached answers do not retain their discovery generation"})
}
func getServerCapabilities(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"nodes": dns.CapabilitySnapshots(), "unknownNodes": "nodes not listed have not been tested; unknown is not confirmed support"})
}
func getDownstreamStats(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"counters": diagstats.Snapshot(), "hybridQuic": hybrid.Stats(), "logSubscriberDrops": log.DroppedEvents(), "lifetime": "process", "coverage": "named counters only; absent subsystems are not measured"})
}

func diagnosticTarget(host, portText string) (string, uint16, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", 0, errors.New("host is required")
	}
	if _, err := netip.ParseAddr(host); err != nil && strings.Contains(host, ":") {
		h, p, e := net.SplitHostPort(host)
		if e != nil || portText != "" {
			return "", 0, errors.New("invalid or duplicate host port")
		}
		host, portText = h, p
	}
	if portText == "" {
		portText = "443"
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", 0, errors.New("port must be between 1 and 65535")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), uint16(port), nil
	}
	host, err = idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, " /\\@?#:\x00\t\r\n") {
		return "", 0, errors.New("invalid host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", 0, errors.New("invalid host label")
		}
	}
	return strings.ToLower(host), uint16(port), nil
}

type pathQuery struct {
	Type          string  `json:"type"`
	Source        string  `json:"source"`
	State         string  `json:"state"`
	Error         string  `json:"error,omitempty"`
	LatencyMillis float64 `json:"latencyMs"`
	dns.MessageDiagnostic
}

func queryPath(ctx context.Context, host, scope string, service resolver.Service, direct resolver.Resolver, allowDirect bool) []pathQuery {
	type job struct {
		kind   uint16
		source string
	}
	jobs := []job{{D.TypeA, "dns_service"}, {D.TypeAAAA, "dns_service"}, {D.TypeHTTPS, "dns_service"}, {D.TypeSVCB, "dns_service"}}
	if allowDirect {
		jobs = append(jobs, job{D.TypeA, "direct_nameserver"}, job{D.TypeAAAA, "direct_nameserver"})
	}
	done := make(chan pathQuery, len(jobs))
	pending := make(map[string]job, len(jobs))
	for _, j := range jobs {
		pending[j.source+strconv.Itoa(int(j.kind))] = j
		go func() {
			start := time.Now()
			q := pathQuery{Type: D.TypeToString[j.kind], Source: j.source, State: "ok", MessageDiagnostic: dns.InspectMessage(nil)}
			var err error
			if j.kind == D.TypeAAAA && resolver.DisableIPv6.Load() {
				q.State = "disabled"
				q.Error = "ipv6_disabled"
			} else if j.source == "dns_service" {
				if service == nil {
					err = errors.New("dns_service_disabled")
				} else {
					m := new(D.Msg)
					m.SetQuestion(D.Fqdn(host), j.kind)
					var msg *D.Msg
					msg, err = service.ServeMsg(ctx, m)
					if err == nil && msg == nil {
						err = errors.New("empty DNS response")
					}
					q.MessageDiagnostic = dns.InspectMessage(msg)
				}
			} else if direct == nil {
				err = errors.New("direct_resolver_disabled")
			} else if progressive, ok := direct.(resolver.ProgressiveResolver); ok {
				for batch := range progressive.LookupIPCandidates(ctx, host, j.kind == D.TypeAAAA, scope) {
					if batch.Err != nil {
						err = errors.Join(err, batch.Err)
					}
					for _, ip := range batch.IPs {
						q.Addresses = append(q.Addresses, ip.String())
					}
				}
				if len(q.Addresses) > 0 && err != nil {
					q.State = "partial"
					q.Error = err.Error()
					err = nil
				}
				if len(q.Addresses) == 0 && err == nil {
					err = resolver.ErrIPNotFound
				}
			} else {
				var ips []netip.Addr
				if j.kind == D.TypeA {
					ips, err = direct.LookupIPv4(ctx, host)
				} else {
					ips, err = direct.LookupIPv6(ctx, host)
				}
				for _, ip := range ips {
					q.Addresses = append(q.Addresses, ip.String())
				}
				if len(ips) == 0 && err == nil {
					err = resolver.ErrIPNotFound
				}
			}
			if err != nil {
				q.State = "error"
				q.Error = err.Error()
			}
			q.LatencyMillis = float64(time.Since(start)) / float64(time.Millisecond)
			done <- q
		}()
	}
	result := make([]pathQuery, 0, len(jobs))
	for len(pending) > 0 {
		select {
		case q := <-done:
			delete(pending, q.Source+strconv.Itoa(int(D.StringToType[q.Type])))
			result = append(result, q)
		case <-ctx.Done():
			for _, j := range pending {
				result = append(result, pathQuery{Type: D.TypeToString[j.kind], Source: j.source, State: "error", Error: ctx.Err().Error(), MessageDiagnostic: dns.InspectMessage(nil)})
			}
			clear(pending)
		}
	}
	slices.SortFunc(result, func(a, b pathQuery) int { return strings.Compare(a.Source+a.Type, b.Source+b.Type) })
	return result
}

func debugPath(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bad := func(err error) { render.Status(r, http.StatusBadRequest); render.JSON(w, r, newError(err.Error())) }
	host, port, err := diagnosticTarget(q.Get("host"), q.Get("port"))
	if err != nil {
		bad(err)
		return
	}
	network := C.TCP
	switch strings.ToLower(q.Get("network")) {
	case "", "tcp":
	case "udp":
		network = C.UDP
	default:
		bad(errors.New("network must be tcp or udp"))
		return
	}
	active := false
	if value := q.Get("resolve"); value != "" {
		active, err = strconv.ParseBool(value)
		if err != nil {
			bad(errors.New("resolve must be true or false"))
			return
		}
	}
	if active {
		select {
		case activePathQueries <- struct{}{}:
			defer func() { <-activePathQueries }()
		default:
			render.Status(r, http.StatusTooManyRequests)
			render.JSON(w, r, newError("too many active diagnostics"))
			return
		}
	}
	route, service, direct, fakeIP, err := executor.DiagnosticPath(host, port, network)
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	state := dialer.CurrentNetworkStatus()
	_, progressive := direct.(resolver.ProgressiveResolver)
	queries := []pathQuery{}
	if active {
		ctx, cancel := context.WithTimeout(r.Context(), resolver.DefaultDNSTimeout)
		defer cancel()
		queries = queryPath(ctx, host, state.NetworkScope, service, direct, route.Complete && route.DNSSource == "direct")
	}
	entries := dns.CacheSnapshots(host)
	ipv4, ipv6 := []string{}, []string{}
	known := false
	add := func(value string) {
		if ip, err := netip.ParseAddr(value); err == nil {
			if ip.Is4() {
				if !slices.Contains(ipv4, value) {
					ipv4 = append(ipv4, value)
				}
			} else if !slices.Contains(ipv6, value) {
				ipv6 = append(ipv6, value)
			}
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		add(ip.String())
		known = true
	}
	for _, entry := range entries {
		if !route.Complete || entry.State != "fresh" {
			continue
		}
		if route.DNSSource == "direct" {
			if !strings.HasPrefix(entry.Resolver, "direct") || (progressive && entry.NetworkScope != state.NetworkScope) || (!progressive && entry.NetworkScope != "" && entry.NetworkScope != state.NetworkScope) {
				continue
			}
		} else if port != 443 || entry.Source != "server-dns" || entry.Node != route.Leaf {
			continue
		}
		if len(entry.Addresses) == 0 {
			continue
		}
		known = true
		for _, ip := range entry.Addresses {
			add(ip)
		}
	}
	for _, query := range queries {
		if query.Source == "direct_nameserver" && (query.State == "ok" || query.State == "partial") {
			known = true
			for _, ip := range query.Addresses {
				add(ip)
			}
		}
	}
	render.JSON(w, r, render.M{
		"host": host, "port": port, "network": network.String(), "activeQueries": active, "route": route,
		"networkState": state, "ipv6State": executor.IPv6Status(), "ecs": ecs.Snapshot(),
		"dns":     render.M{"fakeIPEnabled": fakeIP, "ipv4Candidates": ipv4, "ipv6Candidates": ipv6, "candidatesKnown": known, "cache": entries, "queries": queries, "capabilities": dns.CapabilitySnapshots()},
		"winners": winnerDiagnostics(host), "hybridQuic": render.M{"flows": hybrid.FlowSnapshotsFor(host, strconv.Itoa(int(port)), "")},
		"notes": []string{"Rule preview has no source socket, process or inbound identity; group choice may change before a real connection", "Only matching fresh direct-scope or selected-node bundle addresses are candidates; no cache means unknown", "dns_service queries show actual client-facing A/AAAA/HTTPS/SVCB, including Fake-IP rewriting; cached bindings are upstream observations", "AD and RRSIG presence is observed, not independently validated; active queries can warm the normal DNS cache"},
	})
}
