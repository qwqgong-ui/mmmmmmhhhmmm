package dns

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/component/diagstats"
	"github.com/metacubex/mihomo/component/ecs"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

func logDNSCache(q D.Question, state, scope string) {
	switch state {
	case "fresh":
		diagstats.Add(diagstats.DNSFresh)
	case "stale":
		diagstats.Add(diagstats.DNSStale)
	case "miss":
		diagstats.Add(diagstats.DNSMiss)
	}
	if !log.Enabled(log.DEBUG) {
		return
	}
	log.Fields(log.DEBUG, map[string]string{"subsystem": "dns", "event": "cache_decision", "host": q.Name, "type": D.TypeToString[q.Qtype], "cache": state, "network_scope": scope, "ecs_generation": fmt.Sprint(ecs.Snapshot().Generation)}, "DNS %s %s cache=%s scope=%s", q.Name, D.TypeToString[q.Qtype], state, scope)
}

func exchangeDiagnostic(ctx context.Context, client dnsClient, query *D.Msg, source int) (msg *D.Msg, err error) {
	debug := log.Enabled(log.DEBUG)
	var start time.Time
	if debug {
		start = time.Now()
	}
	msg, err = client.ExchangeContext(ctx, query)
	if err != nil && !errors.Is(err, context.Canceled) {
		diagstats.Add(diagstats.DNSUpstreamError)
	}
	if debug {
		count := 0
		if msg != nil {
			count = len(msgToIP(msg))
		}
		reason := "response"
		if err != nil {
			reason = "query_failed"
			if errors.Is(err, context.Canceled) {
				reason = "cancelled"
			}
		}
		log.Fields(log.DEBUG, map[string]string{"subsystem": "dns", "event": "upstream_response", "host": msgToDomain(query), "upstream": fmt.Sprint(source), "reason": reason, "latency_ms": fmt.Sprint(float64(time.Since(start)) / float64(time.Millisecond)), "candidate_count": fmt.Sprint(count)}, "DNS %s upstream #%d %s candidates=%d error=%v", query.Question[0].String(), source, client.Address(), count, err)
	}
	return
}
