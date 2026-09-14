package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	R "github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
)

const directSourceCacheTTL = 24 * time.Hour

type directResolver struct {
	*Resolver
}

func directQuestion(host string, ipv6 bool) D.Question {
	qType := uint16(D.TypeA)
	if ipv6 {
		qType = D.TypeAAAA
	}
	return D.Question{Name: D.Fqdn(host), Qtype: qType, Qclass: D.ClassINET}
}

func directCacheKey(scope string, q D.Question) string {
	return scope + keySep + q.String()
}

func (r *Resolver) directSourceCacheKey(key string, source int) string {
	return key + keySep + r.main[source].Address()
}

func cacheDirectMessage(c dnsCache, key string, msg *D.Msg, minimumTTL time.Duration) {
	if c == nil || msg == nil {
		return
	}
	msg = msg.Copy()
	msg.Extra = lo.Filter(msg.Extra, func(rr D.RR, _ int) bool {
		return rr.Header().Rrtype != D.TypeOPT
	})
	ttl := minimalTTL(lo.Concat(msg.Answer, msg.Ns, msg.Extra))
	if ttl == 0 {
		return
	}
	expires := time.Now().Add(time.Duration(ttl) * time.Second)
	if minimumTTL > 0 && time.Until(expires) < minimumTTL {
		expires = time.Now().Add(minimumTTL)
	}
	c.SetWithExpire(key, msg, expires)
}

func (r *Resolver) exchangeDirectSource(ctx context.Context, source int, query *D.Msg) (*D.Msg, error) {
	if source < 0 || source >= len(r.main) {
		return nil, errors.New("direct nameserver index out of range")
	}
	client := r.main[source]
	domain := msgToDomain(query)
	_, qType := msgToQtype(query)
	if log.Enabled(log.DEBUG) {
		log.Debugln("[DNS] resolve %s %s from direct-nameserver #%d %s", domain, qType, source+1, client.Address())
	}
	msg, err := exchangeDiagnostic(ctx, client, query, source+1)
	if err != nil {
		return nil, err
	}
	if msg == nil || msg.Rcode == D.RcodeServerFailure || msg.Rcode == D.RcodeRefused {
		if msg == nil {
			return nil, errors.New("empty DNS response")
		}
		return nil, fmt.Errorf("server failure: %s", D.RcodeToString[msg.Rcode])
	}
	if len(msgToIP(msg)) == 0 {
		return nil, R.ErrIPNotFound
	}
	if log.Enabled(log.DEBUG) {
		log.Debugln("[DNS] %s --> %s from direct-nameserver #%d %s", domain, msgToLogString(msg), source+1, client.Address())
	}
	return msg, nil
}

func (r *Resolver) directCachedCandidates(key string, sourceCount int) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	var candidates []netip.Addr
	for source := 0; source < min(sourceCount, len(r.sourceCaches)); source++ {
		msg, expires, hit := r.sourceCaches[source].GetWithExpire(r.directSourceCacheKey(key, source))
		if !hit || msg == nil || !time.Now().Before(expires) {
			continue
		}
		for _, ip := range msgToIP(msg) {
			ip = ip.Unmap()
			if _, loaded := seen[ip]; loaded {
				continue
			}
			seen[ip] = struct{}{}
			candidates = append(candidates, ip)
		}
	}
	return candidates
}

// LookupIPCandidates implements resolver.ProgressiveResolver for the
// direct-nameserver resolver only. A valid ordinary cache is returned without
// network I/O. A cold miss walks servers in order. A stale entry first
// publishes still-live, network-scoped source candidates, then refreshes #1
// and #2 independently and publishes either response as soon as it arrives.
func (direct *directResolver) LookupIPCandidates(ctx context.Context, host string, ipv6 bool, networkScope string) <-chan R.IPCandidateBatch {
	r := direct.Resolver
	output := make(chan R.IPCandidateBatch, len(r.main)+1)
	go func() {
		defer close(output)
		if len(r.main) == 0 {
			output <- R.IPCandidateBatch{Err: R.ErrIPNotFound}
			return
		}

		q := directQuestion(host, ipv6)
		key := directCacheKey(networkScope, q)
		query := new(D.Msg).SetQuestion(q.Name, q.Qtype)
		if matched := r.matchPolicy(query); len(matched) != 0 {
			msg, cache, err := batchExchange(ctx, matched, query)
			if err != nil {
				output <- R.IPCandidateBatch{Err: err}
				return
			}
			if cache {
				cacheDirectMessage(r.cache, key, msg, 0)
			}
			output <- R.IPCandidateBatch{IPs: msgToIP(msg), Source: -1}
			return
		}
		if msg, expires, hit := r.cache.GetWithExpire(key); hit && msg != nil && time.Now().Before(expires) {
			logDNSCache(q, "fresh", networkScope)
			output <- R.IPCandidateBatch{IPs: msgToIP(msg), Source: -1}
			return
		} else if !hit {
			logDNSCache(q, "miss", networkScope)
			var errs []error
			for source := range r.main {
				msg, err := r.exchangeDirectSource(ctx, source, new(D.Msg).SetQuestion(q.Name, q.Qtype))
				if err != nil {
					errs = append(errs, fmt.Errorf("direct-nameserver #%d: %w", source+1, err))
					continue
				}
				cacheDirectMessage(r.sourceCaches[source], r.directSourceCacheKey(key, source), msg, directSourceCacheTTL)
				cacheDirectMessage(r.cache, key, msg, 0)
				output <- R.IPCandidateBatch{IPs: msgToIP(msg), Source: source}
				return
			}
			output <- R.IPCandidateBatch{Err: errors.Join(errs...)}
			return
		}

		logDNSCache(q, "stale", networkScope)
		parallel := min(2, len(r.main))
		if candidates := r.directCachedCandidates(key, len(r.main)); len(candidates) != 0 {
			_, qType := msgToQtype(query)
			log.Debugln("[DNS] direct source cache hit %s %s with %d candidates; refreshing in background", host, qType, len(candidates))
			output <- R.IPCandidateBatch{IPs: candidates, Source: -1}
		}
		type answer struct {
			source int
			msg    *D.Msg
			err    error
		}
		answers := make(chan answer, parallel)
		for source := range parallel {
			go func(source int) {
				msg, err := r.exchangeDirectSource(ctx, source, new(D.Msg).SetQuestion(q.Name, q.Qtype))
				answers <- answer{source: source, msg: msg, err: err}
			}(source)
		}

		var errs []error
		succeeded := false
		for range parallel {
			answer := <-answers
			if answer.err != nil {
				errs = append(errs, fmt.Errorf("direct-nameserver #%d: %w", answer.source+1, answer.err))
				continue
			}
			succeeded = true
			cacheDirectMessage(r.sourceCaches[answer.source], r.directSourceCacheKey(key, answer.source), answer.msg, directSourceCacheTTL)
			cacheDirectMessage(r.cache, key, answer.msg, 0)
			output <- R.IPCandidateBatch{IPs: r.directCachedCandidates(key, parallel), Source: answer.source}
		}
		if succeeded {
			return
		}

		for source := parallel; source < len(r.main); source++ {
			msg, err := r.exchangeDirectSource(ctx, source, new(D.Msg).SetQuestion(q.Name, q.Qtype))
			if err != nil {
				errs = append(errs, fmt.Errorf("direct-nameserver #%d: %w", source+1, err))
				continue
			}
			cacheDirectMessage(r.sourceCaches[source], r.directSourceCacheKey(key, source), msg, directSourceCacheTTL)
			cacheDirectMessage(r.cache, key, msg, 0)
			output <- R.IPCandidateBatch{IPs: msgToIP(msg), Source: source}
			return
		}
		output <- R.IPCandidateBatch{Err: errors.Join(errs...)}
	}()
	return output
}

// PromoteIP makes the current TCP winner the ordinary direct DNS cache answer.
// Source caches are read but never modified, so one server cannot overwrite
// another server's long-lived candidate set.
func (direct *directResolver) PromoteIP(host string, ipv6 bool, networkScope string, winner netip.Addr) {
	r := direct.Resolver
	if r == nil || !winner.IsValid() {
		return
	}
	winner = winner.Unmap()
	q := directQuestion(host, ipv6)
	key := directCacheKey(networkScope, q)
	for source, sourceCache := range r.sourceCaches {
		msg, _, hit := sourceCache.GetWithExpire(r.directSourceCacheKey(key, source))
		if !hit || msg == nil {
			continue
		}
		selected := msg.Copy()
		selected.Answer = lo.Filter(selected.Answer, func(rr D.RR, _ int) bool {
			switch record := rr.(type) {
			case *D.A:
				ip, ok := netip.AddrFromSlice(record.A)
				return ok && ip.Unmap() == winner
			case *D.AAAA:
				ip, ok := netip.AddrFromSlice(record.AAAA)
				return ok && ip.Unmap() == winner
			case *D.CNAME:
				return true
			default:
				return false
			}
		})
		if len(msgToIP(selected)) == 0 {
			continue
		}
		cacheDirectMessage(r.cache, key, selected, 0)
		return
	}
}

var _ R.ProgressiveResolver = (*directResolver)(nil)
