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
)

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
	if msg == nil || msg.Truncated || (msg.Rcode != D.RcodeSuccess && msg.Rcode != D.RcodeNameError) {
		if msg == nil {
			return nil, errors.New("empty DNS response")
		}
		return nil, fmt.Errorf("server failure: %s", D.RcodeToString[msg.Rcode])
	}
	if len(msgToAddressIPs(msg, query.Question[0].Qtype)) == 0 && msg.Rcode == D.RcodeSuccess {
		var soa, referral bool
		for _, rr := range msg.Ns {
			soa = soa || rr.Header().Rrtype == D.TypeSOA
			referral = referral || rr.Header().Rrtype == D.TypeNS
		}
		if referral && !soa {
			return nil, errors.New("unresolved DNS referral")
		}
	}
	if log.Enabled(log.DEBUG) {
		log.Debugln("[DNS] %s --> %s from direct-nameserver #%d %s", domain, msgToLogString(msg), source+1, client.Address())
	}
	return msg, nil
}

func (r *Resolver) directCachedCandidates(key string, sourceCount int, qType uint16) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	var candidates []netip.Addr
	for source := 0; source < min(sourceCount, len(r.sourceCaches)); source++ {
		msg, _, hit := readUpstreamCache(r.sourceCaches[source], r.directSourceCacheKey(key, source))
		if !hit || msg == nil {
			continue
		}
		for _, ip := range msgToAddressIPs(msg, qType) {
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

// LookupIPCandidates publishes retained addresses before waiting for any DNS
// server. Each source refresh has its own coalesced flight and atomic replacement.
func (direct *directResolver) LookupIPCandidates(ctx context.Context, host string, ipv6 bool, networkScope string) <-chan R.IPCandidateBatch {
	r := direct.Resolver
	output := make(chan R.IPCandidateBatch, len(r.main)+2)
	go func() {
		defer close(output)
		if len(r.main) == 0 {
			output <- R.IPCandidateBatch{Err: R.ErrIPNotFound}
			return
		}
		q := directQuestion(host, ipv6)
		key := directCacheKey(networkScope, q)
		query := new(D.Msg).SetQuestion(q.Name, q.Qtype)
		if matched := r.matchPolicy(query); len(matched) > 0 {
			refresh := func() func(context.Context) (*D.Msg, error) {
				return r.cache.Refresh(key, R.DefaultDNSTimeout, func(work context.Context) (*D.Msg, time.Time, error) {
					msg, cache, err := batchExchange(work, matched, query)
					if err != nil {
						return nil, time.Time{}, err
					}
					if msg == nil || msg.Truncated || (msg.Rcode != D.RcodeSuccess && msg.Rcode != D.RcodeNameError) {
						return nil, time.Time{}, errors.New("unusable direct policy refresh")
					}
					if !cache {
						return msg.Copy(), time.Time{}, nil
					}
					msg, due := prepareCachedMessage(q, msg)
					return msg, due, nil
				})
			}
			if msg, due, hit := readUpstreamCache(r.cache, key); hit {
				if !time.Now().Before(due) {
					refresh()
				}
				output <- R.IPCandidateBatch{IPs: msgToAddressIPs(msg, q.Qtype), Source: -1}
				return
			}
			msg, err := refresh()(ctx)
			if err != nil {
				output <- R.IPCandidateBatch{Err: err}
				return
			}
			output <- R.IPCandidateBatch{IPs: msgToAddressIPs(msg, q.Qtype), Source: -1}
			return
		}
		candidates := r.directCachedCandidates(key, len(r.main), q.Qtype)
		fresh := false
		cached := false
		hasSource := false
		allSourcesFresh := len(r.sourceCaches) == len(r.main)
		hasStaleSource := false
		for source, c := range r.sourceCaches {
			if _, due, hit := readUpstreamCache(c, r.directSourceCacheKey(key, source)); hit {
				cached, hasSource = true, true
				if time.Now().Before(due) {
					fresh = true
				} else {
					hasStaleSource = true
					allSourcesFresh = false
				}
			} else {
				allSourcesFresh = false
			}
		}
		// Once sources have complete replacements (including empty answers),
		// an older aggregate answer must not resurrect removed addresses.
		if !hasSource {
			if msg, due, hit := readUpstreamCache(r.cache, key); hit && msg != nil {
				cached = true
				candidates = append(candidates, msgToAddressIPs(msg, q.Qtype)...)
				fresh = time.Now().Before(due) && len(candidates) > 0
			}
		}
		fresh = fresh && !hasStaleSource
		warm := len(candidates) > 0
		if !warm {
			// One upstream's empty answer cannot hide another source's addresses.
			fresh = allSourcesFresh
		}
		state := "miss"
		if cached {
			state = "stale"
			if fresh {
				state = "fresh"
			}
		}
		logDNSCache(q, state, networkScope)
		if warm {
			output <- R.IPCandidateBatch{IPs: candidates, Source: -1}
		}
		if fresh {
			if !warm {
				output <- R.IPCandidateBatch{Source: -1}
			}
			return
		}
		fetch := func(source int) (*D.Msg, error) {
			c := r.sourceCaches[source]
			if msg, due, hit := readUpstreamCache(c, r.directSourceCacheKey(key, source)); hit && time.Now().Before(due) {
				return msg, nil
			}
			wait := c.Refresh(r.directSourceCacheKey(key, source), R.DefaultDNSTimeout, func(work context.Context) (*D.Msg, time.Time, error) {
				msg, err := r.exchangeDirectSource(work, source, new(D.Msg).SetQuestion(q.Name, q.Qtype))
				if err != nil {
					return nil, time.Time{}, err
				}
				stored, due := prepareDirectCachedMessage(q, msg)
				if due.IsZero() {
					due = time.Now()
				}
				return stored, due, nil
			})
			return wait(ctx)
		}
		var errs []error
		answered := false
		tried := make(map[int]bool)
		if warm {
			// Refresh the first two choices plus every retained source that is
			// due. A long TTL on one upstream must not postpone another's refresh.
			sources := make([]int, 0, len(r.main))
			for source, c := range r.sourceCaches {
				_, due, hit := readUpstreamCache(c, r.directSourceCacheKey(key, source))
				if source < 2 || (hit && !time.Now().Before(due)) {
					sources = append(sources, source)
				}
			}
			parallel := len(sources)
			type answer struct {
				source int
				msg    *D.Msg
				err    error
			}
			answers := make(chan answer, parallel)
			for _, source := range sources {
				tried[source] = true
				go func(source int) { msg, err := fetch(source); answers <- answer{source, msg, err} }(source)
			}
			succeeded := false
			for range parallel {
				a := <-answers
				if a.err != nil {
					errs = append(errs, a.err)
					continue
				}
				answered = true
				ips := msgToAddressIPs(a.msg, q.Qtype)
				succeeded = succeeded || len(ips) > 0
				output <- R.IPCandidateBatch{IPs: ips, Source: a.source}
			}
			if succeeded {
				return
			}
		}
		for source := 0; source < len(r.main); source++ {
			if tried[source] {
				continue
			}
			msg, err := fetch(source)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			ips := msgToAddressIPs(msg, q.Qtype)
			output <- R.IPCandidateBatch{IPs: ips, Source: source}
			answered = true
			if len(ips) > 0 {
				return
			}
		}
		if answered {
			return
		}
		output <- R.IPCandidateBatch{Err: errors.Join(errs...)}
	}()
	return output
}

// TCP winners live in dev_cache's TCP namespace. A connection success must not
// renew DNS freshness or replace a complete DNS answer with a single address.
func (direct *directResolver) PromoteIP(string, bool, string, netip.Addr) {}

var _ R.ProgressiveResolver = (*directResolver)(nil)
