package dns

import (
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type (
	handler    func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error)
	middleware func(next handler) handler
)

func withHosts(mapping *lru.LruCache[netip.Addr, string]) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			host := strings.TrimRight(q.Name, ".")
			handleCName := func(resp *D.Msg, domain string) {
				rr := &D.CNAME{}
				rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 10}
				rr.Target = domain + "."
				resp.Answer = append([]D.RR{rr}, resp.Answer...)
			}
			record, ok := resolver.DefaultHosts.Search(host, q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA)
			if !ok {
				if record != nil && record.IsDomain {
					// replace request domain
					newR := r.Copy()
					newR.Question[0].Name = record.Domain + "."
					resp, err := next(ctx, newR)
					if err == nil {
						resp.Id = r.Id
						resp.Question = r.Question
						handleCName(resp, record.Domain)
					}
					return resp, err
				}
				return next(ctx, r)
			}

			msg := r.Copy()
			handleIPs := func() {
				for _, ipAddr := range record.IPs {
					if ipAddr.Is4() && q.Qtype == D.TypeA {
						rr := &D.A{}
						rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 10}
						rr.A = ipAddr.AsSlice()
						msg.Answer = append(msg.Answer, rr)
						if mapping != nil {
							mapping.SetWithExpire(ipAddr, host, time.Now().Add(time.Second*10))
						}
					} else if ipAddr.Is6() && q.Qtype == D.TypeAAAA {
						rr := &D.AAAA{}
						rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 10}
						rr.AAAA = ipAddr.AsSlice()
						msg.Answer = append(msg.Answer, rr)
						if mapping != nil {
							mapping.SetWithExpire(ipAddr, host, time.Now().Add(time.Second*10))
						}
					}
				}
			}

			switch q.Qtype {
			case D.TypeA:
				handleIPs()
			case D.TypeAAAA:
				handleIPs()
			case D.TypeCNAME:
				handleCName(msg, record.Domain)
			default:
				return next(ctx, r)
			}

			ctx.SetType(icontext.DNSTypeHost)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true
			return msg, nil
		}
	}
}

func withMapping(mapping *lru.LruCache[netip.Addr, string]) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			if !isIPRequest(q) {
				return next(ctx, r)
			}

			msg, err := next(ctx, r)
			if err != nil {
				return nil, err
			}

			host := strings.TrimRight(q.Name, ".")

			for _, ans := range msg.Answer {
				var ip netip.Addr
				var ttl uint32

				switch a := ans.(type) {
				case *D.A:
					ip, _ = netip.AddrFromSlice(a.A)
					ttl = a.Hdr.Ttl
				case *D.AAAA:
					ip, _ = netip.AddrFromSlice(a.AAAA)
					ttl = a.Hdr.Ttl
				default:
					continue
				}
				if !ip.IsValid() {
					continue
				}
				if !ip.IsGlobalUnicast() {
					continue
				}
				ip = ip.Unmap()

				if ttl < 1 {
					ttl = 1
				}

				mapping.SetWithExpire(ip, host, time.Now().Add(time.Second*time.Duration(ttl)))
			}

			return msg, nil
		}
	}
}

func withFakeIP(skipper *fakeip.Skipper, fakePool *fakeip.Pool, fakePool6 *fakeip.Pool, fakeIPTTL int, serviceResolver resolver.Resolver) middleware {
	return func(next handler) handler {
		return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
			q := r.Question[0]

			host := strings.TrimRight(q.Name, ".")
			skipped := skipper.ShouldSkipped(host)
			sr, builtIn := serviceResolver.(*Resolver)
			builtIn = builtIn && sr != nil && sr.domainClient != nil
			var serviceAnswer *D.Msg
			var serviceErr error
			if builtIn && q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA {
				serviceRecord := q.Qtype == D.TypeHTTPS || q.Qtype == D.TypeSVCB
				var direct bool
				// Real-IP exclusions and ordinary records still need DIRECT routing.
				// Other leaves keep their existing ordinary or tunnel DNS path.
				serviceAnswer, direct, serviceErr = sr.domainClient.exchangeRouted(ctx, r, skipped || !serviceRecord)
				if direct {
					ctx.SetType(icontext.DNSTypeRaw)
					if serviceErr != nil || skipped || !serviceRecord {
						return serviceAnswer, serviceErr
					}
				}
			}
			if skipped {
				return next(ctx, r)
			}
			if (q.Qtype == D.TypeA || q.Qtype == D.TypeAAAA) && !isFakeIPHostName(host) {
				log.Debugln("[DNS] refusing to allocate a fake IP for %q, which cannot be a host name", host)
				return handleMsgWithNameError(r), nil
			}

			// The built-in resolver warms one complete node/domain bundle before
			// the application can use the fake address. Third-party resolvers
			// retain their previous behavior.
			bundleTTL := uint32(fakeIPTTL)
			if sr, ok := serviceResolver.(*Resolver); ok && sr != nil && sr.domainClient != nil &&
				(q.Qtype == D.TypeA && fakePool != nil || q.Qtype == D.TypeAAAA && fakePool6 != nil) {
				if answer, err := sr.ExchangeContext(ctx, r); err == nil {
					for _, records := range [][]D.RR{answer.Answer, answer.Extra} {
						for _, rr := range records {
							if rr.Header().Rrtype != D.TypeOPT {
								bundleTTL = min(bundleTTL, rr.Header().Ttl)
							}
						}
					}
				} else {
					log.Debugln("[DNS] domain bundle unavailable for %s: %v", host, err)
				}
			}

			var rr D.RR
			switch q.Qtype {
			case D.TypeA:
				if fakePool == nil {
					return handleMsgWithEmptyAnswer(r), nil
				}
				ip := fakePool.Lookup(host)
				rr = &D.A{
					Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
					A:   ip.AsSlice(),
				}
			case D.TypeAAAA:
				if fakePool6 == nil {
					return handleMsgWithEmptyAnswer(r), nil
				}
				ip := fakePool6.Lookup(host)
				rr = &D.AAAA{
					Hdr:  D.RR_Header{Name: q.Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: dnsDefaultTTL},
					AAAA: ip.AsSlice(),
				}
			case D.TypeSVCB, D.TypeHTTPS:
				var msg *D.Msg
				var err error
				if serviceResolver == nil {
					msg, err = next(ctx, r)
				} else {
					ctx.SetType(icontext.DNSTypeRaw)
					if builtIn {
						msg, err = serviceAnswer, serviceErr
					} else {
						msg, err = serviceResolver.ExchangeContext(ctx, r)
					}
					if err != nil {
						// A service resolver that could not be reached must not
						// be worse than having none configured: fall through to
						// the ordinary path rather than failing the query.
						log.Debugln("[DNS] fakeip service resolver failed for %s, falling back: %v", host, err)
						msg, err = next(ctx, r)
					}
				}
				if err != nil {
					return msg, err
				}
				msg = msg.Copy()
				msg.SetRcode(r, msg.Rcode)
				serviceTTL := fakeIPTTL
				if sr, ok := serviceResolver.(*Resolver); ok && sr != nil && sr.domainClient != nil {
					for _, record := range msg.Answer {
						serviceTTL = min(serviceTTL, int(record.Header().Ttl))
					}
				}
				if rewriteFakeIPServiceBindings(msg, fakePool, fakePool6, serviceTTL) {
					ctx.SetType(icontext.DNSTypeFakeIP)
				}
				if sr, ok := serviceResolver.(*Resolver); ok && sr != nil && sr.domainClient != nil {
					for _, record := range msg.Answer {
						record.Header().Ttl = min(record.Header().Ttl, uint32(max(serviceTTL, 0)))
					}
				}
				return msg, nil
			default:
				return next(ctx, r)
			}

			msg := r.Copy()
			msg.Answer = []D.RR{rr}

			ctx.SetType(icontext.DNSTypeFakeIP)
			setMsgTTL(msg, bundleTTL)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			return msg, nil
		}
	}
}

func withResolver(resolver resolver.Resolver, ipv6 bool) handler {
	return func(ctx *icontext.DNSContext, r *D.Msg) (*D.Msg, error) {
		ctx.SetType(icontext.DNSTypeRaw)

		q := r.Question[0]

		// return a empty AAAA msg when ipv6 disabled
		if !ipv6 && q.Qtype == D.TypeAAAA {
			return handleMsgWithEmptyAnswer(r), nil
		}

		msg, err := resolver.ExchangeContext(ctx, r)
		if err != nil {
			log.Debugln("[DNS Server] Exchange %s failed: %v", q.String(), err)
			return msg, err
		}
		msg.SetRcode(r, msg.Rcode)
		msg.Authoritative = true

		return msg, nil
	}
}

func compose(middlewares []middleware, endpoint handler) handler {
	length := len(middlewares)
	h := endpoint
	for i := length - 1; i >= 0; i-- {
		middleware := middlewares[i]
		h = middleware(h)
	}

	return h
}

func newHandler(resolver resolver.Resolver, serviceResolver resolver.Resolver, mapper *ResolverEnhancer) handler {
	var middlewares []middleware

	if mapper.useHosts {
		middlewares = append(middlewares, withHosts(mapper.mapping))
	}

	if mapper.mode == C.DNSFakeIP {
		middlewares = append(middlewares, withFakeIP(mapper.fakeIPSkipper, mapper.fakeIPPool, mapper.fakeIPPool6, mapper.fakeIPTTL, serviceResolver))
	}

	if mapper.mode != C.DNSNormal {
		middlewares = append(middlewares, withMapping(mapper.mapping))
	}

	return compose(middlewares, withResolver(resolver, mapper.ipv6))
}
