package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/dev_cache"
	"github.com/metacubex/mihomo/component/tunneldns"
	"github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"
)

// Experimental EDNS option shared with Xray. Version 1 requests an HTTPS
// answer plus the server's actual address lookup in Additional. An echoed
// option acknowledges a complete bundle, including an empty address family.
const domainBundleOption = 65001

// ErrNoDirectNameServer reports that a domain whose own traffic stays on this
// machine had no direct name server to ask. The caller is expected to fall
// through to the ordinary resolution path, which is still local, rather than
// to carry the question out through a proxy.
var ErrNoDirectNameServer = errors.New("no direct nameserver for a local domain")

// directExchanger is the `direct-nameserver` list, as much of it as this
// client needs.
type directExchanger interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error)
}

func domainKey(node, host string) string {
	return dev_cache.ScopedKey(dev_cache.CurrentScope(), node+keySep+host)
}

type domainClient struct {
	public  dnsClient
	direct  directExchanger
	bundles *tunneldns.Registry
	cache   dnsCache
	records dnsCache
	prepare func(string) (string, func(context.Context) (net.Conn, error), error)
}

func newDomainClient(public dnsClient, direct directExchanger, size int) *domainClient {
	if size <= 0 {
		size = 1024
	}
	return &domainClient{public: public, direct: direct, bundles: tunneldns.NewRegistryFor("domain_bundle"), cache: dev_cache.New[string, *D.Msg](size, "lru"), records: dev_cache.New[string, *D.Msg](size, "lru"), prepare: tunnel.PrepareTunnelDNSCache}
}

func (c *domainClient) ExchangeContext(ctx context.Context, request *D.Msg) (*D.Msg, error) {
	if len(request.Question) != 1 || request.Question[0].Qclass != D.ClassINET {
		return nil, errors.New("domain query needs one IN question")
	}
	q := request.Question[0]
	addressQuery := q.Qtype == D.TypeA || q.Qtype == D.TypeAAAA
	host := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	node, dial, err := c.prepare(host)
	if err != nil {
		if addressQuery {
			return nil, err
		}
		// A domain whose own traffic never leaves this machine has no proxy
		// server to ask, and its service records are the ones a direct
		// connection will be built on. Asking a public resolver through a
		// proxy would answer with a different network's view of the domain,
		// and would send every direct domain's name out through that proxy.
		if errors.Is(err, tunnel.ErrTunnelDNSDirectNode) {
			return c.directExchange(ctx, request)
		}
		// A leaf with no server that is not direct either -- reject above all
		// -- is one nothing ever connects through. Whatever its service
		// records say would be discarded with the connection, so answer here
		// instead of spending a query, and a proxied one at that, on them.
		if errors.Is(err, tunnel.ErrTunnelDNSNoServerNode) {
			return handleMsgWithEmptyAnswer(request), nil
		}
		return c.publicExchange(ctx, request)
	}
	key := domainKey(node, host)
	_, _, hasCachedBundle := c.cache.GetWithExpire(key)
	_, _, hasCachedRecord := c.records.GetWithExpire(key + keySep + q.String())
	if !hasCachedBundle && !hasCachedRecord && !tunneldns.Supported(node) {
		if addressQuery {
			return nil, errors.New("server DNS capability is in retry backoff")
		}
		return c.publicExchange(ctx, request)
	}
	if !hasCachedBundle && !c.bundles.Supported(node) {
		if addressQuery {
			return nil, errors.New("server does not support domain bundles")
		}
		return c.cachedExchange(ctx, key, node, host, dial, request)
	}
	if q.Qtype != D.TypeA && q.Qtype != D.TypeAAAA && q.Qtype != D.TypeHTTPS {
		return c.cachedExchange(ctx, key, node, host, dial, request)
	}
	project := func(msg *D.Msg, expiry time.Time) *D.Msg {
		msg = msg.Copy()
		if !expiry.IsZero() {
			if time.Now().Before(expiry) {
				setMsgTTL(msg, uint32(max(1, time.Until(expiry)/time.Second)))
			} else {
				setMsgTTL(msg, 3)
			}
		}
		response := new(D.Msg)
		response.SetReply(request)
		response.RecursionAvailable = true
		response.Rcode = msg.Rcode
		if q.Qtype == D.TypeHTTPS {
			response.Answer = msg.Answer
			response.Ns = msg.Ns
		} else {
			// Keep the complete bundle internally, including its TTL when the
			// requested family is empty. withFakeIP never exposes these addresses.
			response.Extra = msg.Extra
			for _, rr := range msg.Extra {
				if rr.Header().Rrtype == q.Qtype && strings.EqualFold(rr.Header().Name, D.Fqdn(host)) {
					response.Answer = append(response.Answer, rr)
				}
			}
		}
		return response
	}
	refresh := func() func(context.Context) (*D.Msg, error) {
		return c.cache.Refresh(key, tunnelExchangeTimeout, func(work context.Context) (*D.Msg, time.Time, error) {
			if msg, expiry, ok := c.cache.GetWithExpire(key); ok && time.Now().Before(expiry) {
				return msg, expiry, nil
			}
			query := new(D.Msg)
			query.SetQuestion(D.Fqdn(host), D.TypeHTTPS)
			query.SetEdns0(1232, false)
			query.IsEdns0().Option = append(query.IsEdns0().Option, &D.EDNS0_LOCAL{Code: domainBundleOption, Data: []byte{1}})
			_, _, retained := c.cache.GetWithExpire(key)
			msg, err := c.exchangeNode(work, node, host, dial, query, retained)
			if err != nil {
				return nil, time.Time{}, err
			}
			if !hasDomainBundle(msg) {
				if msg.Rcode == D.RcodeSuccess {
					c.bundles.MarkUnsupported(node)
				}
				return nil, time.Time{}, errors.New("server does not support domain bundles")
			}
			if msg.Rcode != D.RcodeSuccess || msg.Truncated {
				return nil, time.Time{}, errors.New("incomplete domain bundle")
			}
			ttl := uint32(^uint32(0))
			foundAddress := false
			for _, rr := range append(append([]D.RR{}, msg.Answer...), msg.Extra...) {
				if rr.Header().Rrtype == D.TypeOPT {
					continue
				}
				ttl = min(ttl, rr.Header().Ttl)
				if (rr.Header().Rrtype == D.TypeA || rr.Header().Rrtype == D.TypeAAAA) && strings.EqualFold(rr.Header().Name, D.Fqdn(host)) {
					foundAddress = true
				}
			}
			if !foundAddress {
				return nil, time.Time{}, errors.New("domain bundle has no real address")
			}
			// Replace the complete node bundle atomically, including empty families.
			setMsgTTL(msg, ttl)
			c.bundles.MarkSupported(node)
			return msg.Copy(), time.Now().Add(time.Duration(ttl) * time.Second), nil
		})
	}
	if msg, expiry, ok := c.cache.GetWithExpire(key); ok {
		if !time.Now().Before(expiry) {
			logDNSCache(q, "stale", strings.SplitN(key, keySep, 2)[0])
			refresh()
		} else {
			logDNSCache(q, "fresh", strings.SplitN(key, keySep, 2)[0])
		}
		return project(msg, expiry), nil
	}
	logDNSCache(q, "miss", strings.SplitN(key, keySep, 2)[0])
	msg, refreshErr := refresh()(ctx)
	if refreshErr != nil {
		if addressQuery {
			return nil, refreshErr
		}
		// Older servers remain usable for ordinary record queries. They are not
		// marked unsupported just because they did not acknowledge this extension.
		return c.cachedExchange(ctx, key, node, host, dial, request)
	}
	return project(msg, time.Time{}), nil
}

func (c *domainClient) cachedExchange(ctx context.Context, key, node, host string, dial func(context.Context) (net.Conn, error), request *D.Msg) (*D.Msg, error) {
	key += keySep + request.Question[0].String()
	query := request.Copy()
	refresh := func() func(context.Context) (*D.Msg, error) {
		return c.records.Refresh(key, tunnelExchangeTimeout, func(work context.Context) (*D.Msg, time.Time, error) {
			_, _, retained := c.records.GetWithExpire(key)
			msg, err := c.exchangeNode(work, node, host, dial, query, retained)
			if err != nil {
				return nil, time.Time{}, err
			}
			if msg == nil || msg.Truncated || (msg.Rcode != D.RcodeSuccess && msg.Rcode != D.RcodeNameError) {
				return nil, time.Time{}, errors.New("unusable tunnel DNS refresh")
			}
			msg, due := prepareCachedMessage(query.Question[0], msg)
			return msg, due, nil
		})
	}
	if msg, due, ok := c.records.GetWithExpire(key); ok {
		if !time.Now().Before(due) {
			refresh()
		}
		return cachedReply(msg, due, request), nil
	}
	msg, err := refresh()(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A cold fallback can still answer the caller, but must not replace
		// the node-specific view with a public resolver's view.
		return c.publicExchange(ctx, request)
	}
	return cachedReply(msg, time.Time{}, request), nil
}

func hasDomainBundle(msg *D.Msg) bool {
	if opt := msg.IsEdns0(); opt != nil {
		for _, option := range opt.Option {
			if local, ok := option.(*D.EDNS0_LOCAL); ok && local.Code == domainBundleOption && string(local.Data) == "\x01" {
				return true
			}
		}
	}
	return false
}

func (c *domainClient) exchangeNode(ctx context.Context, node, host string, dial func(context.Context) (net.Conn, error), request *D.Msg, retained bool) (*D.Msg, error) {
	conn, err := dial(ctx)
	if err == nil {
		defer conn.Close()
		var msg *D.Msg
		msg, err = exchangeOverConn(ctx, conn, request)
		if err == nil && msg.Rcode != D.RcodeRefused && msg.Rcode != D.RcodeNotImplemented {
			tunneldns.MarkSupported(node)
			return msg, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err == nil {
		err = errors.New("tunnel DNS refused query")
	}
	// A transient failure of a previously useful node belongs to refresh
	// backoff, not the five-minute unsupported-server capability cache.
	if !retained {
		markTunnelDNSUnsupported(node, host, err)
	}
	return nil, err
}

func (c *domainClient) publicExchange(ctx context.Context, request *D.Msg) (*D.Msg, error) {
	return c.public.ExchangeContext(ctx, withoutBundleOption(request))
}

// directExchange answers from `direct-nameserver`. Without one configured
// there is nothing better to ask here: the ordinary resolution path the caller
// falls back to is local too, and it already knows this domain's policy.
func (c *domainClient) directExchange(ctx context.Context, request *D.Msg) (*D.Msg, error) {
	if c.direct == nil {
		return nil, ErrNoDirectNameServer
	}
	return c.direct.ExchangeContext(ctx, withoutBundleOption(request))
}

// withoutBundleOption returns a copy of request that no longer advertises the
// extension, which only the reserved tunnel destination understands.
func withoutBundleOption(request *D.Msg) *D.Msg {
	request = request.Copy()
	if opt := request.IsEdns0(); opt != nil {
		options := opt.Option[:0]
		for _, option := range opt.Option {
			if option.Option() != domainBundleOption {
				options = append(options, option)
			}
		}
		opt.Option = options
	}
	return request
}
