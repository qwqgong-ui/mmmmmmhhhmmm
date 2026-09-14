package dns

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/dev_cache"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
)

type dnsClient interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error)
	Address() string
	ResetConnection()
}

type dnsCache = *dev_cache.Cache[string, *D.Msg]

type result struct {
	Msg   *D.Msg
	Error error
}

type Resolver struct {
	cacheIdentity         string
	domainClient          *domainClient
	ipv6                  bool
	ipv6Timeout           time.Duration
	main                  []dnsClient
	fallback              []dnsClient
	fallbackDomainFilters []C.DomainMatcher
	fallbackIPFilters     []C.IpMatcher
	fallbackLazyQuery     bool
	cache                 dnsCache
	policy                []dnsPolicy
	defaultResolver       *Resolver
	sourceCaches          []dnsCache
}

func (r *Resolver) IPv6Timeout() time.Duration {
	if r == nil {
		return 0
	}
	return r.ipv6Timeout
}

func (r *Resolver) LookupIPPrimaryIPv4(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}
		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	if err == nil {
		return
	}

	ip, open := <-ch
	if !open {
		return nil, resolver.ErrIPNotFound
	}

	return ip, nil
}

func (r *Resolver) LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error) {
	ch := make(chan []netip.Addr, 1)
	go func() {
		defer close(ch)
		ip, err := r.lookupIP(ctx, host, D.TypeAAAA)
		if err != nil {
			return
		}

		ch <- ip
	}()

	ips, err = r.lookupIP(ctx, host, D.TypeA)
	var waitIPv6 *time.Timer
	if r != nil && r.ipv6Timeout > 0 {
		waitIPv6 = time.NewTimer(r.ipv6Timeout)
	} else {
		waitIPv6 = time.NewTimer(100 * time.Millisecond)
	}
	defer waitIPv6.Stop()
	select {
	case ipv6s, open := <-ch:
		if !open && err != nil {
			return nil, resolver.ErrIPNotFound
		}
		ips = append(ips, ipv6s...)
	case <-waitIPv6.C:
		// wait ipv6 result
	}

	return ips, nil
}

// LookupIPv4 request with TypeA
func (r *Resolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeA)
}

// LookupIPv6 request with TypeAAAA
func (r *Resolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupIP(ctx, host, D.TypeAAAA)
}

func (r *Resolver) shouldIPFallback(ip netip.Addr) bool {
	for _, filter := range r.fallbackIPFilters {
		if filter.MatchIp(ip) {
			return true
		}
	}
	return false
}

func (r *Resolver) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), D.TypeHTTPS)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return nil, err
	}

	for _, rr := range msg.Answer {
		switch resource := rr.(type) {
		case *D.HTTPS:
			for _, value := range resource.Value {
				if echConfig, ok := value.(*D.SVCBECHConfig); ok {
					return echConfig.ECH, nil
				}
			}
		}
	}
	return nil, errors.New("no ECH config found in DNS records")
}

// ExchangeContext returns retained answers immediately. A TTL is a refresh
// deadline, never a local availability deadline.
func (r *Resolver) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if len(m.Question) != 1 {
		return nil, errors.New("should have one question")
	}
	if r.domainClient != nil {
		return r.domainClient.ExchangeContext(ctx, m)
	}
	request := m.Copy()
	request.Question[0].Name = strings.ToLower(request.Question[0].Name)
	key := dev_cache.ScopedKey(dev_cache.CurrentScope(), request.Question[0].String())
	if msg, due, hit := r.cache.GetWithExpire(key); hit && msg != nil {
		if !time.Now().Before(due) {
			logDNSCache(request.Question[0], "stale", strings.SplitN(key, keySep, 2)[0])
			r.refreshAnswer(key, request)
		} else {
			logDNSCache(request.Question[0], "fresh", strings.SplitN(key, keySep, 2)[0])
		}
		return cachedReply(msg, due, m), nil
	}
	logDNSCache(request.Question[0], "miss", strings.SplitN(key, keySep, 2)[0])
	wait := r.refreshAnswer(key, request)
	msg, err := wait(ctx)
	if err != nil {
		return nil, err
	}
	return cachedReply(msg, time.Time{}, m), nil
}

func cachedReply(msg *D.Msg, due time.Time, request *D.Msg) *D.Msg {
	msg = msg.Copy()
	msg.Id = request.Id
	msg.Question = append([]D.Question(nil), request.Question...)
	if !due.IsZero() {
		if !time.Now().Before(due) {
			setMsgTTL(msg, 3)
		} else {
			updateMsgTTL(msg, uint32(max(1, time.Until(due)/time.Second)))
		}
	}
	return msg
}

func (r *Resolver) refreshAnswer(key string, m *D.Msg) func(context.Context) (*D.Msg, error) {
	return r.cache.Refresh(key, resolver.DefaultDNSTimeout, func(ctx context.Context) (*D.Msg, time.Time, error) {
		var msg *D.Msg
		var err error
		cache := false
		if isIPRequest(m.Question[0]) {
			msg, err = r.ipExchange(ctx, m)
			cache = true
		} else if matched := r.matchPolicy(m); len(matched) > 0 {
			msg, cache, err = batchExchange(ctx, matched, m)
		} else {
			msg, cache, err = batchExchange(ctx, r.main, m)
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		if msg == nil || msg.Truncated || (msg.Rcode != D.RcodeSuccess && msg.Rcode != D.RcodeNameError) {
			return nil, time.Time{}, errors.New("unusable DNS refresh response")
		}
		if !cache {
			return msg.Copy(), time.Time{}, nil
		}
		stored, due := prepareCachedMessage(m.Question[0], msg)
		return stored, due, nil
	})
}

func (r *Resolver) matchPolicy(m *D.Msg) []dnsClient {
	if r.policy == nil {
		return nil
	}

	domain := msgToDomain(m)
	if domain == "" {
		return nil
	}

	for _, policy := range r.policy {
		if dnsClients := policy.Match(domain); len(dnsClients) > 0 {
			return dnsClients
		}
	}
	return nil
}

func (r *Resolver) shouldOnlyQueryFallback(m *D.Msg) bool {
	if r.fallback == nil || len(r.fallbackDomainFilters) == 0 {
		return false
	}

	domain := msgToDomain(m)

	if domain == "" {
		return false
	}

	for _, df := range r.fallbackDomainFilters {
		if df.MatchDomain(domain) {
			return true
		}
	}

	return false
}

func (r *Resolver) ipExchange(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	if matched := r.matchPolicy(m); len(matched) != 0 {
		res := <-r.asyncExchange(ctx, matched, m)
		return res.Msg, res.Error
	}

	onlyFallback := r.shouldOnlyQueryFallback(m)

	if onlyFallback {
		res := <-r.asyncExchange(ctx, r.fallback, m)
		return res.Msg, res.Error
	}

	msgCh := r.asyncExchange(ctx, r.main, m)

	if r.fallback == nil { // directly return if no fallback servers are available
		res := <-msgCh
		msg, err = res.Msg, res.Error
		return
	}

	var fallbackMsg <-chan *result
	if !r.fallbackLazyQuery {
		fallbackMsg = r.asyncExchange(ctx, r.fallback, m)
	}
	res := <-msgCh
	if res.Error == nil {
		if ips := msgToIP(res.Msg); len(ips) != 0 {
			shouldNotFallback := lo.EveryBy(ips, func(ip netip.Addr) bool {
				return !r.shouldIPFallback(ip)
			})
			if shouldNotFallback {
				msg, err = res.Msg, res.Error // no need to wait for fallback result
				return
			}
		}
	}

	if fallbackMsg == nil {
		fallbackMsg = r.asyncExchange(ctx, r.fallback, m)
	}
	res = <-fallbackMsg
	msg, err = res.Msg, res.Error
	return
}

func (r *Resolver) lookupIP(ctx context.Context, host string, dnsType uint16) (ips []netip.Addr, err error) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		ip = ip.Unmap()
		isIPv4 := ip.Is4()
		if dnsType == D.TypeAAAA && !isIPv4 {
			return []netip.Addr{ip}, nil
		} else if dnsType == D.TypeA && isIPv4 {
			return []netip.Addr{ip}, nil
		} else {
			return []netip.Addr{}, resolver.ErrIPVersion
		}
	}

	query := &D.Msg{}
	query.SetQuestion(D.Fqdn(host), dnsType)

	msg, err := r.ExchangeContext(ctx, query)
	if err != nil {
		return []netip.Addr{}, err
	}

	ips = msgToIP(msg)
	ipLength := len(ips)
	if ipLength == 0 {
		return []netip.Addr{}, resolver.ErrIPNotFound
	}

	return
}

func (r *Resolver) asyncExchange(ctx context.Context, client []dnsClient, msg *D.Msg) <-chan *result {
	ch := make(chan *result, 1)
	go func() {
		res, _, err := batchExchange(ctx, client, msg)
		ch <- &result{Msg: res, Error: err}
	}()
	return ch
}

// Invalid return this resolver can or can't be used
func (r *Resolver) Invalid() bool {
	if r == nil {
		return false
	}
	return len(r.main) > 0
}

func (r *Resolver) ClearCache() {
	if r != nil {
		if r.cache != nil {
			r.cache.Clear()
		}
		if r.domainClient != nil {
			r.domainClient.cache.Clear()
			r.domainClient.records.Clear()
		}
		for _, cache := range r.sourceCaches {
			cache.Clear()
		}
	}
}

func (r *Resolver) ClearVolatileCache() {
	// Network handovers select another partition; they must not discard an
	// offline network's answers. Refresh deadlines remain independently valid.
	if r == nil {
		return
	}
	scope := dev_cache.CurrentScope()
	mark := func(c dnsCache) {
		if c != nil {
			c.MarkStale(func(key string) bool { return dev_cache.InScope(key, scope) })
		}
	}
	mark(r.cache)
	for _, c := range r.sourceCaches {
		mark(c)
	}
	if r.domainClient != nil {
		mark(r.domainClient.cache)
		mark(r.domainClient.records)
	}
}

func (r *Resolver) ResetConnection() {
	if r != nil {
		for _, c := range r.main {
			c.ResetConnection()
		}
		for _, c := range r.fallback {
			c.ResetConnection()
		}
		if dr := r.defaultResolver; dr != nil {
			dr.ResetConnection()
		}
	}
}

type NameServer struct {
	Net          string
	Addr         string
	ProxyAdapter C.ProxyAdapter
	ProxyName    string
	Params       map[string]string
	PreferH3     bool
}

func (ns NameServer) Equal(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	if ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		maps.Equal(ns.Params, ns2.Params) &&
		ns.PreferH3 == ns2.PreferH3 {
		return true
	}
	return false
}

// transportEqual reports whether two NameServers share the same raw transport and
// may reuse a single client. It compares all fields except wrapper-only params.
func (ns NameServer) transportEqual(ns2 NameServer) bool {
	defer func() {
		// C.ProxyAdapter compare maybe panic, just ignore
		recover()
	}()
	paramsEqual := func(a, b map[string]string) bool {
		for k, v := range a {
			if isWrapperOnlyParam(k) {
				continue
			}
			if bv, ok := b[k]; !ok || bv != v {
				return false
			}
		}
		return true
	}
	return ns.Net == ns2.Net &&
		ns.Addr == ns2.Addr &&
		ns.ProxyAdapter == ns2.ProxyAdapter &&
		ns.ProxyName == ns2.ProxyName &&
		ns.PreferH3 == ns2.PreferH3 &&
		paramsEqual(ns.Params, ns2.Params) &&
		paramsEqual(ns2.Params, ns.Params)
}

type Policy struct {
	Domain      string
	Matcher     C.DomainMatcher
	NameServers []NameServer
}

type Config struct {
	CacheIdentity        string
	Main, Fallback       []NameServer
	Default              []NameServer
	ProxyServer          []NameServer
	DirectServer         []NameServer
	DirectFollowPolicy   bool
	IPv6                 bool
	IPv6Timeout          uint
	FallbackIPFilter     []C.IpMatcher
	FallbackDomainFilter []C.DomainMatcher
	FallbackLazyQuery    bool
	Policy               []Policy
	ProxyServerPolicy    []Policy
	CacheAlgorithm       string
	CacheMaxSize         int
}

func (config Config) newCache() dnsCache {
	if config.CacheMaxSize == 0 {
		config.CacheMaxSize = 32768
	}
	return dev_cache.New[string, *D.Msg](config.CacheMaxSize, config.CacheAlgorithm)
}

type Resolvers struct {
	*Resolver
	ProxyResolver  *Resolver
	DirectResolver *directResolver
	// BootstrapResolver is the `default-nameserver` resolver, which only
	// talks to plain IP servers and is therefore the one path that resolves
	// a hostname regardless of how the other lists are configured.
	BootstrapResolver *Resolver
}

func (rs Resolvers) ClearCache() {
	rs.Resolver.ClearCache()
	rs.ProxyResolver.ClearCache()
	rs.DirectResolver.ClearCache()
}

func (rs Resolvers) ClearVolatileCache() {
	rs.Resolver.ClearVolatileCache()
	rs.ProxyResolver.ClearVolatileCache()
	rs.DirectResolver.ClearVolatileCache()
}

func (rs Resolvers) ResetConnection() {
	rs.Resolver.ResetConnection()
	rs.ProxyResolver.ResetConnection()
	rs.DirectResolver.ResetConnection()
}

func NewResolverFromClient(client dnsClient) *Resolver {
	return &Resolver{
		ipv6:  true,
		main:  []dnsClient{client},
		cache: Config{}.newCache(),
	}
}

// NewFakeIPServiceResolver returns the built-in resolver used only for
// address and SVCB/HTTPS queries in fake-IP mode. One node/domain bundle
// is fetched before allocating a fake IP.
//
// The record is asked of the proxy server the queried domain's own traffic
// goes through, over the reserved tunnel destination. Only that server's view
// counts: its answer is the one the connection is actually built on, and a
// SVCB/HTTPS record carries ech keys and alpn that no address query can carry
// back through the proxy.
//
// A server that does not serve the reserved destination falls back to a public
// resolver -- sequentially, not as a race, and remembered per node, so it
// costs one attempt per node instead of one per query and a domain only
// reaches the public resolver when no server could answer for it.
//
// A domain that routes to a local leaf never reaches that public resolver at
// all: it has no proxy server, and its service records are the ones a direct
// connection will use, so direct is the resolver asked for it.
func NewFakeIPServiceResolver(defaultServers []NameServer, direct *Resolver, cacheAlgorithm string, cacheMaxSize int, identity ...string) *Resolver {
	config := fakeIPServiceConfig(defaultServers, cacheAlgorithm, cacheMaxSize)

	bootstrap := &Resolver{
		main:  transform(config.Default, nil),
		cache: config.newCache(),
	}
	public := transform(config.Main, bootstrap)

	// Invalid reports that a resolver has servers behind it. One without any
	// must stay a nil interface so the local path can tell it apart.
	var directExchange directExchanger
	if direct.Invalid() {
		directExchange = direct
	}

	client := newDomainClient(public[0], directExchange, cacheMaxSize)
	namespace := "v1"
	if len(identity) > 0 {
		namespace += "/" + identity[0]
	}
	client.cache = attachDNSCache("domain-bundle/"+namespace, client.cache)
	client.records = attachDNSCache("domain-record/"+namespace, client.records)
	return &Resolver{
		ipv6:            true,
		main:            []dnsClient{public[0]},
		domainClient:    client,
		cache:           config.newCache(),
		defaultResolver: bootstrap,
	}
}

// fakeIPServiceConfig describes the public fallback. It is only reached for a
// domain whose node cannot answer, and it follows routing rules so it is
// carried by the selected proxy rather than by local UDP DNS.
func fakeIPServiceConfig(defaultServers []NameServer, cacheAlgorithm string, cacheMaxSize int) Config {
	return Config{
		Main: []NameServer{{
			Net:       "https",
			Addr:      "https://1.1.1.1:443/dns-query",
			ProxyName: RespectRules,
			Params:    map[string]string{},
		}},
		Default:        defaultServers,
		IPv6:           true,
		CacheAlgorithm: cacheAlgorithm,
		CacheMaxSize:   cacheMaxSize,
	}
}

func NewResolver(config Config) (rs Resolvers) {
	defaultResolver := &Resolver{
		main:        transform(config.Default, nil),
		cache:       config.newCache(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
	}

	var nameServerCache []struct {
		NameServer
		dnsClient
	}
	cacheTransform := func(nameserver []NameServer) (result []dnsClient) {
	LOOP:
		for _, ns := range nameserver {
			var dc dnsClient
			for _, nsc := range nameServerCache {
				if nsc.NameServer.Equal(ns) {
					result = append(result, nsc.dnsClient)
					continue LOOP // exact match wins: reuse the wrapped client as-is
				}
				if dc == nil && nsc.NameServer.transportEqual(ns) {
					dc = nsc.dnsClient // reusable raw transport; keep scanning for an exact match
				}
			}
			if dc != nil { // reuse raw transport, re-wrap the client
				dc = rewrapClient(dc, ns.Params)
			} else { // no reusable transport: build from scratch
				built := transform([]NameServer{ns}, defaultResolver)
				if len(built) == 0 {
					continue
				}
				dc = built[0]
			}
			nameServerCache = append(nameServerCache, struct {
				NameServer
				dnsClient
			}{NameServer: ns, dnsClient: dc})
			result = append(result, dc)
		}
		return
	}

	makePolicy := func(policies []Policy) (dnsPolicies []dnsPolicy) {
		var triePolicy *trie.DomainTrie[[]dnsClient]
		insertPolicy := func(policy dnsPolicy) {
			if triePolicy != nil {
				triePolicy.Optimize()
				dnsPolicies = append(dnsPolicies, domainTriePolicy{triePolicy})
				triePolicy = nil
			}
			if policy != nil {
				dnsPolicies = append(dnsPolicies, policy)
			}
		}

		for _, policy := range policies {
			if policy.Matcher != nil {
				insertPolicy(domainMatcherPolicy{matcher: policy.Matcher, dnsClients: cacheTransform(policy.NameServers)})
			} else {
				if triePolicy == nil {
					triePolicy = trie.New[[]dnsClient]()
				}
				if err := triePolicy.Insert(policy.Domain, cacheTransform(policy.NameServers)); err != nil {
					log.Warnln("[DNS] skip invalid nameserver policy: %s", err)
				}
			}
		}
		insertPolicy(nil)
		return
	}

	r := &Resolver{
		ipv6:        config.IPv6,
		main:        cacheTransform(config.Main),
		cache:       config.newCache(),
		ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
		policy:      makePolicy(config.Policy),
	}
	r.defaultResolver = defaultResolver
	rs.Resolver = r
	rs.DirectResolver = &directResolver{Resolver: &Resolver{}}
	rs.BootstrapResolver = defaultResolver

	if len(config.ProxyServer) != 0 {
		rs.ProxyResolver = &Resolver{
			ipv6:        config.IPv6,
			main:        cacheTransform(config.ProxyServer),
			cache:       config.newCache(),
			ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
			policy:      makePolicy(config.ProxyServerPolicy),
		}
	}

	if len(config.DirectServer) != 0 {
		rs.DirectResolver = &directResolver{Resolver: &Resolver{
			ipv6:        config.IPv6,
			main:        cacheTransform(config.DirectServer),
			cache:       config.newCache(),
			ipv6Timeout: time.Duration(config.IPv6Timeout) * time.Millisecond,
		}}
		for range rs.DirectResolver.main {
			sourceCache := config.newCache()
			rs.DirectResolver.sourceCaches = append(rs.DirectResolver.sourceCaches, sourceCache)
		}
		if config.DirectFollowPolicy {
			rs.DirectResolver.policy = r.policy
		}
	}

	if len(config.Fallback) != 0 {
		r.fallback = cacheTransform(config.Fallback)
		r.fallbackIPFilters = config.FallbackIPFilter
		r.fallbackDomainFilters = config.FallbackDomainFilter
		r.fallbackLazyQuery = config.FallbackLazyQuery
	}
	// Availability changes must reattach the same A/AAAA stores. Policy and
	// upstream configuration remain part of the namespace. Complex matcher
	// identities conservatively start a new namespace if reconstructed.
	identityConfig := config
	identityConfig.IPv6 = false
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%#v", identityConfig))))
	if config.CacheIdentity != "" {
		identity = config.CacheIdentity
	}
	for _, resolver := range []*Resolver{rs.Resolver, rs.ProxyResolver, rs.DirectResolver.Resolver, rs.BootstrapResolver} {
		if resolver != nil {
			resolver.cacheIdentity = identity
		}
	}

	return
}

var ParseNameServer func(servers []string) ([]NameServer, error) // define in config/config.go
