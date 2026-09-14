package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/trie"

	"github.com/metacubex/randv2"
	"github.com/miekg/dns"
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// ProxyServerHostResolver resolve ip for proxies server host, only nil when DefaultResolver is nil
	ProxyServerHostResolver Resolver

	// DirectHostResolver resolve ip for direct outbound host, only nil when DefaultResolver is nil
	DirectHostResolver Resolver

	// BootstrapResolver is the `default-nameserver` resolver used to bring
	// the DNS module up (it resolves the other nameservers' hostnames), only
	// nil when DefaultResolver is nil
	BootstrapResolver Resolver

	// SystemResolver always using system dns, and was init in dns module
	SystemResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	// It is an atomic.Bool because the runtime IPv6 availability monitor in
	// hub/executor flips it from a background goroutine while ordinary
	// lookups read it concurrently from arbitrary connection-handling
	// goroutines.
	DisableIPv6 = atomic.NewBool(true)

	// DefaultHosts aim to resolve hosts
	DefaultHosts = NewHosts(trie.New[HostValue]())

	// DefaultDNSTimeout defined the default dns request timeout
	DefaultDNSTimeout = time.Second * 3
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

type Resolver interface {
	LookupIP(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv4(ctx context.Context, host string) (ips []netip.Addr, err error)
	LookupIPv6(ctx context.Context, host string) (ips []netip.Addr, err error)
	ResolveECH(ctx context.Context, host string) ([]byte, error)
	ExchangeContext(ctx context.Context, m *dns.Msg) (msg *dns.Msg, err error)
	Invalid() bool
	ClearCache()
	ResetConnection()
}

// IPCandidateBatch is one independently resolved set of addresses. DIRECT
// uses the optional ProgressiveResolver interface to start TCP connects as
// soon as one direct-nameserver answers, while later servers may still add
// candidates to the same race.
type IPCandidateBatch struct {
	IPs    []netip.Addr
	Source int
	Err    error
}

// ProgressiveResolver is deliberately optional: only the resolver built from
// direct-nameserver implements it. Other resolver users retain the ordinary
// one-shot Resolver contract.
type ProgressiveResolver interface {
	LookupIPCandidates(ctx context.Context, host string, ipv6 bool, networkScope string) <-chan IPCandidateBatch
	PromoteIP(host string, ipv6 bool, networkScope string, ip netip.Addr)
}

const defaultIPv6Timeout = 100 * time.Millisecond

// IPv6Timeout returns the resolver's AAAA wait budget. Resolver
// implementations that do not expose one retain LookupIP's historical 100ms
// default.
func IPv6Timeout(r Resolver) time.Duration {
	type timeoutProvider interface {
		IPv6Timeout() time.Duration
	}
	if provider, ok := r.(timeoutProvider); ok {
		if timeout := provider.IPv6Timeout(); timeout > 0 {
			return timeout
		}
	}
	return defaultIPv6Timeout
}

// parseAddrLiteral is netip.ParseAddr with a cheap pre-filter for hostnames.
// netip's failure path builds an error that carries the input string, so
// calling it on every hostname lookup allocates for a result that is always
// discarded. Any textual IP either contains a ':' (IPv6) or ends in a digit
// (IPv4), so anything else cannot parse and is rejected without touching the
// parser.
func parseAddrLiteral(host string) (netip.Addr, error) {
	if !mayBeAddrLiteral(host) {
		return netip.Addr{}, ErrIPNotFound
	}
	return netip.ParseAddr(host)
}

func mayBeAddrLiteral(host string) bool {
	if host == "" {
		return false
	}
	if strings.IndexByte(host, ':') >= 0 {
		return true
	}
	// Without a colon the only thing left that can parse is an IPv4 literal,
	// which always ends in a digit. A hostname ending in a digit still falls
	// through to the parser, it just costs what it always did.
	last := host[len(host)-1]
	return last >= '0' && last <= '9'
}

// LookupIPv4WithResolver same as LookupIPv4, but with a resolver
func LookupIPv4WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is4()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	if ip, err := parseAddrLiteral(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return []netip.Addr{ip}, nil
		}
		return []netip.Addr{}, ErrIPVersion
	}

	if r != nil && r.Invalid() {
		return r.LookupIPv4(ctx, host)
	}

	return SystemResolver.LookupIPv4(ctx, host)
}

// LookupIPv4 with a host, return ipv4 list
func LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv4WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv4WithResolver same as ResolveIPv4, but with a resolver
func ResolveIPv4WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv4WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[randv2.IntN(len(ips))], nil
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv4WithResolver(ctx, host, DefaultResolver)
}

// LookupIPv6WithResolver same as LookupIPv6, but with a resolver
func LookupIPv6WithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if DisableIPv6.Load() {
		return nil, ErrIPv6Disabled
	}

	if node, ok := DefaultHosts.Search(host, false); ok {
		if addrs := utils.Filter(node.IPs, func(ip netip.Addr) bool {
			return ip.Is6()
		}); len(addrs) > 0 {
			return addrs, nil
		}
	}

	if ip, err := parseAddrLiteral(host); err == nil {
		ip = ip.Unmap()
		if ip.Is6() {
			return []netip.Addr{ip}, nil
		}
		return nil, ErrIPVersion
	}

	if r != nil && r.Invalid() {
		return r.LookupIPv6(ctx, host)
	}

	return SystemResolver.LookupIPv6(ctx, host)
}

// LookupIPv6 with a host, return ipv6 list
func LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPv6WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv6WithResolver same as ResolveIPv6, but with a resolver
func ResolveIPv6WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPv6WithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[randv2.IntN(len(ips))], nil
}

func ResolveIPv6(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPv6WithResolver(ctx, host, DefaultResolver)
}

// LookupIPWithResolver same as LookupIP, but with a resolver
func LookupIPWithResolver(ctx context.Context, host string, r Resolver) ([]netip.Addr, error) {
	if node, ok := DefaultHosts.Search(host, false); ok {
		return node.IPs, nil
	}

	if r != nil && r.Invalid() {
		if DisableIPv6.Load() {
			return r.LookupIPv4(ctx, host)
		}
		return r.LookupIP(ctx, host)
	} else if DisableIPv6.Load() {
		return LookupIPv4WithResolver(ctx, host, r)
	}

	if ip, err := parseAddrLiteral(host); err == nil {
		ip = ip.Unmap()
		return []netip.Addr{ip}, nil
	}

	return SystemResolver.LookupIP(ctx, host)
}

// LookupIP with a host, return ip
func LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return LookupIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPWithResolver same as ResolveIP, but with a resolver
func ResolveIPWithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPWithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	ipv4s, ipv6s := SortationAddr(ips)
	if len(ipv4s) > 0 {
		return ipv4s[randv2.IntN(len(ipv4s))], nil
	}
	return ipv6s[randv2.IntN(len(ipv6s))], nil
}

// ResolveIP with a host, return ip and priority return TypeA
func ResolveIP(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPPrefer6WithResolver same as ResolveIP, but with a resolver
func ResolveIPPrefer6WithResolver(ctx context.Context, host string, r Resolver) (netip.Addr, error) {
	ips, err := LookupIPWithResolver(ctx, host, r)
	if err != nil {
		return netip.Addr{}, err
	} else if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	ipv4s, ipv6s := SortationAddr(ips)
	if len(ipv6s) > 0 {
		return ipv6s[randv2.IntN(len(ipv6s))], nil
	}
	return ipv4s[randv2.IntN(len(ipv4s))], nil
}

// ResolveIPPrefer6 with a host, return ip and priority return TypeAAAA
func ResolveIPPrefer6(ctx context.Context, host string) (netip.Addr, error) {
	return ResolveIPPrefer6WithResolver(ctx, host, DefaultResolver)
}

func ResolveECHWithResolver(ctx context.Context, host string, r Resolver) ([]byte, error) {
	if r != nil && r.Invalid() {
		return r.ResolveECH(ctx, host)
	}
	return SystemResolver.ResolveECH(ctx, host)
}

func ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return ResolveECHWithResolver(ctx, host, DefaultResolver)
}

func ClearCache() {
	if DefaultResolver != nil {
		DefaultResolver.ClearCache()
	}
	SystemResolver.ClearCache() // SystemResolver unneeded check nil
}

// ClearVolatileCache drops ordinary resolver answers after a network handover
// without deleting long-lived, network-scoped source candidates.
func ClearVolatileCache() {
	clear := func(r Resolver) {
		if volatile, ok := r.(interface{ ClearVolatileCache() }); ok {
			volatile.ClearVolatileCache()
		} else {
			r.ClearCache()
		}
	}
	if DefaultResolver != nil {
		go clear(DefaultResolver)
	}
	go clear(SystemResolver)
}

func ResetConnection() {
	if DefaultResolver != nil {
		go DefaultResolver.ResetConnection()
	}
	go SystemResolver.ResetConnection() // SystemResolver unneeded check nil
}

func SortationAddr(ips []netip.Addr) (ipv4s, ipv6s []netip.Addr) {
	for _, v := range ips {
		if v.Unmap().Is4() {
			ipv4s = append(ipv4s, v)
		} else {
			ipv6s = append(ipv6s, v)
		}
	}
	return
}
