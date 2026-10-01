package dialer

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/resolver"
)

var (
	DefaultInterface   = atomic.NewTypedValue[string]("")
	DefaultRoutingMark = atomic.NewInt32(0)
	// SystemDNSRoutingMark is the active sing-tun auto-redirect output mark.
	// It is intentionally separate from DefaultRoutingMark: ordinary direct
	// sockets only need the global mark in mark mode, while system DNS sockets
	// must always be identifiable as TUN-bypass traffic.
	SystemDNSRoutingMark = atomic.NewInt32(0)

	DefaultInterfaceFinder   = atomic.NewTypedValue[InterfaceFinder](nil)
	SystemDNSInterfaceFinder = atomic.NewTypedValue[InterfaceFinder](nil)
)

type InterfaceFinder interface {
	FindInterfaceName(destination netip.Addr) string
}

type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type NetDialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f NetDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type option struct {
	interfaceName string
	fallbackBind  bool
	addrReuse     bool
	dontFragment  bool
	routingMark   int
	network       int
	prefer        int
	concurrentTCP bool
	directRace    bool
	directAdapter string
	tfo           bool
	mpTcp         bool
	resolver      resolver.Resolver
	netDialer     NetDialer
}

type Option func(opt *option)

func WithInterface(name string) Option {
	return func(opt *option) {
		opt.interfaceName = name
	}
}

func WithFallbackBind(fallback bool) Option {
	return func(opt *option) {
		opt.fallbackBind = fallback
	}
}

func WithAddrReuse(reuse bool) Option {
	return func(opt *option) {
		opt.addrReuse = reuse
	}
}

// WithDontFragment carries a sender's refusal to have its datagrams fragmented
// through to the socket that re-sends them. Without it the tunnel quietly
// fragments what the sender asked to keep whole, and the sender's path MTU
// discovery settles on a size the path only carries in pieces.
func WithDontFragment(dontFragment bool) Option {
	return func(opt *option) {
		opt.dontFragment = dontFragment
	}
}

func WithRoutingMark(mark int) Option {
	return func(opt *option) {
		opt.routingMark = mark
	}
}

func WithResolver(r resolver.Resolver) Option {
	return func(opt *option) {
		opt.resolver = r
	}
}

func WithPreferIPv4() Option {
	return func(opt *option) {
		opt.prefer = 4
	}
}

func WithPreferIPv6() Option {
	return func(opt *option) {
		opt.prefer = 6
	}
}

// WithConcurrentTCP races every resolved address on each TCP dial, without
// address-family preference or the global TCP winner cache's head start.
func WithConcurrentTCP() Option {
	return func(opt *option) {
		opt.concurrentTCP = true
	}
}

// WithDirectDualStack enables the asynchronous A/AAAA and TCP connection race
// used by the DIRECT outbound. It is intentionally separate from the generic
// dual-stack dialer so DNS upstream hostnames keep their existing behavior.
func WithDirectDualStack() Option {
	return func(opt *option) {
		opt.directRace = true
	}
}

// WithDirectRacePreference identifies the DIRECT adapter whose recent ICMP
// winner may be scheduled first after it is validated against the DNS RRset.
func WithDirectRacePreference(adapter string) Option {
	return func(opt *option) {
		opt.directAdapter = adapter
	}
}

func WithOnlySingleStack(isIPv4 bool) Option {
	return func(opt *option) {
		if isIPv4 {
			opt.network = 4
		} else {
			opt.network = 6
		}
	}
}

func WithTFO(tfo bool) Option {
	return func(opt *option) {
		opt.tfo = tfo
	}
}

func WithMPTCP(mpTcp bool) Option {
	return func(opt *option) {
		opt.mpTcp = mpTcp
	}
}

func WithNetDialer(netDialer NetDialer) Option {
	return func(opt *option) {
		opt.netDialer = netDialer
	}
}

func WithOption(o option) Option {
	return func(opt *option) {
		*opt = o
	}
}

func WithOptions(options ...Option) Option {
	return func(opt *option) {
		for _, o := range options {
			o(opt)
		}
	}
}

func IsZeroOptions(opts []Option) bool {
	return applyOptions(opts...) == option{}
}

func applyOptions(options ...Option) option {
	opt := option{}
	for _, o := range options {
		o(&opt)
	}
	return opt
}
