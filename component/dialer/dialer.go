package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/directrace"
	"github.com/metacubex/mihomo/component/keepalive"
	"github.com/metacubex/mihomo/component/mptcp"
	"github.com/metacubex/mihomo/component/resolver"
)

const (
	DefaultTCPTimeout = 5 * time.Second
	DefaultUDPTimeout = DefaultTCPTimeout

	dualStackFallbackTimeout = 300 * time.Millisecond
)

var (
	tcpConcurrent = atomic.NewBool(false)
)

func SetTcpConcurrent(concurrent bool) {
	tcpConcurrent.Store(concurrent)
}

func GetTcpConcurrent() bool {
	return tcpConcurrent.Load()
}

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	opt := applyOptions(options...)

	if opt.network == 4 || opt.network == 6 {
		if strings.Contains(network, "tcp") {
			network = "tcp"
		} else {
			network = "udp"
		}

		network = fmt.Sprintf("%s%d", network, opt.network)
	}

	if isTCPNetwork(network) && opt.directRace {
		host, _, splitErr := net.SplitHostPort(address)
		_, literalErr := netip.ParseAddr(host)
		if splitErr == nil && canUseProgressiveDirect(host) {
			preferResolver := opt.resolver
			if preferResolver == nil {
				preferResolver = resolver.ProxyServerHostResolver
			}
			if progressive, ok := preferResolver.(resolver.ProgressiveResolver); ok {
				opt.resolver = preferResolver
				return directProgressiveDialContext(ctx, network, address, opt, progressive)
			}
		}
		// Literal destinations use the ordinary single-address path below;
		// they have no DNS or address-family race requiring TFO suppression.
		if network == "tcp" && !GetTcpConcurrent() && literalErr != nil {
			return directDualStackDialContext(ctx, network, address, opt)
		}
	}

	ips, port, err := parseAddr(ctx, network, address, opt.resolver)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(address)

	tcpConcurrent := GetTcpConcurrent()

	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		var dialFn dialFunc = serialDialContext
		if tcpConcurrent {
			dialFn = parallelDialContext
		}
		var result dialResult
		if tcpConcurrent && strings.HasPrefix(network, "tcp") {
			result = tcpConcurrentDialContext(ctx, network, host, ips, port, opt, dialFn)
		} else {
			result = dialFn(ctx, network, ips, port, opt)
		}
		return result.Conn, result.error
	case "tcp", "udp":
		if tcpConcurrent {
			var fallback dialFunc = parallelDialContext
			if opt.prefer == 4 || opt.prefer == 6 {
				fallback = func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) dialResult {
					return dualStackDialContext(ctx, parallelDialContext, network, ips, port, opt)
				}
			}
			var result dialResult
			if network == "tcp" {
				result = tcpConcurrentDialContext(ctx, network, host, ips, port, opt, fallback)
			} else {
				result = fallback(ctx, network, ips, port, opt)
			}
			return result.Conn, result.error
		}
		result := dualStackDialContext(ctx, serialDialContext, network, ips, port, opt)
		return result.Conn, result.error
	default:
		return nil, ErrorInvalidedNetworkStack
	}
}

type lookupResult struct {
	version int
	ips     []netip.Addr
	err     error
}

// directDualStackDialContext overlaps A/AAAA lookup with real TCP connects.
// The first family with usable addresses starts immediately. When AAAA wins
// DNS, IPv6 gets the resolver's ipv6-timeout budget before IPv4 joins, unless
// every IPv6 connect has already failed. When A wins DNS, IPv4 starts without
// delay and AAAA may join until that same wait budget expires.
func directDualStackDialContext(ctx context.Context, network, address string, opt option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	preferResolver := opt.resolver
	if preferResolver == nil {
		preferResolver = resolver.ProxyServerHostResolver
	}
	// Keep the effective resolver on the option copy so its ipv6-timeout is
	// used even when the caller relied on the default resolver selection.
	opt.resolver = preferResolver

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	lookups := make(chan lookupResult, 2)
	lookup := func(version int) {
		var ips []netip.Addr
		var lookupErr error
		if version == 4 {
			ips, lookupErr = resolver.LookupIPv4WithResolver(raceCtx, host, preferResolver)
		} else {
			ips, lookupErr = resolver.LookupIPv6WithResolver(raceCtx, host, preferResolver)
		}
		ips = unmapAddrs(ips)
		ips = prioritizeDirectWinner(host, opt.directAdapter, ips)
		lookups <- lookupResult{version: version, ips: ips, err: lookupErr}
	}
	go lookup(4)
	go lookup(6)
	if opt.prefer == 4 || opt.prefer == 6 {
		return directPreferredDialContext(ctx, raceCtx, network, port, opt, lookups, opt.prefer)
	}

	var lookupErrs []error
	for completed := range 2 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-lookups:
			if result.err != nil || len(result.ips) == 0 {
				if result.err == nil {
					result.err = ErrorNoIpAddress
				}
				lookupErrs = append(lookupErrs, fmt.Errorf("dns resolve IPv%d failed: %w", result.version, result.err))
				continue
			}

			otherPending := completed == 0
			if result.version == 4 {
				return directIPv4First(ctx, raceCtx, network, port, opt, result.ips, lookups, otherPending, lookupErrs)
			}
			return directIPv6First(ctx, raceCtx, network, port, opt, result.ips, lookups, otherPending, lookupErrs)
		}
	}
	return nil, errors.Join(lookupErrs...)
}

// unmapAddrs returns ips with every 4-in-6 address unmapped, allocating a copy
// only when something actually has to change. The slice comes straight from a
// resolver and may be shared with state that outlives this call (a hosts
// entry, another concurrent lookup of the same name), so it must never be
// rewritten in place.
func unmapAddrs(ips []netip.Addr) []netip.Addr {
	for index, ip := range ips {
		unmapped := ip.Unmap()
		if unmapped == ip {
			continue
		}
		unmappedIPs := append([]netip.Addr(nil), ips...)
		for rest := index; rest < len(unmappedIPs); rest++ {
			unmappedIPs[rest] = unmappedIPs[rest].Unmap()
		}
		return unmappedIPs
	}
	return ips
}

func prioritizeDirectWinner(host, adapter string, ips []netip.Addr) []netip.Addr {
	preferred, loaded := directrace.Prefer(host, adapter, ips)
	if !loaded || len(ips) < 2 || ips[0] == preferred {
		return ips
	}
	ordered := append([]netip.Addr(nil), ips...)
	for index, ip := range ordered {
		if ip == preferred {
			copy(ordered[1:index+1], ordered[:index])
			ordered[0] = preferred
			break
		}
	}
	return ordered
}

func startDirectConnects(ctx context.Context, network, port string, opt option, ips []netip.Addr, isPrimary bool, results chan<- dialResult) int {
	// Every call here is part of a Happy-Eyeballs race (this family may
	// also be joined later by the other one), so a real synchronous connect
	// is required to know which candidate actually wins. The lazy TFO
	// dialer (tfo.go) reports success before any network I/O happens, which
	// would make "first done" just reflect goroutine scheduling and silently
	// drop the ability to skip a dead/blocked candidate. See the identical
	// rationale in parallelDialContext.
	opt.tfo = false
	for _, ip := range ips {
		go func(ip netip.Addr) {
			conn, err := dialContext(ctx, network, ip, port, opt)
			result := dialResult{ip: ip, Conn: conn, error: err, isPrimary: isPrimary}
			select {
			case results <- result:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}(ip)
	}
	return len(ips)
}

// directPreferredDialContext starts both address families as soon as their DNS
// answers arrive, but keeps the configured family preference when choosing the
// winner. A successful fallback connection is held ready instead of delaying
// its TCP handshake until the preferred family times out.
func directPreferredDialContext(ctx, raceCtx context.Context, network, port string, opt option, lookups <-chan lookupResult, preferredVersion int) (net.Conn, error) {
	connects := make(chan dialResult)
	var errs []error
	var fallback net.Conn
	var preferredPending, fallbackPending int
	var preferredLookupDone bool
	var preferredFailed, fallbackFailed bool
	var preferredAbandoned bool

	var lookupTimer, preferenceTimer *time.Timer
	var lookupTimeout, preferenceTimeout <-chan time.Time
	defer func() {
		if lookupTimer != nil {
			lookupTimer.Stop()
		}
		if preferenceTimer != nil {
			preferenceTimer.Stop()
		}
	}()

	closeFallback := func() {
		if fallback != nil {
			conn := fallback
			fallback = nil
			go func() { _ = conn.Close() }()
		}
	}
	returnFallback := func() (net.Conn, error) {
		conn := fallback
		fallback = nil
		return conn, nil
	}
	startPreferenceTimer := func() {
		if preferenceTimer == nil {
			preferenceTimer = time.NewTimer(dualStackFallbackTimeout)
			preferenceTimeout = preferenceTimer.C
		}
	}
	stopLookupTimer := func() {
		if lookupTimer != nil {
			lookupTimer.Stop()
			lookupTimeout = nil
		}
	}

	for {
		if (preferredFailed || preferredAbandoned) && fallback != nil {
			return returnFallback()
		}
		if (preferredFailed || preferredAbandoned) && fallbackFailed {
			return nil, errors.Join(errs...)
		}

		select {
		case <-ctx.Done():
			closeFallback()
			return nil, ctx.Err()
		case result := <-lookups:
			isPreferred := result.version == preferredVersion
			if isPreferred {
				preferredLookupDone = true
				stopLookupTimer()
			}

			if result.err != nil || len(result.ips) == 0 {
				if result.err == nil {
					result.err = ErrorNoIpAddress
				}
				errs = append(errs, fmt.Errorf("dns resolve IPv%d failed: %w", result.version, result.err))
				if isPreferred {
					preferredFailed = true
				} else {
					fallbackFailed = true
				}
				continue
			}

			if isPreferred {
				if preferredAbandoned {
					continue
				}
				preferredPending = startDirectConnects(raceCtx, network, port, opt, result.ips, true, connects)
				startPreferenceTimer()
			} else {
				fallbackPending = startDirectConnects(raceCtx, network, port, opt, result.ips, false, connects)
				if !preferredLookupDone && lookupTimer == nil {
					lookupTimer = time.NewTimer(resolver.IPv6Timeout(opt.resolver))
					lookupTimeout = lookupTimer.C
				}
			}
		case result := <-connects:
			if result.isPrimary {
				preferredPending--
				if result.error == nil {
					closeFallback()
					return result.Conn, nil
				}
				errs = append(errs, fmt.Errorf("connect %s failed: %w", result.ip, result.error))
				if preferredPending == 0 {
					preferredFailed = true
				}
				continue
			}

			fallbackPending--
			if result.error == nil {
				if fallback == nil {
					fallback = result.Conn
				} else {
					go func() { _ = result.Conn.Close() }()
				}
				if preferredFailed || preferredAbandoned || preferenceTimeout == nil && preferenceTimer != nil {
					return returnFallback()
				}
			} else {
				errs = append(errs, fmt.Errorf("connect %s failed: %w", result.ip, result.error))
			}
			if fallbackPending == 0 && fallback == nil {
				fallbackFailed = true
			}
		case <-lookupTimeout:
			lookupTimeout = nil
			preferredAbandoned = true
			if fallback != nil {
				return returnFallback()
			}
		case <-preferenceTimeout:
			preferenceTimeout = nil
			if fallback != nil {
				return returnFallback()
			}
		}
	}
}

func receiveDirectConnect(result dialResult, pending *int, errs *[]error) net.Conn {
	*pending--
	if result.error == nil {
		return result.Conn
	}
	*errs = append(*errs, fmt.Errorf("connect %s failed: %w", result.ip, result.error))
	return nil
}

func directIPv4First(ctx, raceCtx context.Context, network, port string, opt option, ipv4s []netip.Addr, lookups <-chan lookupResult, ipv6Pending bool, errs []error) (net.Conn, error) {
	connects := make(chan dialResult)
	pending := startDirectConnects(raceCtx, network, port, opt, ipv4s, true, connects)
	if !ipv6Pending {
		return waitDirectConnects(ctx, connects, pending, errs)
	}

	timer := time.NewTimer(resolver.IPv6Timeout(opt.resolver))
	defer timer.Stop()
	timeout := timer.C
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-connects:
			if conn := receiveDirectConnect(result, &pending, &errs); conn != nil {
				return conn, nil
			}
			// Even after all IPv4 attempts fail, AAAA still owns the configured
			// wait budget and may enter the race before it expires.
		case result := <-lookups:
			if result.err != nil || len(result.ips) == 0 {
				if result.err == nil {
					result.err = ErrorNoIpAddress
				}
				errs = append(errs, fmt.Errorf("dns resolve IPv6 failed: %w", result.err))
				return waitDirectConnects(ctx, connects, pending, errs)
			}
			pending += startDirectConnects(raceCtx, network, port, opt, result.ips, true, connects)
			return waitDirectConnects(ctx, connects, pending, errs)
		case <-timeout:
			if pending > 0 {
				return waitDirectConnects(ctx, connects, pending, errs)
			}
			// The wait budget only decides how long AAAA may delay a live
			// IPv4 race. With every IPv4 attempt already failed there is
			// nothing left to protect, and returning here would fail a
			// connection the outstanding AAAA answer can still complete, so
			// keep waiting for that answer instead (ctx still bounds it).
			timeout = nil
		}
	}
}

func directIPv6First(ctx, raceCtx context.Context, network, port string, opt option, ipv6s []netip.Addr, lookups <-chan lookupResult, ipv4Pending bool, errs []error) (net.Conn, error) {
	connects := make(chan dialResult)
	pending := startDirectConnects(raceCtx, network, port, opt, ipv6s, true, connects)
	if !ipv4Pending {
		return waitDirectConnects(ctx, connects, pending, errs)
	}

	timer := time.NewTimer(resolver.IPv6Timeout(opt.resolver))
	defer timer.Stop()
	var ipv4 lookupResult
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-connects:
			if conn := receiveDirectConnect(result, &pending, &errs); conn != nil {
				return conn, nil
			}
			if pending == 0 {
				return directIPv4Fallback(ctx, raceCtx, network, port, opt, connects, pending, lookups, ipv4, errs)
			}
		case result := <-lookups:
			ipv4 = result
			lookups = nil
		case <-timer.C:
			return directIPv4Fallback(ctx, raceCtx, network, port, opt, connects, pending, lookups, ipv4, errs)
		}
	}
}

func directIPv4Fallback(ctx, raceCtx context.Context, network, port string, opt option, connects chan dialResult, pending int, lookups <-chan lookupResult, ipv4 lookupResult, errs []error) (net.Conn, error) {
	for lookups != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-connects:
			// A still-pending IPv6 attempt can win while the A answer is
			// outstanding. Blocking only on the lookup would hold a ready
			// connection hostage to a slow or dead A query, for up to the
			// whole DNS timeout.
			if conn := receiveDirectConnect(result, &pending, &errs); conn != nil {
				return conn, nil
			}
		case ipv4 = <-lookups:
			lookups = nil
		}
	}
	if ipv4.err != nil || len(ipv4.ips) == 0 {
		if ipv4.err == nil {
			ipv4.err = ErrorNoIpAddress
		}
		errs = append(errs, fmt.Errorf("dns resolve IPv4 failed: %w", ipv4.err))
		return waitDirectConnects(ctx, connects, pending, errs)
	}
	pending += startDirectConnects(raceCtx, network, port, opt, ipv4.ips, true, connects)
	return waitDirectConnects(ctx, connects, pending, errs)
}

func waitDirectConnects(ctx context.Context, results <-chan dialResult, pending int, errs []error) (net.Conn, error) {
	for pending > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if conn := receiveDirectConnect(result, &pending, &errs); conn != nil {
				return conn, nil
			}
		}
	}
	return nil, errors.Join(errs...)
}

func ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort, options ...Option) (net.PacketConn, error) {
	opt := applyOptions(options...)

	lc, address, err := listenConfig(network, address, rAddrPort, opt)
	if err != nil {
		return nil, err
	}
	return lc.ListenPacket(ctx, network, address)
}

// Listen creates a TCP listener with the same socket policy as ListenPacket.
func Listen(ctx context.Context, network, address string, options ...Option) (net.Listener, error) {
	lc, address, err := listenConfig(network, address, netip.AddrPort{}, applyOptions(options...))
	if err != nil {
		return nil, err
	}
	return lc.Listen(ctx, network, address)
}

func listenConfig(network, address string, rAddrPort netip.AddrPort, opt option) (*net.ListenConfig, string, error) {
	lc := &net.ListenConfig{}
	if opt.addrReuse {
		addrReuseToListenConfig(lc)
	}
	if opt.dontFragment {
		dontFragmentToListenConfig(lc)
	}
	if DefaultSocketHook != nil { // ignore interfaceName, routingMark when DefaultSocketHook not null (in CMFA)
		socketHookToListenConfig(lc)
	} else {
		if opt.interfaceName == "" {
			opt.interfaceName = DefaultInterface.Load()
		}
		if opt.interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				opt.interfaceName = finder.FindInterfaceName(rAddrPort.Addr().Unmap())
			}
		}
		if rAddrPort.Addr().Unmap().IsLoopback() || listenAddressIsLoopback(address) {
			// avoid "The requested address is not valid in its context."
			opt.interfaceName = ""
		}
		if opt.interfaceName != "" {
			bind := bindIfaceToListenConfig
			if opt.fallbackBind {
				bind = fallbackBindIfaceToListenConfig
			}
			addr, err := bind(opt.interfaceName, lc, network, address, rAddrPort)
			if err != nil {
				return nil, "", err
			}
			address = addr
		}
		if opt.routingMark == 0 {
			opt.routingMark = int(DefaultRoutingMark.Load())
		}
		if opt.routingMark != 0 {
			bindMarkToListenConfig(opt.routingMark, lc, network, address)
		}
	}

	return lc, address, nil
}

// tfoDialIsAsynchronous reports whether dialContext, under these options,
// hands back a connection before the real TCP handshake happens. That is
// the case for the lazy TFO dialer (tfo.go's dialTFO/tfoConn): it returns a
// stub immediately and only performs the actual connect+early-data write on
// the caller's first Write, keeping the exact condition dialContext itself
// uses to pick that path. Wall-clock timing around such a dialContext call
// measures stub construction, not network latency, and must not be used as
// an RTT sample (see tcpConcurrentDialContext and parallelDialContext).
func tfoDialIsAsynchronous(opt option) bool {
	if DefaultSocketHook != nil || !opt.tfo || DisableTFO {
		return false
	}
	switch opt.netDialer.(type) {
	case nil, *net.Dialer:
		return true
	default:
		return false // Custom dialers bypass dialTFO in dialContext.
	}
}

// joinAddrPort formats destination:port the same way
// net.JoinHostPort(destination.String(), port) does, but with a single
// allocation instead of one for the address text and another for the join.
// Every racing candidate of every DIRECT dial goes through here.
func joinAddrPort(destination netip.Addr, port string) string {
	if !destination.IsValid() {
		// AppendTo writes nothing for the zero Addr; keep the caller-visible
		// text identical to the old formatting so error messages don't change.
		return net.JoinHostPort(destination.String(), port)
	}
	var buf [64]byte
	b := buf[:0]
	if destination.Is6() {
		// Matches JoinHostPort's rule: anything whose text can contain ':'
		// or a '%' zone has to be bracketed. That is every 16-byte address,
		// including the "::ffff:1.2.3.4" form of a 4-in-6 address, and
		// nothing else (an invalid Addr prints as plain text).
		b = append(b, '[')
		b = destination.AppendTo(b)
		b = append(b, ']')
	} else {
		b = destination.AppendTo(b)
	}
	b = append(b, ':')
	b = append(b, port...)
	return string(b)
}

func dialContext(ctx context.Context, network string, destination netip.Addr, port string, opt option) (net.Conn, error) {
	destination, port = resolver.LookupIP4P(destination, port)
	address := joinAddrPort(destination, port)

	netDialer := opt.netDialer
	switch netDialer.(type) {
	case nil:
		netDialer = &net.Dialer{}
	case *net.Dialer:
		_netDialer := *netDialer.(*net.Dialer)
		netDialer = &_netDialer // make a copy
	default:
		return netDialer.DialContext(ctx, network, address)
	}

	dialer := netDialer.(*net.Dialer)
	keepalive.SetNetDialer(dialer)
	mptcp.SetNetDialer(dialer, opt.mpTcp)

	if DefaultSocketHook != nil { // ignore interfaceName, routingMark and tfo when DefaultSocketHook not null (in CMFA)
		socketHookToToDialer(dialer)
	} else {
		if opt.interfaceName == "" {
			opt.interfaceName = DefaultInterface.Load()
		}
		if opt.interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				opt.interfaceName = finder.FindInterfaceName(destination)
			}
		}
		if opt.interfaceName != "" {
			bind := bindIfaceToDialer
			if opt.fallbackBind {
				bind = fallbackBindIfaceToDialer
			}
			if err := bind(opt.interfaceName, dialer, network, destination); err != nil {
				return nil, err
			}
		}
		if opt.routingMark == 0 {
			opt.routingMark = int(DefaultRoutingMark.Load())
		}
		if opt.routingMark != 0 {
			bindMarkToDialer(opt.routingMark, dialer, network, destination)
		}
		if opt.tfo && !DisableTFO {
			return dialTFO(ctx, *dialer, network, address)
		}
	}

	return dialer.DialContext(ctx, network, address)
}

func ICMPControl(destination netip.Addr) func(network, address string, conn syscall.RawConn) error {
	return ICMPControlWithOptions(destination)
}

func ICMPControlWithOptions(destination netip.Addr, options ...Option) func(network, address string, conn syscall.RawConn) error {
	opt := applyOptions(options...)
	return func(network, address string, conn syscall.RawConn) error {
		if DefaultSocketHook != nil {
			return DefaultSocketHook(network, address, conn)
		}
		dialer := &net.Dialer{}
		interfaceName := opt.interfaceName
		if interfaceName == "" {
			interfaceName = DefaultInterface.Load()
		}
		if interfaceName == "" {
			if finder := DefaultInterfaceFinder.Load(); finder != nil {
				interfaceName = finder.FindInterfaceName(destination)
			}
		}
		if interfaceName != "" {
			if err := bindIfaceToDialer(interfaceName, dialer, network, destination); err != nil {
				return err
			}
		}
		routingMark := opt.routingMark
		if routingMark == 0 {
			routingMark = int(DefaultRoutingMark.Load())
		}
		if routingMark != 0 {
			bindMarkToDialer(routingMark, dialer, network, destination)
		}
		if dialer.ControlContext != nil {
			return dialer.ControlContext(context.TODO(), network, address, conn)
		}
		return nil
	}
}

type dialFunc func(ctx context.Context, network string, ips []netip.Addr, port string, opt option) dialResult

func dualStackDialContext(ctx context.Context, dialFn dialFunc, network string, ips []netip.Addr, port string, opt option) dialResult {
	ipv4s, ipv6s := resolver.SortationAddr(ips)
	if len(ipv4s) == 0 && len(ipv6s) == 0 {
		return dialResult{error: ErrorNoIpAddress}
	}
	if len(ipv4s) == 0 && len(ipv6s) != 0 {
		return dialFn(ctx, network, ipv6s, port, opt)
	}
	if len(ipv4s) != 0 && len(ipv6s) == 0 {
		return dialFn(ctx, network, ipv4s, port, opt)
	}
	// Both families compete, even if each contains only one address.
	// Lazy TFO must not report a winner before either handshake completes.
	opt.tfo = false

	preferIPVersion := opt.prefer
	fallbackTicker := time.NewTicker(dualStackFallbackTimeout)
	defer fallbackTicker.Stop()

	results := make(chan dialResult)
	returned := make(chan struct{})
	defer close(returned)

	var wg sync.WaitGroup

	racer := func(ips []netip.Addr, isPrimary bool) {
		defer wg.Done()
		result := dialFn(ctx, network, ips, port, opt)
		result.isPrimary = isPrimary
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil && result.error == nil {
					_ = result.Conn.Close()
				}
			}
		}()
	}

	if len(ipv4s) != 0 {
		wg.Add(1)
		go racer(ipv4s, preferIPVersion != 6)
	}

	if len(ipv6s) != 0 {
		wg.Add(1)
		go racer(ipv6s, preferIPVersion != 4)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var fallback dialResult
	var errs []error

loop:
	for {
		select {
		case <-fallbackTicker.C:
			if fallback.error == nil && fallback.Conn != nil {
				return fallback
			}
		case res, ok := <-results:
			if !ok {
				break loop
			}
			if res.error == nil {
				if res.isPrimary {
					if fallback.error == nil && fallback.Conn != nil {
						go func() { // close fallback connection in new goroutine to avoid blocking
							_ = fallback.Conn.Close()
						}()
					}
					return res
				}
				fallback = res
			} else {
				if res.isPrimary {
					errs = append([]error{fmt.Errorf("connect failed: %w", res.error)}, errs...)
				} else {
					errs = append(errs, fmt.Errorf("connect failed: %w", res.error))
				}
			}
		}
	}

	if fallback.error == nil && fallback.Conn != nil {
		return fallback
	}
	return dialResult{error: errors.Join(errs...)}
}

func parallelDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt option) dialResult {
	if len(ips) == 0 {
		return dialResult{error: ErrorNoIpAddress}
	}
	if len(ips) == 1 {
		return serialDialContext(ctx, network, ips, port, opt)
	}
	// Only competing candidates require synchronous handshakes. A single
	// destination keeps TFO, whose lazy dial must not be timed as an RTT.
	opt.tfo = false

	results := make(chan dialResult)
	returned := make(chan struct{})
	defer close(returned)
	racer := func(ctx context.Context, ip netip.Addr) {
		start := time.Now()
		result := dialResult{isPrimary: true, ip: ip}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil && result.error == nil {
					_ = result.Conn.Close()
				}
			}
		}()
		result.Conn, result.error = dialContext(ctx, network, ip, port, opt)
		result.dialDuration = measuredDialDuration(start)
	}

	for _, ip := range ips {
		go racer(ctx, ip)
	}
	var errs []error
	for range ips {
		res := <-results
		if res.error == nil {
			return res
		}
		errs = append(errs, res.error)
	}

	if len(errs) > 0 {
		return dialResult{error: errors.Join(errs...)}
	}
	return dialResult{error: os.ErrDeadlineExceeded}
}

func serialDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt option) dialResult {
	if len(ips) == 0 {
		return dialResult{error: ErrorNoIpAddress}
	}
	measureLatency := !tfoDialIsAsynchronous(opt)
	var errs []error
	for _, ip := range ips {
		start := time.Now()
		if conn, err := dialContext(ctx, network, ip, port, opt); err == nil {
			result := dialResult{ip: ip, Conn: conn}
			if measureLatency {
				result.dialDuration = measuredDialDuration(start)
			}
			return result
		} else {
			errs = append(errs, err)
		}
	}
	return dialResult{error: errors.Join(errs...)}
}

// measuredDialDuration reports how long a real connect took, floored at one
// nanosecond so that a genuinely instant dial stays distinguishable from one
// that was never timed at all.
//
// Every consumer of dialDuration reads a zero value as "no sample": the lazy
// TFO dialer returns a stub before any network I/O, so timing it measures
// nothing. Windows' monotonic clock is coarse enough that time.Since across a
// fast connect routinely returns exactly 0, which without this floor makes a
// real measurement indistinguishable from that sentinel -- and the winner is
// then either dropped or replaced by a wall-clock span that includes unrelated
// waiting.
func measuredDialDuration(start time.Time) time.Duration {
	return max(time.Since(start), time.Nanosecond)
}

type dialResult struct {
	ip netip.Addr
	net.Conn
	error
	isPrimary bool
	// dialDuration is how long the winning dialContext call itself took,
	// measured at the point of the actual connect attempt. Kept separate
	// from any time a caller (e.g. dualStackDialContext's fallback-hold
	// window) spends sitting on an already-completed result, so RTT
	// samples derived from it aren't inflated by unrelated waiting.
	dialDuration time.Duration
}

func parseAddr(ctx context.Context, network, address string, preferResolver resolver.Resolver) ([]netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, "-1", err
	}

	if preferResolver == nil {
		preferResolver = resolver.ProxyServerHostResolver
	}

	var ips []netip.Addr
	switch network {
	case "tcp4", "udp4":
		ips, err = resolver.LookupIPv4WithResolver(ctx, host, preferResolver)
	case "tcp6", "udp6":
		ips, err = resolver.LookupIPv6WithResolver(ctx, host, preferResolver)
	default:
		ips, err = resolver.LookupIPWithResolver(ctx, host, preferResolver)
	}
	if err != nil {
		return nil, "-1", fmt.Errorf("dns resolve failed: %w", err)
	}
	for i, ip := range ips {
		if ip.Is4In6() {
			ips[i] = ip.Unmap()
		}
	}
	return ips, port, nil
}

func listenAddressIsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.Unmap().IsLoopback()
}

type Dialer struct {
	Opt option
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address, WithOption(d.Opt))
}

func (d Dialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return ListenPacket(ctx, ParseNetwork(network, rAddrPort.Addr()), address, rAddrPort, WithOption(d.Opt))
}

func NewDialer(options ...Option) Dialer {
	opt := applyOptions(options...)
	return Dialer{Opt: opt}
}
