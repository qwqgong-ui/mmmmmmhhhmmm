package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/diagstats"
	R "github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

type progressiveCandidateEvent struct {
	R.IPCandidateBatch
	ipv6 bool
	done bool
}

type progressiveConnectResult struct {
	dialResult
	ipv6 bool
	rtt  time.Duration
	fast bool
}

func canUseProgressiveDirect(host string) bool {
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	_, static := R.DefaultHosts.Search(host, false)
	return !static
}

func directProgressiveDialContext(ctx context.Context, network, address string, opt option, progressive R.ProgressiveResolver) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	scope := directNetworkScope(opt)
	cacheKey, cacheable := tcpConcurrentPathKey(host, port, network, scope, opt)
	if !cacheable {
		cacheKey = ""
	}

	workCtx, cancelWork := context.WithTimeout(context.Background(), R.DefaultDNSTimeout+DefaultTCPTimeout)
	// An unbuffered handoff transfers ownership only while the caller is here.
	// A successful dial arriving after cancellation must close its connection.
	resultCh := make(chan dialResult)
	go runProgressiveDirectRace(workCtx, cancelWork, resultCh, network, host, port, scope, opt, progressive, cacheKey)
	select {
	case result := <-resultCh:
		return result.Conn, result.error
	case <-ctx.Done():
		cancelWork()
		return nil, ctx.Err()
	case <-workCtx.Done():
		return nil, workCtx.Err()
	}
}

func runProgressiveDirectRace(
	ctx context.Context,
	cancel context.CancelFunc,
	resultCh chan<- dialResult,
	network, host, port, scope string,
	opt option,
	progressive R.ProgressiveResolver,
	cacheKey string,
) {
	defer cancel()

	sendResult := func(result dialResult) {
		select {
		case resultCh <- result:
		case <-ctx.Done():
			if result.Conn != nil {
				_ = result.Conn.Close()
			}
		}
	}

	events := make(chan progressiveCandidateEvent, 8)
	feed := func(ipv6 bool) {
		for batch := range progressive.LookupIPCandidates(ctx, host, ipv6, scope) {
			select {
			case events <- progressiveCandidateEvent{IPCandidateBatch: batch, ipv6: ipv6}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case events <- progressiveCandidateEvent{ipv6: ipv6, done: true}:
		case <-ctx.Done():
		}
	}

	families := 0
	var startedFamily [2]bool
	if network != "tcp6" {
		families++
		startedFamily[0] = true
		go feed(false)
	}
	if network != "tcp4" && !R.DisableIPv6.Load() {
		families++
		startedFamily[1] = true
		go feed(true)
	}
	if families == 0 {
		sendResult(dialResult{error: ErrorNoIpAddress})
		return
	}
	connects := make(chan progressiveConnectResult)
	seen := make(map[netip.Addr]struct{})
	pending := 0
	var pendingFamily [2]int
	doneFamilies := 0
	var doneFamily [2]bool
	var errs []error
	var bestRTT time.Duration
	var delivered bool
	var heldFallback net.Conn
	preferredIPv6 := opt.prefer == 6
	preferenceEnabled := opt.prefer == 4 || opt.prefer == 6
	var preferenceTimer *time.Timer
	var preferenceTimeout <-chan time.Time
	type queuedCandidate struct {
		ip   netip.Addr
		ipv6 bool
	}
	var queued []queuedCandidate
	var cachedWinners []tcpConcurrentWinner
	cachedIPv6 := false
	cachePending := false
	if cacheKey != "" && GetTcpConcurrent() {
		cachedWinners, cachePending = tcpConcurrentCache.Winners(cacheKey)
		if cachePending {
			diagstats.Add(diagstats.DirectWinnerHit)
		} else {
			diagstats.Add(diagstats.DirectWinnerMiss)
		}
		if log.Enabled(log.DEBUG) {
			log.Fields(log.DEBUG, map[string]string{"subsystem": "direct", "event": "winner_cache_lookup", "host": host, "network_scope": scope}, "DIRECT TCP %s:%s cached winners=%+v", host, port, cachedWinners)
		}
		if cachePending {
			cachedWinners = slices.DeleteFunc(cachedWinners, func(winner tcpConcurrentWinner) bool {
				return winner.IP.Is4() && network == "tcp6" ||
					winner.IP.Is6() && (network == "tcp4" || R.DisableIPv6.Load())
			})
			if len(cachedWinners) == 0 {
				// Keep retained hints for other families and pending DNS sources.
				cachePending = false
			} else {
				// The fast path is armed by one family's DNS batch, and a
				// winner of the other family cannot be validated against it,
				// so the slower family's winners stay ordinary candidates.
				cachedIPv6 = cachedWinners[0].IP.Is6()
				cachedWinners = slices.DeleteFunc(cachedWinners, func(winner tcpConcurrentWinner) bool {
					return winner.IP.Is6() != cachedIPv6
				})
			}
		}
	}
	// fastInFlight holds the cached winners currently being dialed under the
	// fast path's shared budget.
	var fastInFlight []netip.Addr
	fastPriority := false
	fastSucceeded := false
	var fastTimer *time.Timer
	var fastTimeout <-chan time.Time

	deliver := func(conn net.Conn, ip netip.Addr) {
		if delivered {
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
		delivered = true
		if log.Enabled(log.DEBUG) {
			log.Fields(log.DEBUG, map[string]string{"subsystem": "direct", "event": "tcp_winner", "host": host, "network_scope": scope}, "DIRECT TCP %s:%s first delivered winner=%s", host, port, ip)
		}
		sendResult(dialResult{ip: ip, Conn: conn})
	}
	promote := func(result progressiveConnectResult) {
		if result.rtt <= 0 {
			return
		}
		// Every candidate that connected is offered to the winner cache, not
		// only the ones that beat the best so far. The runner-up is exactly
		// what the fast path needs to race when the best address goes dead,
		// and recording improvements alone would leave that slot empty: in a
		// race, results tend to arrive fastest first, so nothing after the
		// opening result would ever qualify.
		tcpConcurrentCache.SetIfFaster(cacheKey, result.ip, result.rtt)
		if bestRTT > 0 && result.rtt >= bestRTT {
			return
		}
		bestRTT = result.rtt
		// The DNS answer still names one address, so it only follows the
		// genuine winner.
		progressive.PromoteIP(host, result.ipv6, scope, result.ip)
	}
	start := func(ip netip.Addr, ipv6 bool) {
		ip = ip.Unmap()
		if !ip.IsValid() {
			return
		}
		if _, loaded := seen[ip]; loaded {
			return
		}
		seen[ip] = struct{}{}
		pending++
		family := 0
		if ipv6 {
			family = 1
		}
		pendingFamily[family]++
		go func() {
			connectOpt := opt
			connectOpt.tfo = false
			started := time.Now()
			conn, err := dialContext(ctx, network, ip, port, connectOpt)
			logDirectAttempt(host, port, scope, ip, time.Since(started), err, false)
			result := progressiveConnectResult{
				dialResult: dialResult{ip: ip, Conn: conn, error: err},
				ipv6:       ipv6,
				rtt:        measuredDialDuration(started),
			}
			select {
			case connects <- result:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}
	startQueued := func() {
		for _, candidate := range queued {
			start(candidate.ip, candidate.ipv6)
		}
		queued = nil
	}
	stopFastTimer := func() {
		fastTimeout = nil
		if fastTimer == nil {
			return
		}
		if !fastTimer.Stop() {
			select {
			case <-fastTimer.C:
			default:
			}
		}
		fastTimer = nil
	}
	// startFastGroup dials every cached winner at once under one shared
	// budget. Trying them in turn would make a dead first winner cost its
	// whole budget before the second one is even started, which is exactly
	// the case the second winner exists for; racing them costs one extra
	// connect and settles in the time of whichever answers first.
	//
	// The attempts are tied to the race context rather than a private one, so
	// an expired budget releases the remaining candidates without destroying
	// connects that may still be about to complete.
	startFastGroup := func(winners []tcpConcurrentWinner, ipv6 bool) {
		fastPriority = true
		fastInFlight = fastInFlight[:0]
		budget := time.Duration(0)
		family := 0
		if ipv6 {
			family = 1
		}
		for _, winner := range winners {
			// The budget covers the group, so it follows the slowest member:
			// a faster winner's sample says nothing about when the others
			// should be given up on.
			budget = max(budget, fastPathTimeoutFor(winner.RTT))
			fastInFlight = append(fastInFlight, winner.IP)
			seen[winner.IP] = struct{}{}
			pending++
			pendingFamily[family]++
			go func() {
				connectOpt := opt
				connectOpt.tfo = false
				started := time.Now()
				conn, err := dialContext(ctx, network, winner.IP, port, connectOpt)
				logDirectAttempt(host, port, scope, winner.IP, time.Since(started), err, true)
				result := progressiveConnectResult{
					dialResult: dialResult{ip: winner.IP, Conn: conn, error: err},
					ipv6:       ipv6,
					rtt:        measuredDialDuration(started),
					fast:       true,
				}
				select {
				case connects <- result:
				case <-ctx.Done():
					if conn != nil {
						_ = conn.Close()
					}
				}
			}()
		}
		if log.Enabled(log.DEBUG) {
			log.Fields(log.DEBUG, map[string]string{"subsystem": "direct", "event": "race_budget", "host": host, "network_scope": scope}, "DIRECT TCP %s:%s cached race budget=%s winners=%+v", host, port, budget, winners)
		}
		fastTimer = time.NewTimer(budget)
		fastTimeout = fastTimer.C
	}
	// abandonFastPath stops holding candidates back for the cached winners
	// and releases everything queued behind them. Attempts already in flight
	// keep running: an expired budget is not evidence that a connect failed,
	// and cancelling it throws away the round trip already spent.
	abandonFastPath := func() {
		cachePending = false
		fastPriority = false
		fastInFlight = nil
		stopFastTimer()
		startQueued()
	}
	preferredDone := func() bool {
		if !preferenceEnabled {
			return true
		}
		family := 0
		if preferredIPv6 {
			family = 1
		}
		return !startedFamily[family] || doneFamily[family] && pendingFamily[family] == 0
	}

	for {
		if doneFamilies == families && pending == 0 {
			if !delivered {
				if heldFallback != nil {
					deliver(heldFallback, netip.Addr{})
					heldFallback = nil
				} else {
					err := errors.Join(errs...)
					if err == nil {
						err = ErrorNoIpAddress
					}
					sendResult(dialResult{error: err})
				}
			}
			return
		}
		select {
		case <-ctx.Done():
			if heldFallback != nil {
				_ = heldFallback.Close()
			}
			if !delivered {
				sendResult(dialResult{error: ctx.Err()})
			}
			return
		case event := <-events:
			if !event.done && log.Enabled(log.DEBUG) {
				log.Fields(log.DEBUG, map[string]string{"subsystem": "direct", "event": "candidates", "host": host, "network_scope": scope}, "DIRECT TCP candidates source=%d ips=%v error=%v", event.Source, event.IPs, event.Err)
			}
			if event.done {
				if cachePending && event.ipv6 == cachedIPv6 {
					// That family produced nothing to validate the winners
					// against, so they cannot be trusted for this network.
					// Keep retained hints for other families and pending DNS sources.
					abandonFastPath()
				}
				doneFamilies++
				if event.ipv6 {
					doneFamily[1] = true
				} else {
					doneFamily[0] = true
				}
				if heldFallback != nil && preferredDone() && !delivered {
					deliver(heldFallback, netip.Addr{})
					heldFallback = nil
				}
				continue
			}
			if event.Err != nil {
				errs = append(errs, event.Err)
				continue
			}
			if fastSucceeded {
				continue
			}
			if cachePending || fastPriority {
				for _, ip := range event.IPs {
					queued = append(queued, queuedCandidate{ip: ip, ipv6: event.ipv6})
				}
				if cachePending && event.ipv6 == cachedIPv6 {
					cachePending = false
					// Only winners this answer still names are worth a
					// dedicated budget; the rest are stale.
					fastWinners := slices.DeleteFunc(cachedWinners, func(winner tcpConcurrentWinner) bool {
						return !containsTCPConcurrentCandidate(event.IPs, winner.IP)
					})
					if len(fastWinners) > 0 {
						log.Debugln("[TCP] progressive direct cache hit %s:%s --> %s (%d cached winner(s))",
							host, port, fastWinners[0].IP, len(fastWinners))
						startFastGroup(fastWinners, event.ipv6)
					} else {
						log.Debugln("[TCP] progressive direct cache expired %s:%s; racing current candidates", host, port)
						// Keep retained hints for other families and pending DNS sources.
						abandonFastPath()
					}
				}
				continue
			}
			for _, ip := range event.IPs {
				start(ip, event.ipv6)
			}
		case result := <-connects:
			pending--
			if result.ipv6 {
				pendingFamily[1]--
			} else {
				pendingFamily[0]--
			}
			if result.fast {
				// A fast attempt whose budget already expired still counts:
				// it kept running, so a late success is a real connection and
				// a late failure still condemns that winner.
				fastInFlight = slices.DeleteFunc(fastInFlight, func(ip netip.Addr) bool {
					return ip == result.ip
				})
				if result.error != nil {
					log.Debugln("[TCP] progressive direct cached connect failed %s:%s --> %s: %v", host, port, result.ip, result.error)
					errs = append(errs, fmt.Errorf("cached connect %s failed: %w", result.ip, result.error))
					tcpConcurrentCache.Backoff(cacheKey, result.ip)
					// Only the last cached winner to fail releases the field:
					// while another is still dialing, it may yet answer.
					if fastPriority && len(fastInFlight) == 0 {
						abandonFastPath()
					}
					continue
				}
				fastSucceeded = true
				queued = nil
				fastPriority = false
				// The budget keeps running even though the destination is
				// settled: a winner that never answers would otherwise stay
				// cached forever, costing a wasted connect on every dial,
				// because a black hole never reports an error to remove it.
				log.Debugln("[TCP] progressive direct cached connect ready %s:%s --> %s in %s", host, port, result.ip, result.rtt)
				promote(result)
				deliver(result.Conn, result.ip)
				continue
			}
			if result.error != nil {
				errs = append(errs, fmt.Errorf("connect %s failed: %w", result.ip, result.error))
				if heldFallback != nil && preferredDone() && !delivered {
					deliver(heldFallback, netip.Addr{})
					heldFallback = nil
				}
				continue
			}
			promote(result)
			if delivered {
				_ = result.Conn.Close()
				continue
			}
			isPreferred := !preferenceEnabled || result.ipv6 == preferredIPv6
			if isPreferred {
				if heldFallback != nil {
					_ = heldFallback.Close()
					heldFallback = nil
				}
				deliver(result.Conn, result.ip)
				continue
			}
			if heldFallback == nil {
				heldFallback = result.Conn
				preferenceTimer = time.NewTimer(dualStackFallbackTimeout)
				preferenceTimeout = preferenceTimer.C
			} else {
				_ = result.Conn.Close()
			}
			if preferredDone() {
				deliver(heldFallback, result.ip)
				heldFallback = nil
			}
		case <-preferenceTimeout:
			preferenceTimeout = nil
			if heldFallback != nil && !delivered {
				deliver(heldFallback, netip.Addr{})
				heldFallback = nil
			}
		case <-fastTimeout:
			// Whatever has not answered by now does not deserve to be tried
			// first again, whether or not one of its peers already won.
			for _, ip := range fastInFlight {
				tcpConcurrentCache.Backoff(cacheKey, ip)
			}
			if !fastPriority {
				stopFastTimer()
				fastInFlight = nil
				continue
			}
			log.Debugln("[TCP] progressive direct cached connect timeout %s:%s --> %s; racing current candidates",
				host, port, fastInFlight)
			abandonFastPath()
		}
	}
}

func isTCPNetwork(network string) bool {
	return strings.HasPrefix(network, "tcp")
}
