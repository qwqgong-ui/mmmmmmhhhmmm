package dialer

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// Expiring the historical budget releases other candidates. It is not a
// connection failure: retain in-flight work and try each current address once.
func tcpRetainedDialContext(ctx context.Context, network string, ips []netip.Addr, port string, opt option, key string, winners []tcpConcurrentWinner) dialResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult)
	seen := make(map[netip.Addr]bool)
	inFlight := make(map[netip.Addr]bool)
	var pendingFamily [2]int
	pending := 0
	family := func(ip netip.Addr) int {
		if ip.Is6() {
			return 1
		}
		return 0
	}
	start := func(ip netip.Addr, connectOpt option) {
		ip = ip.Unmap()
		if seen[ip] || ctx.Err() != nil {
			return
		}
		seen[ip], inFlight[ip] = true, true
		pending++
		pendingFamily[family(ip)]++
		go func() {
			started := time.Now()
			conn, err := dialContext(ctx, network, ip, port, connectOpt)
			result := dialResult{ip: ip, Conn: conn, error: err}
			if !tfoDialIsAsynchronous(connectOpt) {
				result.dialDuration = measuredDialDuration(started)
			}
			select {
			case results <- result:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}
	fastOpt := opt
	if len(winners) > 1 {
		fastOpt.tfo = false
	}
	var budget time.Duration
	for _, winner := range winners {
		budget = max(budget, fastPathTimeoutFor(winner.RTT))
		start(winner.IP, fastOpt)
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	budgetC := timer.C
	fullRace := false
	var preferenceTimer *time.Timer
	var preferenceC <-chan time.Time
	preferenceExpired := false
	startRemaining := func() {
		fullRace = true
		budgetC = nil
		timer.Stop()
		if opt.prefer == 4 || opt.prefer == 6 {
			preferenceTimer = time.NewTimer(dualStackFallbackTimeout)
			preferenceC = preferenceTimer.C
		}
		connectOpt := opt
		connectOpt.tfo = false
		for _, ip := range ips {
			start(ip, connectOpt)
		}
	}
	preferred := 0
	if opt.prefer == 6 {
		preferred = 1
	}
	preference := opt.prefer == 4 || opt.prefer == 6
	var held *dialResult
	defer func() {
		if held != nil && held.Conn != nil {
			_ = held.Conn.Close()
		}
	}()
	defer func() {
		if preferenceTimer != nil {
			preferenceTimer.Stop()
		}
	}()
	finish := func(result dialResult) dialResult {
		tcpConcurrentCache.SetWithRTT(key, result.ip, result.dialDuration)
		return result
	}
	finishHeld := func() dialResult { result := *held; held = nil; return finish(result) }
	var errs []error
	for {
		if ctx.Err() != nil {
			return dialResult{error: ctx.Err()}
		}
		if fullRace && held != nil && pendingFamily[preferred] == 0 {
			return finishHeld()
		}
		if pending == 0 {
			if !fullRace {
				startRemaining()
				continue
			}
			if held != nil {
				return finishHeld()
			}
			return dialResult{error: errors.Join(errs...)}
		}
		select {
		case <-ctx.Done():
			return dialResult{error: ctx.Err()}
		case <-budgetC:
			if ctx.Err() != nil {
				return dialResult{error: ctx.Err()}
			}
			for _, winner := range winners {
				if inFlight[winner.IP.Unmap()] {
					tcpConcurrentCache.Backoff(key, winner.IP)
				}
			}
			startRemaining()
		case <-preferenceC:
			if ctx.Err() != nil {
				return dialResult{error: ctx.Err()}
			}
			preferenceC = nil
			preferenceExpired = true
			if held != nil {
				return finishHeld()
			}
		case result := <-results:
			if ctx.Err() != nil {
				if result.Conn != nil {
					_ = result.Conn.Close()
				}
				return dialResult{error: ctx.Err()}
			}
			pending--
			pendingFamily[family(result.ip)]--
			delete(inFlight, result.ip)
			if result.error != nil {
				errs = append(errs, result.error)
				tcpConcurrentCache.Backoff(key, result.ip)
				continue
			}
			if !fullRace || !preference || preferenceExpired || family(result.ip) == preferred || pendingFamily[preferred] == 0 {
				return finish(result)
			}
			if held == nil {
				held = &result
			} else if result.Conn != nil {
				_ = result.Conn.Close()
			}
		}
	}
}
