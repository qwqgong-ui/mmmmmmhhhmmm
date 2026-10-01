package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

// Candidate work belongs to the packet association, not to the setup context:
// callers may cancel that context as soon as ListenPacketContext returns.
func (d *Direct) registerProgressiveUDPTarget(ctx context.Context, race *directUDPRacePacketConn, metadata *C.Metadata) error {
	work, cancel := context.WithTimeout(race.ctx, resolver.DefaultDNSTimeout)
	stopSetupCancel := context.AfterFunc(ctx, cancel)
	defer stopSetupCancel()
	snapshot := metadata.Clone()
	r := resolver.DirectHostResolver
	preserveResolved := r == resolver.DefaultResolver
	batches := directUDPCandidateBatches(work, snapshot.Host, dialer.NetworkScope(d.DialOptions()...), r)
	var errs []error
	for {
		select {
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		case <-work.Done():
			cancel()
			return work.Err()
		case batch, ok := <-batches:
			if !ok {
				cancel()
				return fmt.Errorf("can't resolve ip: %w", errors.Join(append(errs, resolver.ErrIPNotFound)...))
			}
			if batch.Err != nil {
				errs = append(errs, batch.Err)
			}
			candidates, fallback := d.orderUDPRaceCandidates(snapshot, batch.IPs, preserveResolved)
			if len(candidates) == 0 {
				continue
			}
			logical := netip.AddrPortFrom(fallback, snapshot.DstPort)
			if err := race.register(work, logical, candidates, snapshot.Host, d.Name()); err != nil {
				errs = append(errs, err)
				continue
			}
			if err := ctx.Err(); err != nil {
				cancel()
				return err
			}
			race.mu.Lock()
			target := race.targets[logical]
			if target.collectingCandidates || !target.acceptsCandidates(snapshot.Host, d.Name()) {
				race.mu.Unlock()
				cancel()
				metadata.DstIP = fallback
				return nil
			}
			target.collectingCandidates = true
			race.mu.Unlock()
			metadata.DstIP = fallback
			go func() {
				defer cancel()
				defer func() {
					race.mu.Lock()
					target := race.targets[logical]
					target.collectingCandidates = false
					target.replay = nil
					target.replayBytes = 0
					race.mu.Unlock()
				}()
				for {
					select {
					case <-work.Done():
						return
					case batch, ok := <-batches:
						if !ok {
							return
						}
						candidates, _ := d.orderUDPRaceCandidates(snapshot, batch.IPs, preserveResolved)
						if len(candidates) > 0 {
							_ = race.register(work, logical, candidates, snapshot.Host, d.Name())
						}
					}
				}
			}()
			return nil
		}
	}
}

func directUDPCandidateBatches(ctx context.Context, host, scope string, r resolver.Resolver) <-chan resolver.IPCandidateBatch {
	output := make(chan resolver.IPCandidateBatch, 2)
	progressive, useProgressive := r.(resolver.ProgressiveResolver)
	if _, static := resolver.DefaultHosts.Search(host, false); static {
		useProgressive = false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		useProgressive = false
	}
	var workers sync.WaitGroup
	feed := func(ipv6 bool) {
		defer workers.Done()
		send := func(batch resolver.IPCandidateBatch) bool {
			select {
			case output <- batch:
				return true
			case <-ctx.Done():
				return false
			}
		}
		if useProgressive {
			for batch := range progressive.LookupIPCandidates(ctx, host, ipv6, scope) {
				if !send(batch) {
					return
				}
			}
		} else {
			lookup := resolver.LookupIPv4WithResolver
			if ipv6 {
				lookup = resolver.LookupIPv6WithResolver
			}
			ips, err := lookup(ctx, host, r)
			send(resolver.IPCandidateBatch{IPs: ips, Err: err})
		}
	}
	workers.Add(1)
	go feed(false)
	if !resolver.DisableIPv6.Load() {
		workers.Add(1)
		go feed(true)
	}
	go func() { workers.Wait(); close(output) }()
	return output
}
