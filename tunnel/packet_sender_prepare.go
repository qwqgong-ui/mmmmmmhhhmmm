package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

type udpPrepareKey struct {
	host string
	ip   netip.Addr
	port uint16
}

func udpPacketKey(metadata *C.Metadata) udpPrepareKey {
	if metadata.Host != "" {
		return udpPrepareKey{host: metadata.Host, port: metadata.DstPort}
	}
	return udpPrepareKey{ip: metadata.DstIP, port: metadata.DstPort}
}

// slots cover input and per-target queues together. Ownership stays with the
// sender, not with a resolver worker, and every packet releases its slot once.
type queuedUDPPacket struct {
	C.PacketAdapter
	slots chan struct{}
	once  sync.Once
}

func (p *queuedUDPPacket) Drop() {
	p.once.Do(func() { p.PacketAdapter.Drop(); <-p.slots })
}

type udpPreparation struct {
	key      udpPrepareKey
	metadata *C.Metadata
	err      error
}

type udpPendingTarget struct {
	packets []C.PacketAdapter
}

func (s *packetSender) processPreparedPackets(pc C.PacketConn, proxy C.WriteBackProxy) {
	ctx, cancel := context.WithCancel(s.ctx)
	pending := make(map[udpPrepareKey]*udpPendingTarget)
	defer func() {
		cancel()
		for _, group := range pending {
			for _, packet := range group.packets {
				packet.Drop()
			}
		}
		s.dropAll()
	}()
	// Unknown adapters retain serialized ResolveUDP calls. DIRECT's resolver
	// explicitly allows parallel target preparation, while socket writes always
	// stay in this one loop (some proxy protocols use multiple writes per frame).
	workers := 1
	if _, ok := N.FindUpstream[interface{ ConcurrentResolveUDP() bool }](pc, func(c interface{ ConcurrentResolveUDP() bool }) bool { return c.ConcurrentResolveUDP() }); ok {
		workers = 8
	}
	ready := make(chan udpPreparation)
	var waiting []udpPrepareKey
	active := 0
	startWaiting := func() {
		for ctx.Err() == nil && active < workers && len(waiting) > 0 {
			key := waiting[0]
			waiting = waiting[1:]
			metadata := pending[key].packets[0].Metadata().Clone()
			active++
			go func() {
				_ = preHandleMetadata(metadata)
				metadata = metadata.Pure()
				var err error
				if metadata.Host != "" {
					err = pc.ResolveUDP(ctx, metadata)
				}
				if err == nil && !udpDestination(metadata).IsValid() {
					err = errors.New("invalid UDP destination")
				}
				select {
				case ready <- udpPreparation{key, metadata, err}:
				case <-ctx.Done():
				}
			}()
		}
	}
	write := func(packet C.PacketAdapter) {
		if proxy != nil {
			proxy.UpdateWriteBack(packet)
		}
		s.processPacket(pc, packet)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-ready:
			active--
			group := pending[result.key]
			delete(pending, result.key)
			if result.err != nil {
				logUDPResolveFailure(result.metadata.Host, result.err)
				for _, packet := range group.packets {
					packet.Drop()
				}
			} else {
				s.AddMapping(group.packets[0].Metadata(), result.metadata)
				for _, packet := range group.packets {
					if ctx.Err() != nil {
						packet.Drop()
					} else {
						write(packet)
					}
				}
			}
			startWaiting()
		case packet := <-s.ch:
			if ctx.Err() != nil {
				packet.Drop()
				return
			}
			key := udpPacketKey(packet.Metadata())
			if group := pending[key]; group != nil {
				group.packets = append(group.packets, packet)
				continue
			}
			s.mappingMutex.RLock()
			prepared := s.preparedTargets[key].IsValid()
			s.mappingMutex.RUnlock()
			if prepared {
				write(packet)
				continue
			}
			pending[key] = &udpPendingTarget{packets: []C.PacketAdapter{packet}}
			waiting = append(waiting, key)
			startWaiting()
		}
	}
}
