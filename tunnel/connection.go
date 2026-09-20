package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/diagstats"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	M "github.com/metacubex/sing/common/metadata"
)

type remoteDomainTarget struct {
	// origin is the local synthetic address (normally FakeIP) that the TUN
	// application used. ports maps every remote port requested for this FQDN to
	// the sequence number of the most recent request, so an IP-only reply can be
	// attributed to the domain that asked for that port last.
	origin netip.Addr
	ports  map[uint16]uint64
}

// maxLearnedTargets bounds the IP-learning table. A single association can fan
// out to many trackers or DHT nodes; the cap keeps that bounded without
// reintroducing the old "learn exactly one IP" restriction.
const maxLearnedTargets = 512

// udpResolveFailureLogWindow bounds, in seconds, how often one unresolvable
// UDP destination may repeat its failure at warn level.
//
// A destination that cannot be resolved is not resolved once: the application
// never learns that the FQDN is a dead end (fake-ip already answered its
// query), so it simply retries, and every retry re-runs the lookup and logs
// again. One such peer - e.g. an IPv6-only STUN host while the system has no
// usable IPv6, whose A lookup finds nothing and whose AAAA lookup is refused -
// is enough to produce tens of thousands of journal entries per hour and
// evict everything else from a size-capped journal.
//
// An unresolvable destination is a property of the network the user is on,
// not a fault in the proxy, so it is reported at info rather than warn; one
// line per host per window keeps it discoverable when the log level is raised
// to look for it, and the repeats stay available at debug.
const udpResolveFailureLogWindow = 60

// udpResolveFailureLog remembers which destinations have already warned inside
// the current window. Entries expire on their own (the cache is not created
// with WithUpdateAgeOnGet, so reads do not extend the window) and the size cap
// bounds it if many distinct hosts fail at once.
var udpResolveFailureLog = lru.New(
	lru.WithAge[string, struct{}](udpResolveFailureLogWindow),
	lru.WithSize[string, struct{}](512),
)

// logUDPResolveFailure reports the first failure recorded for a host in the
// current window at info and demotes the rest to debug.
func logUDPResolveFailure(host string, err error) {
	if _, seen := udpResolveFailureLog.GetOrStore(host, func() struct{} { return struct{}{} }); seen {
		log.Debugln("[UDP] Resolve Ip error (repeat, suppressed for %ds): %s", udpResolveFailureLogWindow, err)
		return
	}
	log.Infoln("[UDP] Resolve Ip error: %s", err)
}

type packetSender struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan C.PacketAdapter

	// UDP destination-identity mapping.
	//
	// Proxy UDP address fields are a tagged union: either FQDN or IP, never both.
	// XUDP-capable servers can return the requested FQDN, while a standard
	// Hysteria2 server normally resolves it and returns only the real IP. Keep
	// the exact maps separate from the conservative HY2 IP-learning fallback so
	// future protocol debugging does not accidentally turn ambiguity into a
	// wrong TUN source address.
	originToTarget        map[string]M.Socksaddr
	targetToOrigin        map[netip.Addr]netip.Addr // exact locally-resolved IP -> origin
	remoteDomains         map[string]*remoteDomainTarget
	learnedTargetToOrigin map[netip.Addr]netip.Addr // HY2 real IP -> attributed origin
	sendSeq               uint64                    // monotonic per-request counter
	mappingMutex          sync.RWMutex
}

// newPacketSender return a chan based C.PacketSender
// It ensures that packets can be sent sequentially and without blocking
func newPacketSender() C.PacketSender {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan C.PacketAdapter, senderCapacity)
	return &packetSender{
		ctx:    ctx,
		cancel: cancel,
		ch:     ch,

		originToTarget:        make(map[string]M.Socksaddr),
		targetToOrigin:        make(map[netip.Addr]netip.Addr),
		remoteDomains:         make(map[string]*remoteDomainTarget),
		learnedTargetToOrigin: make(map[netip.Addr]netip.Addr),
	}
}

func canonicalUDPDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(domain), ".")
}

func udpSocksaddrFromNet(addr net.Addr) M.Socksaddr {
	// Preserve the old typed-nil *net.UDPAddr fallback. Passing a typed nil to
	// sing's SocksaddrFromNet would dereference it before handleUDPToLocal can
	// replace the source with the original TUN destination.
	if addr == nil {
		return M.Socksaddr{}
	}
	if udpAddr, isUDPAddr := addr.(*net.UDPAddr); isUDPAddr && udpAddr == nil {
		return M.Socksaddr{}
	}
	return M.SocksaddrFromNet(addr).Unwrap()
}

func udpDestination(metadata *C.Metadata) M.Socksaddr {
	if metadata.DstIP.IsValid() {
		// Preserve upstream behavior for DIRECT and every locally resolved
		// adapter. Host may remain populated for rules and logging after
		// ResolveUDP, but a native UDP socket must receive the selected IP.
		return M.SocksaddrFromNet(metadata.UDPAddr()).Unwrap()
	}
	if metadata.Host != "" {
		// RemoteDNS adapters deliberately leave DstIP invalid so capable
		// proxy protocols can carry the original FQDN to the server.
		return M.ParseSocksaddrHostPort(metadata.Host, metadata.DstPort).Unwrap()
	}
	return M.Socksaddr{}
}

func (s *packetSender) AddMapping(originMetadata *C.Metadata, metadata *C.Metadata) {
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()

	originKey := originMetadata.String()
	originAddr := originMetadata.DstIP.Unmap()
	target := udpDestination(metadata)
	if addr := s.originToTarget[originKey]; !addr.IsValid() && target.IsValid() { // overwrite only if the record is illegal
		s.originToTarget[originKey] = target
	}
	if !originAddr.IsValid() || !target.IsValid() {
		return
	}

	if target.IsFqdn() {
		// Preserve the canonical domain separately from originToTarget: the
		// latter is for outgoing packet reuse, whereas this map restores an
		// incoming FQDN to the exact FakeIP expected by the TUN application.
		domain := canonicalUDPDomain(target.Fqdn)
		remoteTarget, loaded := s.remoteDomains[domain]
		if !loaded {
			remoteTarget = &remoteDomainTarget{
				origin: originAddr,
				ports:  make(map[uint16]uint64),
			}
			s.remoteDomains[domain] = remoteTarget
		} else if remoteTarget.origin != originAddr {
			// A recycled Fake-IP must never inherit an older association: forget
			// what was learned for the superseded origin, then adopt the new one.
			s.forgetLearnedForOriginLocked(remoteTarget.origin)
			remoteTarget.origin = originAddr
		}
		if metadata.DstPort != 0 {
			s.sendSeq++
			remoteTarget.ports[metadata.DstPort] = s.sendSeq
		}
		return
	}

	targetAddr := target.Addr.Unmap()
	if addr := s.targetToOrigin[targetAddr]; !addr.IsValid() { // overwrite only if the record is illegal
		s.targetToOrigin[targetAddr] = originAddr
	}
	// An exact mapping supersedes anything guessed for the same IP.
	delete(s.learnedTargetToOrigin, targetAddr)
}

// forgetLearnedForOriginLocked drops every guessed mapping that points at a
// superseded origin. The caller must hold mappingMutex.
func (s *packetSender) forgetLearnedForOriginLocked(origin netip.Addr) {
	if !origin.IsValid() {
		return
	}
	for target, learned := range s.learnedTargetToOrigin {
		if learned == origin {
			delete(s.learnedTargetToOrigin, target)
		}
	}
}

// remoteOriginForPortLocked attributes an IP-only reply to a remote domain by
// its port, preferring the domain that requested that port most recently.
//
// When several domains share one port the choice is a guess. That is deliberate:
// a source port is one socket is one application flow, so a wrong guess only
// costs that single packet — the application rejects it on its own source check,
// exactly as it rejects the unrestored real IP today. Refusing to guess instead
// breaks every destination after the first, which is fatal for any client that
// fans out over one UDP port (BitTorrent trackers and DHT, HTTP/3 to several
// origins). The caller must hold mappingMutex.
func (s *packetSender) remoteOriginForPortLocked(port uint16) netip.Addr {
	if port == 0 {
		return netip.Addr{}
	}
	var (
		origin netip.Addr
		newest uint64
	)
	for _, target := range s.remoteDomains {
		seq, loaded := target.ports[port]
		if !loaded || !target.origin.IsValid() {
			continue
		}
		if !origin.IsValid() || seq > newest {
			origin, newest = target.origin, seq
		}
	}
	return origin
}

func (s *packetSender) RestoreReadFrom(addr net.Addr) netip.Addr {
	source := udpSocksaddrFromNet(addr)
	if source.IsFqdn() {
		s.mappingMutex.RLock()
		target := s.remoteDomains[canonicalUDPDomain(source.Fqdn)]
		var originAddr netip.Addr
		if target != nil {
			originAddr = target.origin
		}
		s.mappingMutex.RUnlock()
		return originAddr
	}

	sourceAddr := source.Addr.Unmap()
	if !sourceAddr.IsValid() {
		return netip.Addr{}
	}

	s.mappingMutex.RLock()
	if originAddr := s.targetToOrigin[sourceAddr]; originAddr.IsValid() {
		s.mappingMutex.RUnlock()
		return originAddr
	}
	if originAddr := s.learnedTargetToOrigin[sourceAddr]; originAddr.IsValid() {
		s.mappingMutex.RUnlock()
		return originAddr
	}
	originAddr := s.remoteOriginForPortLocked(source.Port)
	canLearn := originAddr.IsValid() && len(s.learnedTargetToOrigin) < maxLearnedTargets
	s.mappingMutex.RUnlock()
	if !canLearn {
		return sourceAddr
	}

	// Standard Hysteria2 returns the resolved IP instead of the requested FQDN.
	// Bind each new (IP, port) reply to the domain that requested that port most
	// recently, and keep the binding so later replies from the same IP stay
	// stable. A domain with several A records therefore keeps working after the
	// first reply, which the earlier single-entry table could not do.
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	if originAddr = s.targetToOrigin[sourceAddr]; originAddr.IsValid() {
		return originAddr
	}
	if originAddr = s.learnedTargetToOrigin[sourceAddr]; originAddr.IsValid() {
		return originAddr
	}
	originAddr = s.remoteOriginForPortLocked(source.Port)
	if originAddr.IsValid() && len(s.learnedTargetToOrigin) < maxLearnedTargets {
		s.learnedTargetToOrigin[sourceAddr] = originAddr
		return originAddr
	}
	return sourceAddr
}

func (s *packetSender) processPacket(pc C.PacketConn, packet C.PacketAdapter) {
	defer packet.Drop()
	metadata := packet.Metadata()

	var addr net.Addr

	s.mappingMutex.RLock()
	targetAddr := s.originToTarget[metadata.String()]
	s.mappingMutex.RUnlock()

	if targetAddr.IsValid() {
		// A cached Socksaddr deliberately retains whether the target was an FQDN
		// or an IP. Rebuilding it from DstIP would discard that identity.
		targetAddr.Port = metadata.DstPort
		if targetAddr.IsFqdn() {
			addr = targetAddr
		} else {
			// Match upstream DIRECT behavior: native UDP sockets receive a
			// *net.UDPAddr, never a domain-capable proxy address wrapper.
			addr = net.UDPAddrFromAddrPort(targetAddr.AddrPort())
		}
	}

	if addr == nil {
		originMetadata := metadata  // save origin metadata
		metadata = metadata.Clone() // don't modify PacketAdapter's metadata

		_ = preHandleMetadata(metadata) // error was pre-checked
		metadata = metadata.Pure()
		if metadata.Host != "" {
			// TODO: ResolveUDP may take a long time to block the Process loop
			//       but we want keep sequence sending so can't open a new goroutine
			if err := pc.ResolveUDP(s.ctx, metadata); err != nil {
				logUDPResolveFailure(metadata.Host, err)
				return
			}
		}

		targetAddr = udpDestination(metadata)
		if !targetAddr.IsValid() {
			log.Warnln("[UDP] Destination ip not valid: %#v", metadata)
			return
		}
		if targetAddr.IsFqdn() {
			addr = targetAddr
		} else {
			addr = metadata.UDPAddr()
		}
		s.AddMapping(originMetadata, metadata)
	}
	if err := handleUDPToRemote(packet, pc, addr); err != nil {
		reportUDPICMPError(packet, addr, err)
	}
}

// reportUDPICMPError tells the sender why its datagram went no further, for the
// failures an ICMP error exists for. Without this the write error dies here:
// the sender is talking to a tun device that took the packet, so it keeps
// sending the same size, or waits out a timeout.
func reportUDPICMPError(packet C.UDPPacket, addr net.Addr, err error) {
	reporter, canReport := packet.(C.UDPPacketICMPError)
	if !canReport {
		return
	}
	var (
		icmpError C.ICMPError
		mtu       uint32
	)
	var packetTooBig *C.PacketTooBigError
	switch {
	case errors.As(err, &packetTooBig):
		icmpError = C.ICMPErrorPacketTooBig
		mtu = senderMTU(packetTooBig.MTU, packet.LocalAddr(), addr)
		if mtu == 0 {
			return
		}
	case errors.Is(err, syscall.ECONNREFUSED):
		icmpError = C.ICMPErrorPortUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		icmpError = C.ICMPErrorHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		icmpError = C.ICMPErrorNetworkUnreachable
	default:
		return
	}
	reportErr := reporter.ReportICMPError(icmpError, mtu)
	if reportErr != nil {
		diagstats.Add(diagstats.ICMPWriteError)
	} else {
		diagstats.Add(diagstats.ICMPReported)
	}
	if log.Enabled(log.DEBUG) {
		log.Fields(log.DEBUG, map[string]string{"subsystem": "tun", "event": "icmp_report", "reason": icmpError.String(), "writeback_ok": fmt.Sprint(reportErr == nil)}, "UDP socket error=%v -> ICMP %s mtu=%d sender=%s report_error=%v", err, icmpError, mtu, packet.LocalAddr(), reportErr)
	}
}

// senderMTU restates a path MTU the way the sender measures it. The sender's
// datagram is re-headered on the way out, so when the two sides are not the
// same address family the headers differ in size and the number has to move
// with them.
func senderMTU(pathMTU uint32, source net.Addr, destination net.Addr) uint32 {
	const (
		ipv4HeaderSize = 20
		ipv6HeaderSize = 40
		minimumMTUv4   = 576
		minimumMTUv6   = 1280
	)
	sourceIs6, ok := addrIs6(source)
	if !ok {
		return 0
	}
	destinationIs6, ok := addrIs6(destination)
	if !ok {
		return 0
	}
	mtu := int(pathMTU)
	if sourceIs6 != destinationIs6 {
		if sourceIs6 {
			mtu += ipv6HeaderSize - ipv4HeaderSize
		} else {
			mtu -= ipv6HeaderSize - ipv4HeaderSize
		}
	}
	minimum := minimumMTUv4
	if sourceIs6 {
		minimum = minimumMTUv6
	}
	if mtu < minimum {
		return 0
	}
	return uint32(mtu)
}

func addrIs6(addr net.Addr) (bool, bool) {
	if addr == nil {
		return false, false
	}
	if udpAddr, isUDPAddr := addr.(*net.UDPAddr); isUDPAddr {
		if ip, ok := netip.AddrFromSlice(udpAddr.IP); ok {
			return ip.Unmap().Is6(), true
		}
		return false, false
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false, false
	}
	return addrPort.Addr().Unmap().Is6(), true
}

func (s *packetSender) Process(pc C.PacketConn, proxy C.WriteBackProxy) {
	for {
		select {
		case <-s.ctx.Done():
			return // sender closed
		case packet := <-s.ch:
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			s.processPacket(pc, packet)
		}
	}
}

func (s *packetSender) dropAll() {
	for {
		select {
		case data := <-s.ch:
			data.Drop() // drop all data still in chan
		default:
			return // no data, exit goroutine
		}
	}
}

func (s *packetSender) Send(packet C.PacketAdapter) {
	select {
	case <-s.ctx.Done():
		packet.Drop() // sender closed before Send()
		return
	default:
	}

	select {
	case s.ch <- packet:
		// put ok, so don't drop packet, will process by other side of chan
	case <-s.ctx.Done():
		packet.Drop() // sender closed when putting data to chan
	default:
		packet.Drop() // chan is full
	}
}

func (s *packetSender) Close() {
	s.cancel()
	s.dropAll()
}

func (s *packetSender) DoSniff(metadata *C.Metadata) error { return nil }

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, addr net.Addr) error {
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(writeBack C.WriteBack, pc C.PacketConn, sender C.PacketSender, key string, oAddrPort netip.AddrPort) {
	defer func() {
		sender.Close()
		_ = pc.Close()
		closeAllLocalCoon(key)
		natTable.Delete(key)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			return
		}

		source := udpSocksaddrFromNet(from)
		fromPort := source.Port
		if fromPort == 0 {
			fromPort = oAddrPort.Port()
		}

		// Restore both locally resolved IP mappings and remote FQDN mappings.
		fromAddr := sender.RestoreReadFrom(from).Unmap()
		var writeBackAddr net.Addr
		switch {
		case fromAddr.IsValid() && fromPort != 0:
			writeBackAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(fromAddr, fromPort))
		case source.IsFqdn() && !oAddrPort.IsValid():
			// Non-transparent inbounds such as SOCKS can preserve the domain
			// directly even when there is no Fake-IP to restore.
			writeBackAddr = source
		case source.IsFqdn():
			// A transparent inbound cannot write a domain as the packet source.
			// Falling back to the association's first FakeIP would silently
			// misattribute an unknown domain on a multi-destination EIM socket.
			if put != nil {
				put()
			}
			log.Warnln("server returned an unmapped UDP domain [%s], drop instead of guessing (%s)", source, oAddrPort)
			return
		case oAddrPort.IsValid():
			// Retain the historical fallback for invalid/typed-nil server
			// addresses; unlike an unknown domain, these carry no identity that
			// could be incorrectly assigned to another destination.
			writeBackAddr = net.UDPAddrFromAddrPort(oAddrPort)
			log.Warnln("server returned an unrestorable [%T](%v), force replace to (%s)", from, from, oAddrPort)
		default:
			if put != nil {
				put()
			}
			log.Warnln("server returned an invalid UDP source [%T](%v)", from, from)
			return
		}

		_, err = writeBack.WriteBack(data, writeBackAddr)
		if put != nil {
			put()
		}
		if err != nil {
			return
		}
	}
}

func closeAllLocalCoon(lAddr string) {
	natTable.RangeForLocalConn(lAddr, func(key string, value *net.UDPConn) bool {
		conn := value

		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", lAddr, key)
		return true
	})
}

func handleSocket(inbound, outbound net.Conn) {
	N.Relay(inbound, outbound)
}
