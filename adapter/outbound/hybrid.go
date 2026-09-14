package outbound

import (
	"context"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/hybrid"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
)

// Hybrid wraps the already selected node. Only its datagram path changes;
// the reserved stream is dialled through that node without running rules again.
type Hybrid struct{ ProxyAdapter }

func NewHybrid(proxy ProxyAdapter) ProxyAdapter { return &Hybrid{ProxyAdapter: proxy} }
func (h *Hybrid) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if metadata.DstPort != 443 {
		return h.ProxyAdapter.ListenPacketContext(ctx, metadata)
	}
	if err := h.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	original := *metadata
	streamDialer := proxydialer.New(h.ProxyAdapter, false)
	pc := hybrid.NewPacketConn(hybrid.ClientOptions{
		Proxy:        h.Name(),
		NetworkScope: dialer.NetworkScope(h.DialOptions()...),
		Dial: func(ctx context.Context) (net.Conn, error) {
			return streamDialer.DialContext(ctx, "tcp", hybrid.Address)
		},
		Raw: func(ctx context.Context, relay netip.AddrPort) (net.PacketConn, error) {
			network := "udp4"
			if relay.Addr().Is6() {
				network = "udp6"
			}
			return dialer.ListenPacket(ctx, network, "", relay, h.DialOptions()...)
		},
		Fallback: func(ctx context.Context) (net.PacketConn, error) {
			m := original
			return h.ProxyAdapter.ListenPacketContext(ctx, &m)
		},
	})
	return NewPacketConn(pc, h), nil
}

// Keep fake-IP names for remote resolution, but retain a selected real IP for
// DNS mapping/hosts mode, just as remote-DNS native adapters do.
func (h *Hybrid) ResolveUDP(ctx context.Context, m *C.Metadata) error {
	if m.DstPort != 443 {
		return h.ProxyAdapter.ResolveUDP(ctx, m)
	}
	if m.Host != "" && (m.DNSMode == C.DNSMapping || m.DNSMode == C.DNSHosts) && m.DstIP.IsValid() {
		m.Host = ""
	}
	return nil
}

// QUIC is supported even when the node only offers proxy streams. Other UDP
// destinations still require the underlying node's native datagram capability.
func (h *Hybrid) SupportUDP() bool { return true }
