package tunnel

// WARNING: all function in this file should only be using in dns module

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const DnsRespectRules = "RULES"

type DNSDialer struct {
	r             resolver.Resolver
	proxyAdapter  C.ProxyAdapter
	proxyName     string
	interfaceName string
	systemDNS     bool
	destination   netip.Addr
}

// WithDestination pins the transport address while retaining the original
// hostname for TLS verification and domain-based routing.
func (d *DNSDialer) WithDestination(ip netip.Addr) *DNSDialer {
	copy := *d
	copy.destination = ip.Unmap()
	return &copy
}

func NewDNSDialer(r resolver.Resolver, proxyAdapter C.ProxyAdapter, proxyName string) *DNSDialer {
	return &DNSDialer{r: r, proxyAdapter: proxyAdapter, proxyName: proxyName}
}

// NewSystemDNSDialer creates a direct DNS dialer pinned to the physical
// interface that supplied the system name server. It explicitly applies
// sing-tun's active auto-redirect output bypass mark on Linux. On Windows,
// WithInterface becomes IP_UNICAST_IF/IPV6_UNICAST_IF.
func NewSystemDNSDialer(r resolver.Resolver, interfaceName string) *DNSDialer {
	return &DNSDialer{r: r, interfaceName: interfaceName, systemDNS: true}
}

func (d *DNSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	r := d.r
	proxyName := d.proxyName
	proxyAdapter := d.proxyAdapter
	// Race all IPv4/IPv6 TCP addresses, regardless of global tcp-concurrent.
	opts := []dialer.Option{dialer.WithConcurrentTCP()}
	if d.interfaceName != "" {
		opts = append(opts, dialer.WithInterface(d.interfaceName))
	}
	if d.systemDNS {
		opts = append(opts, dialer.WithRoutingMark(int(dialer.SystemDNSRoutingMark.Load())))
	}
	var rule C.Rule
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.INNER,
	}
	err := metadata.SetRemoteAddress(addr) // tcp can resolve host by remote
	if err != nil {
		return nil, err
	}
	if d.destination.IsValid() {
		metadata.DstIP = d.destination
		_, port, _ := net.SplitHostPort(addr)
		addr = net.JoinHostPort(d.destination.String(), port)
		opts = append(opts, dialer.WithOnlySingleStack(d.destination.Is4()))
	}
	if !strings.Contains(network, "tcp") {
		metadata.NetWork = C.UDP
	}

	if proxyAdapter == nil && len(proxyName) != 0 {
		if proxyName == DnsRespectRules {
			if !metadata.Resolved() {
				// resolve here before resolveMetadata to avoid its inner resolver.ResolveIP
				dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
				if err != nil {
					return nil, err
				}
				metadata.DstIP = dstIP
			}
			proxyAdapter, rule, err = resolveMetadata(metadata)
			if err != nil {
				return nil, err
			}
		} else {
			var ok bool
			proxyAdapter, ok = Proxies()[proxyName]
			if ok {
				metadata.SpecialProxy = proxyName // just for log
			} else {
				opts = append(opts, dialer.WithInterface(proxyName))
			}
		}
	}

	if metadata.NetWork == C.TCP {
		if proxyAdapter == nil {
			opts = append(opts, dialer.WithResolver(r))
			return dialer.DialContext(ctx, network, addr, opts...)
		}

		if proxyAdapter.IsL3Protocol(metadata) { // L3 proxy should resolve domain before to avoid loopback
			if !metadata.Resolved() {
				dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
				if err != nil {
					return nil, err
				}
				metadata.DstIP = dstIP
			}
			metadata.Host = "" // clear host to avoid double resolve in proxy
		}

		conn, err := proxyAdapter.DialContext(ctx, metadata)
		if err != nil {
			logMetadataErr(metadata, rule, proxyAdapter, err)
			return nil, err
		}
		logMetadata(metadata, rule, conn.Chains())

		conn = statistic.NewTCPTracker(conn, statistic.DefaultManager, metadata, rule, 0, 0, false)

		return conn, nil
	} else {
		if proxyAdapter == nil {
			opts = append(opts, dialer.WithResolver(r))
			return dialer.DialContext(ctx, network, addr, opts...)
		}

		if !metadata.Resolved() {
			dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
			if err != nil {
				return nil, err
			}
			metadata.DstIP = dstIP
		}

		if !proxyAdapter.SupportUDP() {
			return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", proxyAdapter.Name())
		}

		packetConn, err := proxyAdapter.ListenPacketContext(ctx, metadata)
		if err != nil {
			logMetadataErr(metadata, rule, proxyAdapter, err)
			return nil, err
		}
		logMetadata(metadata, rule, packetConn.Chains())

		packetConn = statistic.NewUDPTracker(packetConn, statistic.DefaultManager, metadata, rule, 0, 0, false)

		return N.NewBindPacketConn(packetConn, metadata.UDPAddr()), nil
	}

}

func (d *DNSDialer) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	r := d.r
	proxyAdapter := d.proxyAdapter
	proxyName := d.proxyName
	var opts []dialer.Option
	if d.interfaceName != "" {
		opts = append(opts, dialer.WithInterface(d.interfaceName))
	}
	if d.systemDNS {
		opts = append(opts, dialer.WithRoutingMark(int(dialer.SystemDNSRoutingMark.Load())))
	}
	metadata := &C.Metadata{
		NetWork: C.UDP,
		Type:    C.INNER,
	}
	err := metadata.SetRemoteAddress(addr)
	if err != nil {
		return nil, err
	}
	if d.destination.IsValid() {
		metadata.DstIP = d.destination
	}
	if !metadata.Resolved() {
		// udp must resolve host first
		dstIP, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, r)
		if err != nil {
			return nil, err
		}
		metadata.DstIP = dstIP
	}

	var rule C.Rule
	if proxyAdapter == nil {
		if proxyName == DnsRespectRules {
			proxyAdapter, rule, err = resolveMetadata(metadata)
			if err != nil {
				return nil, err
			}
		} else {
			var ok bool
			proxyAdapter, ok = Proxies()[proxyName]
			if ok {
				metadata.SpecialProxy = proxyName // just for log
			} else {
				opts = append(opts, dialer.WithInterface(proxyName))
			}
		}
	}

	if proxyAdapter == nil {
		return dialer.NewDialer(opts...).ListenPacket(ctx, network, "", metadata.AddrPort())
	}

	if !proxyAdapter.SupportUDP() {
		return nil, fmt.Errorf("proxy adapter [%s] UDP is not supported", proxyAdapter.Name())
	}

	packetConn, err := proxyAdapter.ListenPacketContext(ctx, metadata)
	if err != nil {
		logMetadataErr(metadata, rule, proxyAdapter, err)
		return nil, err
	}
	logMetadata(metadata, rule, packetConn.Chains())

	packetConn = statistic.NewUDPTracker(packetConn, statistic.DefaultManager, metadata, rule, 0, 0, false)

	return packetConn, nil
}
