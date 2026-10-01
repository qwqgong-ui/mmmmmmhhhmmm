package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/constant/features"

	"github.com/metacubex/mipstack"
)

const (
	ipStackAuto   = "auto"
	ipStackGVisor = "gvisor"
	ipStackMips   = "mips"
)

type IPStackOption struct {
	Mode                 string `proxy:"mode,omitempty"`
	CongestionController string `proxy:"congestion-controller,omitempty"`
}

func (o *IPStackOption) normalize() {
	o.Mode = strings.ToLower(o.Mode)
	if o.Mode == "" {
		o.Mode = ipStackAuto
	}
	o.CongestionController = strings.ToLower(o.CongestionController)
}

func (o IPStackOption) validate() error {
	switch o.Mode {
	case ipStackAuto, ipStackMips:
	case ipStackGVisor:
		if !features.WithGVisor {
			return errors.New("gVisor IP stack requires the with_gvisor build tag")
		}
	default:
		return fmt.Errorf("invalid IP stack mode %q; expected auto, gvisor, or mips", o.Mode)
	}
	switch o.CongestionController {
	case "", mipstack.CongestionControlCUBIC, mipstack.CongestionControlReno, mipstack.CongestionControlBBR, mipstack.CongestionControlBBR3:
		return nil
	default:
		return fmt.Errorf("invalid IP stack congestion controller %q; expected cubic, reno, bbr, or bbr3", o.CongestionController)
	}
}

// ipStack is the mihomo IP stack's packet and socket surface.
type ipStack interface {
	Start() error
	DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	DialIP(ctx context.Context, network string, source, destination netip.Addr) (net.Conn, error)
	ListenTCP(ctx context.Context, network string, local netip.AddrPort) (net.Listener, error)
	ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error)
	ListenIP(ctx context.Context, network string, local netip.Addr) (net.PacketConn, error)
	Read(buffers [][]byte, sizes []int, offset int) (int, error)
	Write(buffers [][]byte, offset int) (int, error)
	MTU() (int, error)
	Name() (string, error)
	BatchSize() int
	Close() error
}

// newIPStack constructs the selected userspace IP stack.
func newIPStack(option IPStackOption, localAddresses []netip.Prefix, mtu uint32) (ipStack, error) {
	mode := option.Mode
	if mode == ipStackAuto {
		mode = ipStackMips
	}
	switch mode {
	case ipStackGVisor:
		return newGVisorIPStack(localAddresses, mtu)
	case ipStackMips:
		return mipstack.New(mipstack.Config{
			LocalAddresses: localAddresses,
			MTU:            mtu,
			TCP: mipstack.TCPSocketDefaults{
				CongestionControl: option.CongestionController,
				// Align with sing-wireguard: enable keepalive with 15-second
				// idle/interval timing and gVisor's default probe count.
				KeepAlive: true,
				KeepAliveConfig: mipstack.KeepAliveConfig{
					Idle: 15 * time.Second, Interval: 15 * time.Second, Count: 9,
				},
			},
			IP: mipstack.IPSocketDefaults{
				// Match sing-wireguard's raw IP socket semantics.
				IPHeaderIncludedOnRead:  true,
				IPHeaderIncludedOnWrite: true,
			},
		})
	default:
		return nil, errors.New("invalid IP stack mode")
	}
}

var _ ipStack = (*mipstack.Stack)(nil)

type ipStackNetDialer struct {
	stack ipStack
}

var _ dialer.NetDialer = (*ipStackNetDialer)(nil)

func (d ipStackNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dst, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	switch {
	case strings.HasPrefix(network, "tcp"):
		return d.stack.DialTCP(ctx, network, netip.AddrPort{}, dst)
	case strings.HasPrefix(network, "udp"):
		return d.stack.DialUDP(ctx, network, netip.AddrPort{}, dst)
	default:
		return nil, fmt.Errorf("invalid network %q", network)
	}
}
