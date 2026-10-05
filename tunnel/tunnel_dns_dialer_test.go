package tunnel

import (
	"errors"
	"net"
	"testing"

	"github.com/metacubex/mihomo/component/tunneldns"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestTunnelDNSMatchTargetPreservesAddressParsing(t *testing.T) {
	for _, host := range []string{"EXAMPLE.com.", "192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "fe80::1%eth0", "fe80::1%", "999.0.0.1", "[example.com]", "[::1]", "[", "]", "a:b"} {
		t.Run(host, func(t *testing.T) {
			previous := &C.Metadata{NetWork: C.TCP, Type: C.INNER}
			previousErr := previous.SetRemoteAddress(net.JoinHostPort(host, "443"))
			metadata, err := tunnelDNSMatchTarget(host)
			if previousErr != nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, previous, metadata)
		})
	}
	_, err := tunnelDNSMatchTarget("")
	require.Error(t, err)
}

type tunnelDNSNodeStub struct {
	name  string
	type_ C.AdapterType
}

func (n tunnelDNSNodeStub) Name() string        { return n.name }
func (n tunnelDNSNodeStub) Type() C.AdapterType { return n.type_ }

func TestTunnelDNSNodeUsableDistinguishesDirectFromOtherLocalAdapters(t *testing.T) {
	directErr := tunnelDNSNodeUsable(tunnelDNSNodeStub{name: "DIRECT", type_: C.Direct})
	require.ErrorIs(t, directErr, ErrTunnelDNSDirectNode)
	require.ErrorIs(t, directErr, ErrTunnelDNSUnsupported)
	require.False(t, errors.Is(directErr, ErrTunnelDNSNoServerNode))

	for _, adapterType := range []C.AdapterType{C.Reject, C.RejectDrop, C.Compatible, C.Pass, C.PassRule, C.Rematch, C.Dns} {
		err := tunnelDNSNodeUsable(tunnelDNSNodeStub{name: adapterType.String(), type_: adapterType})
		require.ErrorIs(t, err, ErrTunnelDNSUnsupported)
		require.ErrorIs(t, err, ErrTunnelDNSNoServerNode, adapterType.String())
		require.False(t, errors.Is(err, ErrTunnelDNSDirectNode), adapterType.String())
	}

	// A node that could have answered and simply did not is neither.
	tunneldns.MarkUnsupported("JP")
	t.Cleanup(func() { tunneldns.MarkSupported("JP") })
	silent := tunnelDNSNodeUsable(tunnelDNSNodeStub{name: "JP", type_: C.Vless})
	require.ErrorIs(t, silent, ErrTunnelDNSUnsupported)
	require.False(t, errors.Is(silent, ErrTunnelDNSDirectNode))
	require.False(t, errors.Is(silent, ErrTunnelDNSNoServerNode))
}
