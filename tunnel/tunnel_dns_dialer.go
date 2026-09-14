package tunnel

// WARNING: all functions in this file should only be used in the dns module

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/component/tunneldns"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// ErrTunnelDNSUnsupported reports that the selected node cannot be asked --
// either it has no proxy server behind it, or it has already been found not to
// serve the reserved destination.
var ErrTunnelDNSUnsupported = errors.New("the selected node does not serve tunnel DNS")

// ErrTunnelDNSDirectNode reports the DIRECT case specifically: there is no
// proxy server whose view could differ from ours. It is worth telling apart
// from a node that merely did not answer, because such a domain's records
// belong on the direct name server rather than on a public resolver carried
// out through a proxy.
//
// It wraps ErrTunnelDNSUnsupported, so callers that only care whether the
// tunnel can be used at all keep matching it.
var ErrTunnelDNSDirectNode = fmt.Errorf("%w, it is direct", ErrTunnelDNSUnsupported)

// ErrTunnelDNSNoServerNode reports a leaf that has no proxy server behind it
// and is not direct either: reject, an empty group, and the pass-through
// types. Nothing is ever connected through such a leaf, so records for its
// domains would only be discarded -- they are not worth asking anyone for,
// least of all a public resolver reached through a proxy.
//
// It wraps ErrTunnelDNSUnsupported for the same reason as the direct case.
var ErrTunnelDNSNoServerNode = fmt.Errorf("%w, it has no server", ErrTunnelDNSUnsupported)

// DialTunnelDNS opens a connection to the reserved tunnel DNS destination
// through the proxy that queryDomain itself would use, and reports the name of
// the node it went through.
//
// The node is chosen from queryDomain, never from the reserved name. The whole
// point of asking the server is to get the record the connection to
// queryDomain will actually be built on, and that is only true of the server
// that connection goes through. Matching rules against the reserved name
// instead would pick a second, unrelated node and answer with a record nothing
// is ever built on -- and would resolve a name that has no address anywhere.
func DialTunnelDNS(ctx context.Context, queryDomain string) (net.Conn, string, error) {
	node, dial, err := PrepareTunnelDNS(queryDomain)
	if err != nil {
		return nil, node, err
	}
	conn, err := dial(ctx)
	return conn, node, err
}

// PrepareTunnelDNS pins the selected leaf before cache lookup and dialing.
// Reusing the group for dialing could select a different node for the reserved name.
func PrepareTunnelDNS(queryDomain string) (string, func(context.Context) (net.Conn, error), error) {
	return prepareTunnelDNS(queryDomain, false)
}

// PrepareTunnelDNSCache pins a leaf without making capability backoff a cache
// lookup failure. The cache owner gates cold work and coordinates warm retries.
func PrepareTunnelDNSCache(queryDomain string) (string, func(context.Context) (net.Conn, error), error) {
	return prepareTunnelDNS(queryDomain, true)
}

func prepareTunnelDNS(queryDomain string, cacheOwner bool) (string, func(context.Context) (net.Conn, error), error) {
	match, err := tunnelDNSMatchTarget(queryDomain)
	if err != nil {
		return "", nil, err
	}
	proxy, rule, err := resolveMetadata(match)
	if err != nil {
		return "", nil, err
	}
	if proxy == nil {
		return "", nil, fmt.Errorf("%w: %s matched no proxy", ErrTunnelDNSUnsupported, queryDomain)
	}
	node := leafProxy(proxy, match)
	if err := tunnelDNSNodeUsable(node); err != nil && (!cacheOwner || node.Type() == C.Direct || !node.Type().CanServeTunnelDNS()) {
		return node.Name(), nil, err
	}
	return node.Name(), func(ctx context.Context) (net.Conn, error) {
		// Capability backoff limits network work, never access to a retained
		// bundle. Return the pinned identity before checking this condition.
		if err := tunnelDNSNodeUsable(node); err != nil && !cacheOwner {
			return nil, err
		}
		metadata := &C.Metadata{NetWork: C.TCP, Type: C.INNER}
		if err := metadata.SetRemoteAddress(C.TunnelDNSAddress); err != nil {
			return nil, err
		}
		conn, err := node.DialContext(ctx, metadata)
		if err != nil {
			logMetadataErr(metadata, rule, node, err)
			return nil, err
		}
		logMetadata(metadata, rule, conn.Chains())
		return statistic.NewTCPTracker(conn, statistic.DefaultManager, metadata, rule, 0, 0, false), nil
	}, nil
}

// tunnelDNSMatchTarget is the destination node selection runs against: the one
// the client actually wants, on the port its traffic would use, so a port or
// domain rule places this query exactly where it places that traffic.
//
// It is never the reserved name. That name has no address anywhere and belongs
// to no rule, so matching on it would pick some unrelated node and answer with
// a record no connection is built on.
func tunnelDNSMatchTarget(queryDomain string) (*C.Metadata, error) {
	if queryDomain == "" {
		return nil, errors.New("tunnel DNS needs a domain to select a node with")
	}
	match := &C.Metadata{NetWork: C.TCP, Type: C.INNER}
	if err := match.SetRemoteAddress(net.JoinHostPort(queryDomain, "443")); err != nil {
		return nil, err
	}
	return match, nil
}

// tunnelDNSNode is the part of a proxy this decision depends on.
type tunnelDNSNode interface {
	Name() string
	Type() C.AdapterType
}

// tunnelDNSNodeUsable reports whether node can be asked at all: it needs a
// proxy server behind it, and it must not already have been found not to serve
// the reserved destination.
func tunnelDNSNodeUsable(node tunnelDNSNode) error {
	if node.Type() == C.Direct {
		return fmt.Errorf("%w: %s", ErrTunnelDNSDirectNode, node.Name())
	}
	if !node.Type().CanServeTunnelDNS() {
		return fmt.Errorf("%w: %s", ErrTunnelDNSNoServerNode, node.Name())
	}
	if !tunneldns.Supported(node.Name()) {
		return fmt.Errorf("%w: %s did not answer recently", ErrTunnelDNSUnsupported, node.Name())
	}
	return nil
}

// leafProxy walks a group down to the adapter that actually holds the
// connection, which is the one whose server answers -- and whose name the
// answer is remembered against.
func leafProxy(proxy C.Proxy, metadata *C.Metadata) C.Proxy {
	leaf := proxy
	for next := leaf.Unwrap(metadata, false); next != nil; next = leaf.Unwrap(metadata, false) {
		leaf = next
	}
	return leaf
}
