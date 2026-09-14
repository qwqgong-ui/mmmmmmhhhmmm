package process

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/diagstats"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var (
	ErrInvalidNetwork     = errors.New("invalid network")
	ErrPlatformNotSupport = errors.New("not support on this platform")
	ErrNotFound           = errors.New("process not found")
)

const (
	TCP = "tcp"
	UDP = "udp"
)

// ProcessMatcher reports whether an executable path can match any configured
// process rule. It is used as a hint only: implementations must preserve the
// unfiltered lookup when no matcher is supplied.
type ProcessMatcher interface {
	MatchProcess(path string) bool
	MatchProcessName(name string) bool
}

// RuleProcessMatcher is implemented by rules and rule containers that can
// expose process candidates without evaluating socket ownership.
type RuleProcessMatcher interface {
	ProcessMatcher
	HasProcessRule() bool
}

// EndpointResolver lets an embedding platform authoritatively resolve a socket
// owner using both endpoints. Once registered, its result is final: falling
// through after a platform lookup fails can repeat the same query through an
// unavailable or permission-denied native mechanism.
type EndpointResolver func(network string, src, dst netip.AddrPort) (uint32, string, error)

// An embedding platform can register and clear this while connections are being
// matched: a core restarted in-process writes it from the start and stop paths
// while rule evaluation reads it on the hot path. A plain variable is a data
// race there, so the value is published atomically.
var externalEndpointResolver atomic.TypedValue[EndpointResolver]

func SetEndpointResolver(resolver EndpointResolver) {
	externalEndpointResolver.Store(resolver)
}

// EndpointResolverInstalled reports whether a platform lookup is registered.
// Such a resolver already returns the package name alongside the UID, so a
// caller must not spend a second lookup mapping that UID back to a name.
func EndpointResolverInstalled() bool {
	return externalEndpointResolver.Load() != nil
}

func FindProcessName(network string, srcIP netip.Addr, srcPort int) (uint32, string, error) {
	return findProcessName(network, srcIP, srcPort)
}

// FindProcessNameByAddr finds the process owning a socket identified by its
// local and remote endpoints. Platforms without an endpoint-aware lookup fall
// back to the source-only implementation.
func FindProcessNameByAddr(network string, src, dst netip.AddrPort) (uint32, string, error) {
	return findProcessNameByAddr(network, src, dst, nil)
}

// FindProcessNameByAddrWithMatcher limits expensive process descriptor scans
// to executable paths that can match the active process rules.
func FindProcessNameByAddrWithMatcher(network string, src, dst netip.AddrPort, matcher ProcessMatcher) (uid uint32, path string, err error) {
	defer func() {
		if err != nil {
			diagstats.Add(diagstats.ProcessFallback)
		} else {
			diagstats.Add(diagstats.ProcessFound)
		}
		if log.Enabled(log.DEBUG) {
			reason := "matched"
			if err != nil {
				reason = err.Error()
			}
			log.Fields(log.DEBUG, map[string]string{"subsystem": "process", "event": "attribution", "endpoint": src.String(), "destination": dst.String(), "reason": reason, "uid": fmt.Sprint(uid)}, "Process %s %s -> %s path=%s result=%s", network, src, dst, path, reason)
		}
	}()
	if resolver := externalEndpointResolver.Load(); resolver != nil {
		return resolver(network, src, dst)
	}
	return findProcessNameByAddr(network, src, dst, matcher)
}

// PackageNameResolver
// never change type traits because it's used in CMFA
type PackageNameResolver func(metadata *C.Metadata) (string, error)

// DefaultPackageNameResolver
// never change type traits because it's used in CMFA
var DefaultPackageNameResolver PackageNameResolver

func FindPackageName(metadata *C.Metadata) (string, error) {
	if resolver := DefaultPackageNameResolver; resolver != nil {
		return resolver(metadata)
	}
	return "", ErrPlatformNotSupport
}

func findPackageNameByUID(uid uint32) (string, error) {
	return FindPackageName(&C.Metadata{Uid: uid})
}

func matchPackageNameByUID(uid uint32, matcher ProcessMatcher) (matched, resolved bool) {
	pkg, err := findPackageNameByUID(uid)
	if err != nil {
		return false, false
	}
	return matcher.MatchProcessName(pkg), true
}
