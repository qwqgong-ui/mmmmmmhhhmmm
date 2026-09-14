package dev_cache

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
)

const Separator = "\x00"

var scopeState struct {
	sync.RWMutex
	environment string
	desktop     func() string
}

func SetEnvironment(environment string) {
	scopeState.Lock()
	old := scopeState.environment
	scopeState.environment = strings.TrimSpace(environment)
	scopeState.Unlock()
	if old != strings.TrimSpace(environment) {
		RefreshScope(EnvironmentScope(old))
	}
}
func EnvironmentScope(environment string) string {
	if environment = strings.TrimSpace(environment); environment != "" {
		return "environment|" + environment
	}
	return ""
}
func SetDesktopScopeProvider(provider func() string) {
	scopeState.Lock()
	scopeState.desktop = provider
	scopeState.Unlock()
}
func CurrentScope() string {
	scopeState.RLock()
	env, provider := scopeState.environment, scopeState.desktop
	scopeState.RUnlock()
	if env != "" {
		return EnvironmentScope(env)
	}
	if provider != nil {
		return provider()
	}
	return "ipv4-private|unknown"
}

// DesktopScope deliberately ignores interfaces, IPv6 and IPv4 host bits.
// Only RFC1918 private IPv4 /16 networks identify a desktop cache partition.
func DesktopScope(prefixes []netip.Prefix) string {
	seen := make(map[string]bool)
	for _, prefix := range prefixes {
		ip := prefix.Addr().Unmap()
		if ip.Is4() && ip.IsPrivate() {
			seen[netip.PrefixFrom(ip, 16).Masked().String()] = true
		}
	}
	parts := make([]string, 0, len(seen))
	for p := range seen {
		parts = append(parts, p)
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "ipv4-private|unknown"
	}
	return "ipv4-private|" + strings.Join(parts, ",")
}

func ScopedKey(scope, key string) string { return scope + Separator + key }
func InScope(key, scope string) bool     { return scope != "" && strings.HasPrefix(key, scope+Separator) }
