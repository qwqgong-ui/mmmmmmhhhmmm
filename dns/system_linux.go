//go:build linux

package dns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/dhcp"
)

const systemDHCPTimeout = 10 * time.Second

func dnsReadConfig() ([]systemNameServer, error) {
	interfaceName := defaultPhysicalInterface()
	if interfaceName == "" {
		var err error
		interfaceName, err = linuxDefaultPhysicalInterface()
		if err != nil {
			return nil, fmt.Errorf("default physical interface is unavailable: %w", err)
		}
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("resolve default physical interface %q: %w", interfaceName, err)
	}

	// systemd-networkd and NetworkManager both publish per-link runtime state.
	// Prefer it over resolv.conf, which commonly points back to 127.0.0.53.
	paths := []string{
		fmt.Sprintf("/run/systemd/netif/links/%d", iface.Index),
		fmt.Sprintf("/run/NetworkManager/devices/%d", iface.Index),
	}
	for _, path := range paths {
		servers, readErr := readLinkDNS(path, interfaceName)
		if readErr == nil && len(servers) != 0 {
			return servers, nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), systemDHCPTimeout)
	defer cancel()
	addresses, err := dhcp.ResolveDNSFromDHCP(ctx, interfaceName)
	if err != nil {
		return nil, fmt.Errorf("discover DNS on default physical interface %q: %w", interfaceName, err)
	}
	servers := make([]systemNameServer, 0, len(addresses))
	for _, address := range addresses {
		if usableSystemDNS(address) {
			servers = append(servers, scopedSystemNameServer(address, interfaceName))
		}
	}
	return servers, nil
}

func readLinkDNS(path, interfaceName string) ([]systemNameServer, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var servers []systemNameServer
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, found := strings.Cut(strings.TrimSpace(scanner.Text()), "=")
		if !found {
			continue
		}
		switch strings.ToUpper(key) {
		case "DNS", "IP4_NAMESERVERS", "IP6_NAMESERVERS",
			"DHCP4.DOMAIN_NAME_SERVERS", "DHCP6.DHCP6_NAME_SERVERS":
		default:
			continue
		}
		for _, field := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == ';'
		}) {
			address, err := netip.ParseAddr(strings.Trim(field, "[]\"'"))
			if err != nil || !usableSystemDNS(address) {
				continue
			}
			server := scopedSystemNameServer(address, interfaceName)
			if !containsSystemNameServer(servers, server) {
				servers = append(servers, server)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}

func scopedSystemNameServer(address netip.Addr, interfaceName string) systemNameServer {
	// A link-local destination needs an interface even when the dialer's bind
	// control deliberately skips non-global addresses. Preserve explicit zones.
	if address.Is6() && address.IsLinkLocalUnicast() && address.Zone() == "" {
		address = address.WithZone(interfaceName)
	}
	return systemNameServer{address: address.String(), interfaceName: interfaceName}
}

func containsSystemNameServer(servers []systemNameServer, target systemNameServer) bool {
	return slices.Contains(servers, target)
}

func usableSystemDNS(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
}
