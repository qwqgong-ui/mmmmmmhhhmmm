//go:build linux

package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLinkDNS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "link")
	contents := "DNS=127.0.0.53 192.168.110.1 2001:db8::53\n" +
		"IP4_NAMESERVERS=192.168.110.1,10.0.0.53;\n" +
		"IP6_NAMESERVERS='fe80::53%2' fe80::54\n" +
		"dhcp4.domain_name_servers=172.16.0.53\n" +
		"dhcp6.dhcp6_name_servers=::1\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	servers, err := readLinkDNS(path, "enp4s0")
	if err != nil {
		t.Fatal(err)
	}
	want := []systemNameServer{
		{address: "192.168.110.1", interfaceName: "enp4s0"},
		{address: "2001:db8::53", interfaceName: "enp4s0"},
		{address: "10.0.0.53", interfaceName: "enp4s0"},
		{address: "fe80::53%2", interfaceName: "enp4s0"},
		{address: "fe80::54%enp4s0", interfaceName: "enp4s0"},
		{address: "172.16.0.53", interfaceName: "enp4s0"},
	}
	if len(servers) != len(want) {
		t.Fatalf("got %v, want %v", servers, want)
	}
	for i := range want {
		if servers[i] != want[i] {
			t.Fatalf("server %d: got %v, want %v", i, servers[i], want[i])
		}
	}
}
