package ecs

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// serveWhoami answers every query with the address it is told to report,
// either as an address record or as TXT, mirroring the two answer shapes the
// real probes have to read.
func serveWhoami(t *testing.T, reported string, txt bool) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	assert.NoError(t, err)
	server := &D.Server{PacketConn: conn, Net: "udp", Handler: D.HandlerFunc(func(w D.ResponseWriter, r *D.Msg) {
		reply := new(D.Msg)
		reply.SetReply(r)
		question := r.Question[0]
		record := question.Name + " 0 IN A " + reported
		if txt {
			record = question.Name + ` 0 IN TXT "` + reported + `"`
		}
		if rr, err := D.NewRR(record); err == nil {
			reply.Answer = append(reply.Answer, rr)
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return netip.MustParseAddrPort(conn.LocalAddr().String())
}

func TestDiscoverWhoami(t *testing.T) {
	for _, test := range []struct {
		name string
		txt  bool
	}{
		{name: "address record"},
		{name: "TXT record", txt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := serveWhoami(t, "203.0.113.77", test.txt)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			probes := []whoamiProbe{{question: "myip.example.com.", txt: test.txt, v4Server: server}}
			addr, err := discoverWhoami(ctx, true, probes)
			assert.NoError(t, err)
			assert.Equal(t, netip.MustParseAddr("203.0.113.77"), addr)
		})
	}
}

// TestDiscoverWhoamiRejectsUnusableAddress covers a resolver that reports a
// private address, which carries no location for a CDN.
func TestDiscoverWhoamiRejectsUnusableAddress(t *testing.T) {
	server := serveWhoami(t, "192.168.8.8", false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	probes := []whoamiProbe{{question: "myip.example.com.", v4Server: server}}
	_, err := discoverWhoami(ctx, true, probes)
	assert.ErrorIs(t, err, errNoPublicAddress)
}

// TestDiscoverWhoamiSkipsFamilylessProbe guards the IPv4-only entries in the
// probe list: an IPv6 round must not try to reach them.
func TestDiscoverWhoamiSkipsFamilylessProbe(t *testing.T) {
	server := serveWhoami(t, "203.0.113.77", false)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	probes := []whoamiProbe{{question: "myip.example.com.", v4Server: server}}
	_, err := discoverWhoami(ctx, false, probes)
	assert.ErrorIs(t, err, errNoWhoamiServer)
}

// TestDiscoverPrefixFallsBackToWhoami is the case this host actually hits:
// STUN is filtered, so the DNS probe has to carry the round.
func TestDiscoverPrefixFallsBackToWhoami(t *testing.T) {
	server := serveWhoami(t, "203.0.113.77", false)
	originalSTUN, originalWhoami := stunServers, whoamiProbes
	stunServers = []string{"127.0.0.1:1"} // nothing answers STUN here
	whoamiProbes = []whoamiProbe{{question: "myip.example.com.", v4Server: server}}
	defer func() { stunServers, whoamiProbes = originalSTUN, originalWhoami }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	prefix, source, err := discoverPrefix(ctx, true)
	assert.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("203.0.113.0/24"), prefix)
	assert.Equal(t, "whoami", source)
}
