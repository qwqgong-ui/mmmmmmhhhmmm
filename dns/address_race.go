package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sync"

	R "github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"
)

type addressClientEntry struct {
	client dnsClient
	users  int
	stale  bool
}

// Each address owns its transport pool. Race complete DNS exchanges rather
// than UDP socket creation, preserving the hostname for SNI and HTTP authority.
type addressRaceClient struct {
	host          string
	address       string
	r             R.Resolver
	new           func(netip.Addr) dnsClient
	mu            sync.Mutex
	clients       map[netip.Addr]*addressClientEntry
	winner        netip.Addr
	winnerVersion uint64
	selectionMu   sync.Mutex
}

func raceNameServerAddresses(base dnsClient, ns NameServer, r R.Resolver) dnsClient {
	var host string
	if ns.Net == "https" {
		u, err := url.Parse(ns.Addr)
		if err != nil {
			return base
		}
		host = u.Hostname()
	} else {
		host, _, _ = net.SplitHostPort(ns.Addr)
	}
	if host == "" {
		return base
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return base
	}
	var factory func(netip.Addr) dnsClient
	switch base.(type) {
	case *client:
		factory = func(ip netip.Addr) dnsClient {
			c := newClient(ns.Addr, r, ns.Net, ns.Params, ns.ProxyAdapter, ns.ProxyName)
			c.dialer = c.dialer.WithDestination(ip)
			return c
		}
	case *dnsOverTLS:
		factory = func(ip netip.Addr) dnsClient {
			c := newDoTClient(ns.Addr, r, ns.Params, ns.ProxyAdapter, ns.ProxyName)
			c.dialer = c.dialer.WithDestination(ip)
			return c
		}
	case *dnsOverQUIC:
		factory = func(ip netip.Addr) dnsClient {
			c := newDoQ(ns.Addr, r, ns.Params, ns.ProxyAdapter, ns.ProxyName)
			c.dialer = c.dialer.WithDestination(ip)
			return c
		}
	case *dnsOverHTTPS:
		factory = func(ip netip.Addr) dnsClient {
			c := newDoHClient(ns.Addr, r, ns.PreferH3, ns.Params, ns.ProxyAdapter, ns.ProxyName).(*dnsOverHTTPS)
			c.dialer = c.dialer.WithDestination(ip)
			return c
		}
	default:
		return base
	}
	return &addressRaceClient{host: host, address: base.Address(), r: r, new: factory, clients: make(map[netip.Addr]*addressClientEntry)}
}

func (c *addressRaceClient) Address() string { return c.address }

func (c *addressRaceClient) acquire(ip netip.Addr) (dnsClient, func()) {
	c.mu.Lock()
	e := c.clients[ip]
	if e == nil {
		e = &addressClientEntry{client: c.new(ip)}
		c.clients[ip] = e
	}
	e.users++
	e.stale = false
	c.mu.Unlock()
	return e.client, func() {
		c.mu.Lock()
		e.users--
		close := e.stale && e.users == 0
		if close {
			delete(c.clients, ip)
		}
		c.mu.Unlock()
		if close {
			e.client.ResetConnection()
		}
	}
}

func (c *addressRaceClient) prune(current map[netip.Addr]bool) {
	var retired []dnsClient
	c.mu.Lock()
	for ip, e := range c.clients {
		if current[ip] {
			continue
		}
		e.stale = true
		if e.users == 0 {
			delete(c.clients, ip)
			retired = append(retired, e.client)
		}
	}
	c.mu.Unlock()
	for _, client := range retired {
		client.ResetConnection()
	}
}

func (c *addressRaceClient) ResetConnection() {
	c.mu.Lock()
	clients := make([]dnsClient, 0, len(c.clients))
	for _, e := range c.clients {
		clients = append(clients, e.client)
	}
	c.mu.Unlock()
	for _, client := range clients {
		client.ResetConnection()
	}
}

func (c *addressRaceClient) ExchangeContext(ctx context.Context, query *D.Msg) (*D.Msg, error) {
	if msg, err, used := c.exchangeWinner(ctx, query); used && (err == nil || ctx.Err() != nil) {
		return msg, err
	}
	// Only one caller selects a replacement. Waiting callers reuse its winner.
	c.selectionMu.Lock()
	defer c.selectionMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if msg, err, used := c.exchangeWinner(ctx, query); used && (err == nil || ctx.Err() != nil) {
		return msg, err
	}
	return c.race(ctx, query)
}

func validAddressResponse(msg *D.Msg, err error) error {
	if err != nil {
		return err
	}
	switch {
	case msg == nil:
		return errors.New("empty DNS response")
	case hasUpstreamFakeIP(msg):
		return errUpstreamFakeIP
	case msg.Rcode == D.RcodeServerFailure || msg.Rcode == D.RcodeRefused:
		return fmt.Errorf("DNS response: %s", D.RcodeToString[msg.Rcode])
	}
	return nil
}

func (c *addressRaceClient) exchangeWinner(ctx context.Context, query *D.Msg) (*D.Msg, error, bool) {
	c.mu.Lock()
	ip, version := c.winner, c.winnerVersion
	c.mu.Unlock()
	if !ip.IsValid() {
		return nil, nil, false
	}
	client, release := c.acquire(ip)
	defer release()
	msg, err := client.ExchangeContext(ctx, query.Copy())
	err = validAddressResponse(msg, err)
	if err != nil && ctx.Err() == nil {
		c.mu.Lock()
		if c.winnerVersion == version {
			c.winner = netip.Addr{}
			c.winnerVersion++
		}
		c.mu.Unlock()
	}
	return msg, err, true
}

func (c *addressRaceClient) race(ctx context.Context, query *D.Msg) (*D.Msg, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type event struct {
		lookup bool
		ips    []netip.Addr
		ip     netip.Addr
		msg    *D.Msg
		err    error
	}
	events := make(chan event)
	send := func(e event) {
		select {
		case events <- e:
		case <-ctx.Done():
		}
	}
	r := c.r
	if r == nil {
		r = R.ProxyServerHostResolver
	}
	for _, lookup := range []func(context.Context, string, R.Resolver) ([]netip.Addr, error){R.LookupIPv4WithResolver, R.LookupIPv6WithResolver} {
		go func() {
			ips, err := lookup(ctx, c.host, r)
			send(event{lookup: true, ips: ips, err: err})
		}()
	}
	pendingLookups, pendingQueries := 2, 0
	seen := make(map[netip.Addr]bool)
	defer c.prune(seen)
	var errs []error
	for pendingLookups+pendingQueries > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case e := <-events:
			if e.lookup {
				pendingLookups--
				if e.err != nil {
					errs = append(errs, e.err)
				}
				for _, ip := range e.ips {
					ip = ip.Unmap()
					if !ip.IsValid() || seen[ip] {
						continue
					}
					seen[ip] = true
					client, release := c.acquire(ip)
					pendingQueries++
					go func() {
						defer release()
						msg, err := client.ExchangeContext(ctx, query.Copy())
						err = validAddressResponse(msg, err)
						send(event{ip: ip, msg: msg, err: err})
					}()
				}
				continue
			}
			pendingQueries--
			if e.err == nil {
				c.mu.Lock()
				c.winner = e.ip
				c.winnerVersion++
				c.mu.Unlock()
				return e.msg, nil
			}
			errs = append(errs, e.err)
		}
	}
	if len(errs) == 0 {
		errs = append(errs, R.ErrIPNotFound)
	}
	return nil, fmt.Errorf("all addresses for %s failed: %w", c.host, errors.Join(errs...))
}
