package fakeip

import (
	"errors"
	"net/netip"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/log"

	"go4.org/netipx"
)

const (
	offsetKey = "key-offset-fake-ip"
	cycleKey  = "key-cycle-fake-ip"
)

type store interface {
	GetByHost(host string) (netip.Addr, bool)
	PutMapping(host string, ip netip.Addr) error
	GetByIP(ip netip.Addr) (string, bool)
	Exist(ip netip.Addr) bool
	CloneTo(store)
	FlushFakeIP() error
}

// Pool is an implementation about fake ip generator without storage
type Pool struct {
	gateway netip.Addr
	first   netip.Addr
	last    netip.Addr
	offset  netip.Addr
	cycle   bool
	mux     sync.Mutex
	ipnet   netip.Prefix
	store   store
}

// Lookup return a fake ip with host
func (p *Pool) Lookup(host string) netip.Addr {
	ip, err := p.LookupWithError(host)
	if err != nil {
		log.Warnln("[Fake-IP] persist mapping for %s failed: %v", host, err)
	}
	return ip
}

// LookupWithError never publishes an address whose persistent pair failed to
// commit. Callers serving DNS can report failure instead of returning an IP
// whose reverse mapping still belongs to the recycled address's old host.
func (p *Pool) LookupWithError(host string) (netip.Addr, error) {
	// Persistent mappings are published atomically. A read transaction can
	// return an existing mapping while another allocation waits for disk I/O.
	host = strings.ToLower(host)
	if _, persistent := p.store.(*cachefileStore); persistent {
		if ip, exist := p.store.GetByHost(host); exist {
			return ip, nil
		}
	}
	p.mux.Lock()
	defer p.mux.Unlock()

	// RFC4343: DNS Case Insensitive, we SHOULD return result with all cases.
	if ip, exist := p.store.GetByHost(host); exist {
		return ip, nil
	}

	previousOffset, previousCycle := p.offset, p.cycle
	ip := p.get()
	if err := p.store.PutMapping(host, ip); err != nil {
		p.offset, p.cycle = previousOffset, previousCycle
		return netip.Addr{}, err
	}
	return ip, nil
}

// LookBack return host with the fake ip
func (p *Pool) LookBack(ip netip.Addr) (string, bool) {
	if _, persistent := p.store.(*cachefileStore); persistent {
		return p.store.GetByIP(ip)
	}
	p.mux.Lock()
	defer p.mux.Unlock()

	return p.store.GetByIP(ip)
}

// Exist returns if given ip exists in fake-ip pool
func (p *Pool) Exist(ip netip.Addr) bool {
	if _, persistent := p.store.(*cachefileStore); persistent {
		return p.store.Exist(ip)
	}
	p.mux.Lock()
	defer p.mux.Unlock()

	return p.store.Exist(ip)
}

// Gateway return gateway ip
func (p *Pool) Gateway() netip.Addr {
	return p.gateway
}

// Broadcast return the last ip
func (p *Pool) Broadcast() netip.Addr {
	return p.last
}

// IPNet return raw ipnet
func (p *Pool) IPNet() netip.Prefix {
	return p.ipnet
}

// CloneFrom clone cache from old pool
func (p *Pool) CloneFrom(o *Pool) {
	o.store.CloneTo(p.store)
}

func (p *Pool) get() netip.Addr {
	p.offset = p.offset.Next()

	if !p.offset.Less(p.last) {
		p.cycle = true
		p.offset = p.first
	}

	return p.offset
}

func (p *Pool) FlushFakeIP() error {
	p.mux.Lock()
	defer p.mux.Unlock()
	err := p.store.FlushFakeIP()
	if err == nil {
		p.cycle = false
		p.offset = p.first.Prev()
	}
	return err
}

func (p *Pool) StoreState() {
	p.mux.Lock()
	defer p.mux.Unlock()
	if s, ok := p.store.(*cachefileStore); ok {
		s.PutByHost(offsetKey, p.offset)
		if p.cycle {
			s.PutByHost(cycleKey, p.offset)
		}
	}
}

func (p *Pool) restoreState() {
	if s, ok := p.store.(*cachefileStore); ok {
		if _, exist := s.GetByHost(cycleKey); exist {
			p.cycle = true
		}

		if offset, exist := s.GetByHost(offsetKey); exist {
			if p.ipnet.Contains(offset) {
				p.offset = offset
			} else {
				_ = p.FlushFakeIP()
			}
		} else if s.Exist(p.first) {
			_ = p.FlushFakeIP()
		}
	}
}

type Options struct {
	IPNet netip.Prefix

	// Size sets the maximum number of entries in memory
	// and does not work if Persistence is true
	Size int

	// Persistence will save the data to disk.
	// Size will not work and record will be fully stored.
	Persistence bool
}

// New return Pool instance
func New(options Options) (*Pool, error) {
	var (
		hostAddr = options.IPNet.Masked().Addr()
		gateway  = hostAddr.Next()
		first    = gateway.Next().Next().Next() // default start with 198.18.0.4
		last     = netipx.PrefixLastIP(options.IPNet)
	)

	if !options.IPNet.IsValid() || !first.IsValid() || !first.Less(last) {
		return nil, errors.New("ipnet don't have valid ip")
	}

	pool := &Pool{
		gateway: gateway,
		first:   first,
		last:    last,
		offset:  first.Prev(),
		cycle:   false,
		ipnet:   options.IPNet,
	}
	if options.Persistence {
		pool.store = newCachefileStore(cachefile.Cache(), options.IPNet)
	} else {
		pool.store = newMemoryStore(options.Size)
	}

	pool.restoreState()

	return pool, nil
}
