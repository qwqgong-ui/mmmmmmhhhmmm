package hybrid

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/log"
)

const probeInterval = 250 * time.Millisecond
const probeTimeout = 3 * time.Second
const rawSilence = 15 * time.Second

// readBuffer holds one datagram while it is copied into a pooled buffer sized
// to the datagram, so a 64 KiB receive buffer is allocated per flow and never
// per packet.
const readBuffer = 65536

type ClientOptions struct {
	Proxy, NetworkScope string
	Dial                func(context.Context) (net.Conn, error)
	Raw                 func(context.Context, netip.AddrPort) (net.PacketConn, error)
	Fallback            func(context.Context) (net.PacketConn, error)
}
type PacketConn struct {
	opts            ClientOptions
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	flows           map[string]*clientFlow
	fallback        net.PacketConn
	reads           chan result
	closed          chan struct{}
	once            sync.Once
	deadline        time.Time
	deadlineChanged chan struct{}
	writeDeadline   time.Time
}
type clientFlow struct {
	owner  *PacketConn
	ready  chan struct{}
	err    error
	stream net.Conn
	raw    *rawSocket
	relay  netip.AddrPort
	target netip.AddrPort
	// targetAddr is the address every received datagram is reported from. It
	// is read-only after registration and shared by all of them, so delivery
	// allocates no address.
	targetAddr *net.UDPAddr
	writeMu    sync.Mutex
	// The receive path must not wait behind a send to record raw activity, so
	// these are atomic rather than guarded. Every reader tests disabled first,
	// which is what keeps an activation racing a fallback from reviving raw.
	disabled, active    atomic.Bool
	lastRaw             atomic.Int64 // last raw reply, unix nanoseconds; zero until the first
	probeEnd, nextProbe time.Time    // protected by writeMu
	disableNotified     bool         // protected by writeMu
	done                chan struct{}
	diagnostic          *flowDiagnostic
}
type result struct {
	p      []byte
	a      net.Addr
	err    error
	pooled bool // p returns to the pool once ReadFrom has copied it out
}

func NewPacketConn(opts ClientOptions) *PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketConn{opts: opts, ctx: ctx, cancel: cancel, flows: make(map[string]*clientFlow), reads: make(chan result, 64), closed: make(chan struct{}), deadlineChanged: make(chan struct{})}
}
func (c *PacketConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if len(p) == 0 || len(p) > MaxPacket {
		return 0, errors.New("hybrid: invalid datagram size")
	}
	if a == nil {
		return 0, errors.New("hybrid: missing destination")
	}
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0, err
	}
	if IsReserved(host) {
		return 0, errors.New("hybrid: reserved destination")
	}
	if port != "443" {
		return c.writeFallback(p, a)
	}
	if ip, err := netip.ParseAddr(host); err == nil && !Public(ip) {
		return c.writeFallback(p, a)
	}
	key := a.String()
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	f := c.flows[key]
	if f == nil {
		if !Initial(p) {
			c.mu.Unlock()
			return c.writeFallback(p, a)
		}
		f = &clientFlow{owner: c, ready: make(chan struct{}), done: make(chan struct{}), diagnostic: newFlowDiagnostic(key, c.opts.Proxy, c.opts.NetworkScope)}
		if log.Enabled(log.DEBUG) {
			log.Fields(log.DEBUG, map[string]string{"subsystem": "hybrid", "event": "initial_detected", "flow_id": f.diagnostic.FlowID, "host": host, "proxy": c.opts.Proxy, "network_scope": c.opts.NetworkScope}, "Hybrid QUIC Initial detected for %s", key)
		}
		c.flows[key] = f
		go f.open(key)
	}
	c.mu.Unlock()
	select {
	case <-f.ready:
	case <-c.closed:
		return 0, net.ErrClosed
	}
	if f.err != nil {
		return c.writeFallback(p, a)
	}
	return f.write(p)
}
func (f *clientFlow) open(address string) {
	c := f.owner
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	stream, err := c.opts.Dial(ctx)
	if err != nil {
		f.err = err
		f.diagnostic.update("fallback", "", "stream_dial_error", false)
		f.diagnostic.close()
		close(f.ready)
		return
	}
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	fail := func(err error) {
		f.diagnostic.update("fallback", "", "registration_error", false)
		f.diagnostic.close()
		stop()
		stream.Close()
		f.err = err
		close(f.ready)
	}
	stream.SetDeadline(time.Now().Add(10 * time.Second))
	if err = WriteRequest(stream, Request{Target: address}); err != nil {
		fail(err)
		return
	}
	var status [1]byte
	if _, err = io.ReadFull(stream, status[:]); err != nil {
		fail(err)
		return
	}
	if status[0] != 0 {
		fail(errors.New("hybrid: flow rejected"))
		return
	}
	target, err := ReadAddress(stream)
	if err != nil {
		fail(err)
		return
	}
	relay, err := ReadAddress(stream)
	if err != nil {
		fail(err)
		return
	}
	f.target, err = netip.ParseAddrPort(target)
	if err != nil || !Public(f.target.Addr()) || f.target.Port() != 443 {
		fail(errors.New("hybrid: invalid resolved target"))
		return
	}
	f.targetAddr = net.UDPAddrFromAddrPort(f.target)
	f.relay, err = netip.ParseAddrPort(relay)
	if err != nil || f.relay.Port() != 443 {
		fail(errors.New("hybrid: invalid relay"))
		return
	}
	if Public(f.relay.Addr()) {
		if pc, rawErr := c.opts.Raw(ctx, f.relay); rawErr == nil && pc != nil {
			f.raw = newRawSocket(pc, f.relay)
		}
	}
	f.disabled.Store(f.raw == nil)
	// Stop the setup timer before handing the stream to its lifetime owner.
	if !stop() || ctx.Err() != nil {
		if f.raw != nil {
			f.raw.Close()
		}
		fail(context.DeadlineExceeded)
		return
	}
	stream.SetDeadline(time.Time{})
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		if f.raw != nil {
			f.raw.Close()
		}
		fail(net.ErrClosed)
		return
	}
	f.stream = stream
	stream.SetWriteDeadline(c.writeDeadline)
	c.mu.Unlock()
	f.diagnostic.setRawConnected(f.raw != nil && f.raw.connected())
	f.diagnostic.update("tunnel", f.relay.String(), "", false)
	if log.Enabled(log.DEBUG) {
		log.Fields(log.DEBUG, map[string]string{"subsystem": "hybrid", "event": "hqs1_registered", "flow_id": f.diagnostic.FlowID, "host": address}, "HQS1 registered target=%s raw_endpoint=%s", f.target, f.relay)
	}
	close(f.ready)
	go f.readStream()
	go f.watch()
	if f.raw != nil {
		go f.readRaw()
	} else {
		f.disable(true, "raw_setup_error")
	}
}
func (f *clientFlow) disable(notify bool, reason string) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	return f.disableLocked(notify, reason)
}

func (f *clientFlow) disableLocked(notify bool, reason string) error {
	f.disabled.Store(true)
	f.active.Store(false)
	f.diagnostic.update("tunnel", "", reason, false)
	// A permanent fallback sends at most one disable frame, including setup
	// failure. A peer acknowledgement must not overwrite the original reason.
	if f.disableNotified {
		return nil
	}
	f.disableNotified = true
	if notify {
		return WriteFrame(f.stream, nil)
	}
	return nil
}
func (f *clientFlow) write(p []byte) (int, error) {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	now := time.Now()
	reason := ""
	raw, probe := false, false
	if !f.disabled.Load() && Short(p) {
		if f.active.Load() {
			if last := f.lastRaw.Load(); last != 0 && now.UnixNano()-last >= int64(rawSilence) {
				reason = "raw_silence"
			} else {
				raw = true
			}
		} else {
			if f.probeEnd.IsZero() {
				f.probeEnd = now.Add(probeTimeout)
			}
			if !now.Before(f.probeEnd) {
				reason = "probe_timeout"
			} else if !now.Before(f.nextProbe) {
				probe = true
				f.nextProbe = now.Add(probeInterval)
			}
		}
	}
	if reason != "" {
		if err := f.disableLocked(true, reason); err != nil {
			return 0, err
		}
	}
	if raw {
		if _, err := f.raw.write(p); err == nil {
			f.diagnostic.count(rawTxPackets, rawTxBytes, len(p))
			f.diagnostic.touch(now)
			return len(p), nil
		}
		if err := f.disableLocked(true, "socket_write_error"); err != nil {
			return 0, err
		}
	}
	if err := WriteFrame(f.stream, p); err != nil {
		return 0, err
	}
	f.diagnostic.count(streamTxPackets, streamTxBytes, len(p))
	f.diagnostic.touch(now)
	if probe {
		f.diagnostic.update("probing", f.relay.String(), "", true)
		if _, err := f.raw.write(p); err != nil {
			if err = f.disableLocked(true, "probe_write_error"); err != nil {
				return 0, err
			}
		} else {
			f.diagnostic.count(rawTxPackets, rawTxBytes, len(p))
		}
	}
	return len(p), nil
}
func (f *clientFlow) readStream() {
	defer func() {
		f.diagnostic.close()
		close(f.done)
		f.stream.Close()
		if f.raw != nil {
			f.raw.Close()
		}
	}()
	for {
		p, err := ReadFrame(f.stream)
		if err != nil {
			f.owner.deliver(result{err: err})
			return
		}
		if p == nil {
			continue
		}
		if len(p) == 0 {
			f.disable(false, "peer_disabled_raw")
			continue
		}
		f.diagnostic.count(streamRxPackets, streamRxBytes, len(p))
		f.diagnostic.touch(time.Now())
		f.owner.deliver(result{p: p, a: f.targetAddr})
	}
}
func (f *clientFlow) readRaw() {
	b := pool.Get(readBuffer)
	defer pool.Put(b)
	for {
		n, fromRelay, err := f.raw.read(b)
		if err != nil {
			select {
			case <-f.done:
				return
			default:
			}
			if transientError(err) {
				// An ICMP message about a single datagram, which only a
				// connected socket sees. The socket still works, so the probe
				// and silence timeouts stay the only reasons to fall back.
				f.diagnostic.countOne(rawErrors)
				continue
			}
			if f.owner.ctx.Err() == nil {
				if err = f.disable(true, "socket_read_error"); err != nil {
					f.owner.deliver(result{err: err})
				}
			}
			return
		}
		if !fromRelay || !Short(b[:n]) {
			f.diagnostic.countOne(rawDropped)
			continue
		}
		if f.disabled.Load() {
			continue
		}
		now := time.Now()
		becameActive := f.active.CompareAndSwap(false, true)
		f.lastRaw.Store(now.UnixNano())
		f.diagnostic.count(rawRxPackets, rawRxBytes, n)
		f.diagnostic.touch(now)
		if becameActive {
			f.diagnostic.update("raw", f.relay.String(), "", false)
		}
		p := pool.Get(n)
		copy(p, b[:n])
		f.owner.deliver(result{p: p, a: f.targetAddr, pooled: true})
	}
}
func (c *PacketConn) writeFallback(p []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	pc := c.fallback
	c.mu.Unlock()
	if pc == nil {
		fresh, err := c.opts.Fallback(c.ctx)
		if err != nil {
			return 0, err
		}
		c.mu.Lock()
		if c.ctx.Err() != nil {
			c.mu.Unlock()
			fresh.Close()
			return 0, net.ErrClosed
		}
		if c.fallback == nil {
			c.fallback = fresh
			fresh.SetWriteDeadline(c.writeDeadline)
			go c.readFallback(fresh)
		} else {
			fresh.Close()
		}
		pc = c.fallback
		c.mu.Unlock()
	}
	return pc.WriteTo(p, a)
}
func (c *PacketConn) readFallback(pc net.PacketConn) {
	b := pool.Get(readBuffer)
	defer pool.Put(b)
	for {
		n, a, e := pc.ReadFrom(b)
		if e != nil {
			c.deliver(result{err: e})
			return
		}
		p := pool.Get(n)
		copy(p, b[:n])
		c.deliver(result{p: p, a: a, pooled: true})
	}
}
func (c *PacketConn) deliver(r result) {
	select {
	case c.reads <- r:
	case <-c.closed:
		if r.pooled {
			pool.Put(r.p)
		}
	}
}
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		deadline, changed := c.deadline, c.deadlineChanged
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var r result
		select {
		case r = <-c.reads:
		case <-c.closed:
			r.err = net.ErrClosed
		case <-timeout:
			r.err = os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		}
		if timer != nil {
			timer.Stop()
		}
		n := copy(b, r.p)
		if r.pooled {
			pool.Put(r.p)
		}
		return n, r.a, r.err
	}
}
func (c *PacketConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		close(c.closed)
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, f := range c.flows {
			f.diagnostic.close()
			if f.stream != nil {
				f.stream.Close()
				if f.raw != nil {
					f.raw.Close()
				}
			}
		}
		if c.fallback != nil {
			c.fallback.Close()
		}
	})
	return nil
}
func (c *PacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }
func (c *PacketConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	return nil
}
func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	for _, f := range c.flows {
		if f.stream != nil {
			f.stream.SetWriteDeadline(t)
			if f.raw != nil {
				f.raw.SetWriteDeadline(t)
			}
		}
	}
	if c.fallback != nil {
		c.fallback.SetWriteDeadline(t)
	}
	return nil
}

func (f *clientFlow) watch() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastKeep := time.Now()
	for {
		select {
		case <-f.owner.closed:
			return
		case <-f.done:
			return
		case now := <-ticker.C:
			f.writeMu.Lock()
			reason := ""
			if !f.disabled.Load() {
				if f.active.Load() {
					if last := f.lastRaw.Load(); last != 0 && now.UnixNano()-last >= int64(rawSilence) {
						reason = "raw_silence"
					}
				} else if !f.probeEnd.IsZero() && !now.Before(f.probeEnd) {
					reason = "probe_timeout"
				}
			}
			var err error
			if reason != "" {
				err = f.disableLocked(true, reason)
			}
			if err == nil && now.Sub(lastKeep) >= 30*time.Second {
				err = WriteKeepAlive(f.stream)
				lastKeep = now
			}
			f.writeMu.Unlock()
			if err != nil {
				f.stream.Close()
				return
			}
		}
	}
}
