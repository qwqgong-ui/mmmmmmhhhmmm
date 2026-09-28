package hybrid

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestLeaseZeroCIDProbesWithoutPacketWrapper(t *testing.T) {
	relay, pc := localUDP(t), localUDP(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	records := make(chan *leaseControl, 4)
	frames := make(chan []byte, 4)
	go func() {
		for {
			p, c, e := readRecord(b)
			if e != nil {
				return
			}
			if c != nil {
				records <- c
			} else {
				frames <- p
			}
		}
	}()
	d := newFlowDiagnostic("zero-lease.test:443", "", "")
	defer d.close()
	f := &clientFlow{stream: a, lease: true, raw: newRawSocket(pc, netip.MustParseAddrPort(relay.LocalAddr().String())), diagnostic: d}
	initial := []byte{0xc0, 0, 0, 0, 1, 0, 0}
	if _, err := f.write(initial); err != nil {
		t.Fatal(err)
	}
	if f.disabled.Load() || string(<-frames) != string(initial) {
		t.Fatal("zero CID disabled lease flow")
	}
	p := []byte{0x40, 1, 2, 3, 4, 5}
	if _, err := f.write(p); err != nil {
		t.Fatal(err)
	}
	if c := <-records; c.kind != leaseBind {
		t.Fatalf("control: %+v", c)
	}
	if string(<-frames) != string(p) {
		t.Fatal("missing reliable probe copy")
	}
	relay.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := relay.ReadFrom(buf)
	if err != nil || string(buf[:n]) != string(p) {
		t.Fatalf("raw bytes changed: %x %v", buf[:n], err)
	}
	seq, sent := f.leaseSeq, f.leaseSent
	f.nextProbe = time.Time{}
	next := []byte{0x40, 9, 8, 7, 6}
	if _, err := f.write(next); err != nil {
		t.Fatal(err)
	}
	if string(<-frames) != string(next) {
		t.Fatal("new data did not stay reliable")
	}
	n, _, err = relay.ReadFrom(buf)
	if err != nil || string(buf[:n]) != string(p) {
		t.Fatal("probe changed before acknowledgement")
	}
	if f.leaseSeq != seq || !f.leaseSent.Equal(sent) {
		t.Fatal("delayed acknowledgement invalidated by probe retry")
	}
	select {
	case <-records:
		t.Fatal("retry replaced outstanding binding")
	default:
	}
}

func TestLeaseRegistrationFailureCannotBypassReservedEndpoint(t *testing.T) {
	fallback := false
	c := NewPacketConn(ClientOptions{
		Dial:     func(context.Context) (net.Conn, error) { return nil, errors.New("registration refused") },
		Fallback: func(context.Context) (net.PacketConn, error) { fallback = true; return nil, errors.New("native UDP") },
	})
	defer c.Close()
	if _, err := c.WriteTo([]byte{0xc0, 0, 0, 0, 1, 0, 0}, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}); err == nil {
		t.Fatal("rejected registration succeeded")
	}
	if fallback {
		t.Fatal("rejected reserved endpoint bypassed through native UDP")
	}
}

func TestLeaseControlAndNegotiation(t *testing.T) {
	var b bytes.Buffer
	if err := WriteRequest(&b, Request{Target: "example.com:443", Lease: true}); err != nil {
		t.Fatal(err)
	}
	q, err := ReadRequest(&b)
	if err != nil || !q.Lease || q.Target != "example.com:443" {
		t.Fatalf("%+v %v", q, err)
	}
	c := leaseControl{kind: leaseBind, seq: 42, digest: [32]byte{1, 2, 3}}
	if err := writeLease(&b, c); err != nil {
		t.Fatal(err)
	}
	p, got, err := readRecord(&b)
	if err != nil || p != nil || got == nil || *got != c {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestLeaseClientConservativeDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	d := newFlowDiagnostic("lease.test:443", "", "")
	defer d.close()
	f := &clientFlow{stream: a, lease: true, leaseSeq: 7, leaseSent: time.Now().Add(-5 * time.Second), diagnostic: d}
	activation := make(chan *leaseControl, 1)
	go func() { _, c, _ := readRecord(b); activation <- c }()
	if err := f.acceptLease(leaseControl{kind: leaseBound, seq: 7}); err != nil {
		t.Fatal(err)
	}
	if f.active.Load() {
		t.Fatal("one-way binding activated raw")
	}
	if err := f.confirmLeasePacket([]byte{0x40, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if c := <-activation; c == nil || c.kind != leaseActivate || c.seq != 7 {
		t.Fatalf("activation: %+v", c)
	}
	if err := f.acceptLease(leaseControl{kind: leaseConfirmed, seq: 7}); err != nil {
		t.Fatal(err)
	}
	if !f.active.Load() || f.leaseUntil.Load() != f.leaseSent.Add(leaseDuration).UnixNano() {
		t.Fatal("ACK arrival extended lease")
	}
	deadline := f.leaseUntil.Load()
	if err := f.acceptLease(leaseControl{kind: leaseRenewed, seq: 6}); err != nil {
		t.Fatal(err)
	}
	if f.leaseUntil.Load() != deadline {
		t.Fatal("stale ACK changed lease")
	}
	f.leaseSeq = 8
	f.leaseSent = time.Now().Add(-31 * time.Second)
	f.leaseUntil.Store(0)
	if err := f.acceptLease(leaseControl{kind: leaseRenewed, seq: 8}); err != nil {
		t.Fatal(err)
	}
	if f.leaseUntil.Load() != 0 {
		t.Fatal("expired ACK revived lease")
	}
}
