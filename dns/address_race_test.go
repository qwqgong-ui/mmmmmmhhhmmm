package dns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	R "github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
	D "github.com/miekg/dns"
)

type addressRaceResolver struct {
	R.Resolver
	v4, v6  []netip.Addr
	v6Gate  <-chan struct{}
	lookups chan<- struct{}
}

func (r addressRaceResolver) Invalid() bool { return true }
func (r addressRaceResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	if r.lookups != nil {
		r.lookups <- struct{}{}
	}
	return r.v4, nil
}
func (r addressRaceResolver) LookupIPv6(ctx context.Context, _ string) ([]netip.Addr, error) {
	if r.lookups != nil {
		r.lookups <- struct{}{}
	}
	if r.v6Gate != nil {
		select {
		case <-r.v6Gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.v6, nil
}

type addressRaceFuncClient struct {
	exchange func(context.Context, *D.Msg) (*D.Msg, error)
}

func (c addressRaceFuncClient) Address() string  { return "test" }
func (c addressRaceFuncClient) ResetConnection() {}
func (c addressRaceFuncClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	return c.exchange(ctx, q)
}

func TestAddressRaceKeepsWinnerUntilUpstreamError(t *testing.T) {
	previous := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previous) })
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	lookups := make(chan struct{}, 8)
	var failed atomic.Bool
	var primaryCalls, fallbackCalls atomic.Int32
	c := &addressRaceClient{host: "dns-race.test", r: addressRaceResolver{v4: ips, lookups: lookups}, clients: make(map[netip.Addr]*addressClientEntry)}
	c.new = func(ip netip.Addr) dnsClient {
		return addressRaceFuncClient{exchange: func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if ip == ips[0] {
				primaryCalls.Add(1)
				if failed.Load() {
					return nil, errors.New("upstream failed")
				}
			} else {
				fallbackCalls.Add(1)
				if !failed.Load() {
					<-ctx.Done()
					return nil, ctx.Err()
				}
			}
			msg := new(D.Msg)
			msg.SetReply(q)
			// NXDOMAIN is a valid answer and must not trigger reselection.
			msg.Rcode = D.RcodeNameError
			return msg, nil
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := new(D.Msg)
	q.SetQuestion("example.test.", D.TypeA)
	query := func() {
		t.Helper()
		if _, err := c.ExchangeContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	waitLookups := func() {
		t.Helper()
		for range 2 {
			select {
			case <-lookups:
			case <-ctx.Done():
				t.Fatal("missing bootstrap lookups")
			}
		}
	}
	query()
	waitLookups()
	for range 5 {
		query()
	}
	if primaryCalls.Load() != 6 {
		t.Fatalf("winner calls = %d", primaryCalls.Load())
	}
	select {
	case <-lookups:
		t.Fatal("healthy winner caused a new race")
	default:
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := c.ExchangeContext(canceled, q); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	query()
	select {
	case <-lookups:
		t.Fatal("caller cancellation invalidated winner")
	default:
	}
	failed.Store(true)
	query()
	waitLookups()
	before := fallbackCalls.Load()
	for range 5 {
		query()
	}
	if fallbackCalls.Load() != before+5 {
		t.Fatal("replacement winner not reused")
	}
	select {
	case <-lookups:
		t.Fatal("replacement winner caused another race")
	default:
	}
}

func TestAddressRaceDoesNotWaitForSlowAAAA(t *testing.T) {
	previous := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previous) })
	ip := netip.MustParseAddr("192.0.2.1")
	gate := make(chan struct{})
	close(gate)
	c := &addressRaceClient{host: "dns-race.test", r: addressRaceResolver{v4: []netip.Addr{ip}, v6Gate: make(chan struct{})}, clients: make(map[netip.Addr]*addressClientEntry)}
	c.new = func(ip netip.Addr) dnsClient {
		return &addressRaceStub{ip: ip, gate: gate, started: make(chan netip.Addr, 1)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	q := new(D.Msg)
	q.SetQuestion("example.test.", D.TypeA)
	if _, err := c.ExchangeContext(ctx, q); err != nil {
		t.Fatal(err)
	}
}

type addressRaceStub struct {
	ip       netip.Addr
	gate     <-chan struct{}
	started  chan<- netip.Addr
	canceled chan<- netip.Addr
}

func (s *addressRaceStub) Address() string  { return s.ip.String() }
func (s *addressRaceStub) ResetConnection() {}
func (s *addressRaceStub) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	s.started <- s.ip
	select {
	case <-s.gate:
		msg := new(D.Msg)
		msg.SetReply(q)
		return msg, nil
	case <-ctx.Done():
		s.canceled <- s.ip
		return nil, ctx.Err()
	}
}

func TestAddressRaceAllFamiliesAndCancellation(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")}
	previous := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previous) })
	for _, winner := range []netip.Addr{ips[1], ips[3]} {
		t.Run(winner.String(), func(t *testing.T) {
			gate := make(chan struct{})
			started, canceled := make(chan netip.Addr, 4), make(chan netip.Addr, 4)
			c := &addressRaceClient{host: "dns-race.test", r: addressRaceResolver{v4: ips[:2], v6: ips[2:]}, clients: make(map[netip.Addr]*addressClientEntry)}
			c.new = func(ip netip.Addr) dnsClient {
				var ready <-chan struct{}
				if ip == winner {
					ready = gate
				}
				return &addressRaceStub{ip: ip, gate: ready, started: started, canceled: canceled}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				q := new(D.Msg)
				q.SetQuestion("example.test.", D.TypeA)
				_, err := c.ExchangeContext(ctx, q)
				done <- err
			}()
			seen := make(map[netip.Addr]bool)
			for range ips {
				select {
				case ip := <-started:
					seen[ip] = true
				case <-ctx.Done():
					t.Fatal("not all candidates started")
				}
			}
			if len(seen) != len(ips) {
				t.Fatalf("candidates: %v", seen)
			}
			close(gate)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			for range len(ips) - 1 {
				select {
				case <-canceled:
				case <-ctx.Done():
					t.Fatal("losing queries not canceled")
				}
			}
		})
	}
}

func raceTestTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"dns-race.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}}, NextProtos: []string{NextProtoDQ}}
}

func TestAddressRaceUDPAndQUIC(t *testing.T) {
	previous := R.DisableIPv6.Load()
	R.DisableIPv6.Store(false)
	t.Cleanup(func() { R.DisableIPv6.Store(previous) })
	for _, protocol := range []string{"udp", "quic", "https-h3"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ips := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::1")}
			started := make(chan netip.Addr, len(ips))
			gate := make(chan struct{})
			var port string
			for _, ip := range ips {
				listenPort := port
				if listenPort == "" {
					listenPort = "0"
				}
				pc, err := net.ListenPacket("udp", net.JoinHostPort(ip.String(), listenPort))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { pc.Close() })
				_, port, _ = net.SplitHostPort(pc.LocalAddr().String())
				handle := func(q *D.Msg) *D.Msg {
					started <- ip
					if ip == ips[1] {
						select {
						case <-gate:
						case <-ctx.Done():
							return nil
						}
					} else {
						<-ctx.Done()
						return nil
					}
					msg := new(D.Msg)
					msg.SetReply(q)
					msg.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.2")}}
					return msg
				}
				if protocol == "udp" {
					server := &D.Server{PacketConn: pc, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
						if msg := handle(q); msg != nil {
							_ = w.WriteMsg(msg)
						}
					})}
					go server.ActivateAndServe()
					t.Cleanup(func() { server.Shutdown() })
				} else if protocol == "https-h3" {
					server := &http3.Server{TLSConfig: raceTestTLS(t), Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						buf, err := base64.RawURLEncoding.DecodeString(req.URL.Query().Get("dns"))
						if err != nil {
							return
						}
						q := new(D.Msg)
						if q.Unpack(buf) != nil {
							return
						}
						if req.Host != net.JoinHostPort("dns-race.test", port) {
							t.Error("HTTP/3 authority lost original hostname")
						}
						if req.TLS == nil || req.TLS.ServerName != "dns-race.test" {
							t.Error("HTTP/3 SNI lost original hostname")
						}
						if msg := handle(q); msg != nil {
							buf, _ = msg.Pack()
							w.Header().Set("Content-Type", "application/dns-message")
							_, _ = w.Write(buf)
						}
					})}
					go server.Serve(pc)
					t.Cleanup(func() { server.Close() })
				} else {
					transport := &quic.Transport{Conn: pc}
					listener, err := transport.Listen(raceTestTLS(t), nil)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { listener.Close(); transport.Close() })
					go func() {
						conn, err := listener.Accept(ctx)
						if err != nil {
							return
						}
						defer conn.CloseWithError(0, "")
						if conn.ConnectionState().TLS.ServerName != "dns-race.test" {
							t.Error("QUIC SNI lost original hostname")
						}
						stream, err := conn.AcceptStream(ctx)
						if err != nil {
							return
						}
						var size uint16
						if binary.Read(stream, binary.BigEndian, &size) != nil {
							return
						}
						buf := make([]byte, size)
						if _, err := io.ReadFull(stream, buf); err != nil {
							return
						}
						q := new(D.Msg)
						if q.Unpack(buf) != nil {
							return
						}
						msg := handle(q)
						if msg == nil {
							return
						}
						buf, _ = msg.Pack()
						_ = binary.Write(stream, binary.BigEndian, uint16(len(buf)))
						_, _ = stream.Write(buf)
						_ = stream.Close()
						<-ctx.Done()
					}()
				}
			}
			r := addressRaceResolver{v4: ips[:2], v6: ips[2:]}
			ns := NameServer{Net: protocol, Addr: net.JoinHostPort("dns-race.test", port), Params: map[string]string{"skip-cert-verify": "true"}}
			if protocol == "https-h3" {
				ns.Net = "https"
				ns.Addr = "https://" + ns.Addr + "/dns-query"
				ns.Params["h3"] = "true"
			}
			clients := transform([]NameServer{ns}, r)
			t.Cleanup(func() { clients[0].ResetConnection() })
			q := new(D.Msg)
			q.SetQuestion("example.test.", D.TypeA)
			done := make(chan error, 1)
			go func() {
				msg, err := clients[0].ExchangeContext(ctx, q)
				if err == nil && (msg == nil || len(msg.Answer) != 1 || msg.Id != q.Id) {
					err = errors.New("invalid winning response")
				}
				done <- err
			}()
			seen := make(map[netip.Addr]bool)
			for range ips {
				select {
				case ip := <-started:
					seen[ip] = true
				case <-ctx.Done():
					t.Fatal("not all UDP/QUIC candidates sent real queries on port " + strconv.Quote(port))
				}
			}
			if len(seen) != len(ips) {
				t.Fatalf("queries: %v", seen)
			}
			close(gate)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
