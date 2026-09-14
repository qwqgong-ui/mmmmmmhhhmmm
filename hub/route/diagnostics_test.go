package route

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestDiagnosticRoutesAreAuthenticated(t *testing.T) {
	handler := router(true, "secret", "", Cors{})

	request := httptest.NewRequest(http.MethodGet, "/network", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /network status = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/network", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated /network status = %d: %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/debug/path", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /debug/path status = %d", response.Code)
	}
}

func TestAllDiagnosticRoutesRequireAuthentication(t *testing.T) {
	for _, debug := range []bool{false, true} {
		h := router(debug, "secret", "", Cors{})
		for _, path := range []string{"/network", "/dns/cache", "/dns/server-capabilities", "/direct/winners", "/hybrid-quic/stats", "/hybrid-quic/flows", "/debug/path?host=example.test", "/stats/downstream"} {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("debug=%t path=%s status=%d", debug, path, w.Code)
			}
			r = httptest.NewRequest(http.MethodGet, path, nil)
			r.Header.Set("Authorization", "Bearer secret")
			w = httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("path=%s status=%d body=%s", path, w.Code, w.Body.String())
			}
		}
	}
}

func TestDiagnosticTargetValidation(t *testing.T) {
	for _, v := range []struct{ host, port string }{{"", ""}, {"a.test", "0"}, {"a.test", "65536"}, {"a.test", "bad"}, {"https://a.test", ""}, {"a..test", ""}, {"a.test:443", "8443"}} {
		if _, _, err := diagnosticTarget(v.host, v.port); err == nil {
			t.Fatalf("accepted %+v", v)
		}
	}
	for _, v := range []struct {
		input, want string
		port        uint16
	}{{"EXAMPLE.test.", "example.test", 443}, {"example.test:8443", "example.test", 8443}, {"2001:db8::1", "2001:db8::1", 443}} {
		h, p, err := diagnosticTarget(v.input, "")
		if err != nil || h != v.want || p != v.port {
			t.Fatalf("%+v => %s %d %v", v, h, p, err)
		}
	}
}

type diagnosticServiceSpy struct{ calls atomic.Int32 }

func (s *diagnosticServiceSpy) ServeMsg(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	s.calls.Add(1)
	return nil, errors.New("test DNS unavailable")
}

type emptyDiagnosticResolver struct{ resolver.Resolver }

func (emptyDiagnosticResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}
func (emptyDiagnosticResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func TestDebugPathDefaultDoesNotProbe(t *testing.T) {
	old := resolver.DefaultService
	spy := new(diagnosticServiceSpy)
	resolver.DefaultService = spy
	defer func() { resolver.DefaultService = old }()
	w := httptest.NewRecorder()
	debugPath(w, httptest.NewRequest(http.MethodGet, "/debug/path?host=example.test", nil))
	if w.Code != http.StatusOK || spy.calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, spy.calls.Load())
	}
	var body struct {
		Active bool `json:"activeQueries"`
		DNS    struct {
			Queries []pathQuery `json:"queries"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Active || len(body.DNS.Queries) != 0 {
		t.Fatalf("body=%s err=%v", w.Body.String(), err)
	}
}

func TestActivePathReportsErrorsAndDoesNotQueryDirectForProxy(t *testing.T) {
	old := resolver.DisableIPv6.Swap(false)
	defer resolver.DisableIPv6.Store(old)
	spy := new(diagnosticServiceSpy)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, allow := range []bool{false, true} {
		got := queryPath(ctx, "example.test", "scope", spy, emptyDiagnosticResolver{}, allow)
		want := 4
		if allow {
			want = 6
		}
		if len(got) != want {
			t.Fatal(got)
		}
		for _, q := range got {
			if q.State != "error" || q.Error == "" {
				t.Fatalf("silent failure %+v", q)
			}
			if !allow && q.Source == "direct_nameserver" {
				t.Fatal("proxy queried DIRECT")
			}
		}
	}
}

func TestActivePathCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := queryPath(ctx, "example.test", "scope", nil, nil, false)
	if len(got) != 4 {
		t.Fatal(got)
	}
}
