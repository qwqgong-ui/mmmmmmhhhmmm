package provider

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

type rejectInvalidationTunnel struct {
	invalidations atomic.Int32
	callback      *utils.Callback[P.RuleProvider]
}

func (*rejectInvalidationTunnel) Providers() map[string]P.ProxyProvider    { return nil }
func (*rejectInvalidationTunnel) RuleProviders() map[string]P.RuleProvider { return nil }
func (t *rejectInvalidationTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return t.callback
}
func (t *rejectInvalidationTunnel) InvalidateRejectCache() { t.invalidations.Add(1) }

func TestRuleProviderInvalidatesRejectBansBeforeUpdateCallback(t *testing.T) {
	previous := tunnel
	stub := &rejectInvalidationTunnel{callback: utils.NewCallback[P.RuleProvider]()}
	SetTunnel(stub)
	t.Cleanup(func() { SetTunnel(previous) })
	observed := make(chan int32, 2)
	listener := stub.callback.Register(func(P.RuleProvider) { observed <- stub.invalidations.Load() })
	defer listener.Close()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := NewRuleSetProvider("reject-invalidation-test", P.Domain, P.TextRule, 0, resource.NewFileVehicle(path), nil, nil, nil)
	defer provider.(*RuleSetProvider).Close()
	for i, payload := range []string{"example.com\n", "changed.example\n"} {
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := provider.Update(); err != nil {
			t.Fatal(err)
		}
		want := int32(i + 1)
		if stub.invalidations.Load() != want {
			t.Fatal("Update returned before synchronously invalidating the reject cache")
		}
		select {
		case actual := <-observed:
			if actual != want {
				t.Fatal("rule update callback ran before reject cache invalidation")
			}
		case <-time.After(time.Second):
			t.Fatal("rule update callback was not delivered")
		}
	}
	if err := provider.Update(); err != nil {
		t.Fatal(err)
	}
	if stub.invalidations.Load() != 2 {
		t.Fatal("unchanged rule-provider contents invalidated the reject cache")
	}
}
