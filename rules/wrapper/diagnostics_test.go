package wrapper

import (
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/rules/common"
	"testing"
)

func TestDiagnosticMatchDoesNotCountTraffic(t *testing.T) {
	r := NewRuleWrapper(common.NewDomain("example.test", "DIRECT"))
	for _, host := range []string{"example.test", "other.test"} {
		r.Match(&C.Metadata{Host: host}, C.RuleMatchHelper{Diagnostic: true})
	}
	if r.HitCount() != 0 || r.MissCount() != 0 {
		t.Fatal("diagnostic polluted traffic counters")
	}
	r.Match(&C.Metadata{Host: "example.test"}, C.RuleMatchHelper{})
	if r.HitCount() != 1 {
		t.Fatal("normal traffic no longer counted")
	}
}
