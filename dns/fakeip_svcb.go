package dns

import (
	"net"
	"strings"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

type serviceRRSet struct {
	name   string
	rrType uint16
}

// rewriteFakeIPServiceBindings turns upstream SVCB/HTTPS address hints into
// addresses owned by the fake-IP pools. It deliberately leaves AliasMode
// records untouched so the client can follow the alias before a ServiceMode
// record is synthesized.
func rewriteFakeIPServiceBindings(msg *D.Msg, fakePool, fakePool6 *fakeip.Pool, fakeIPTTL int) bool {
	modifiedRRsets := map[serviceRRSet]struct{}{}
	if log.Enabled(log.DEBUG) {
		before := InspectMessage(msg)
		defer func() {
			reason := "rrsets_unchanged_dnssec_preserved"
			if len(modifiedRRsets) > 0 {
				reason = "hints_rewritten_affected_rrsig_and_ad_cleared"
			}
			log.Fields(log.DEBUG, map[string]string{"subsystem": "dns", "event": "fakeip_service_binding", "host": msgToDomain(msg), "reason": reason}, "Fake-IP HTTPS/SVCB bindings %+v -> %+v; AD=%t -> %t; %s", before.Bindings, InspectMessage(msg).Bindings, before.AuthenticatedData, msg.AuthenticatedData, reason)
		}()
	}

	rewriteSection := func(records []D.RR) {
		for _, record := range records {
			var (
				owner    string
				rrType   uint16
				priority uint16
				target   string
				values   []D.SVCBKeyValue
				setValue func([]D.SVCBKeyValue)
			)

			switch rr := record.(type) {
			case *D.HTTPS:
				owner = rr.Hdr.Name
				rrType = D.TypeHTTPS
				priority = rr.Priority
				target = rr.Target
				values = rr.Value
				setValue = func(value []D.SVCBKeyValue) { rr.Value = value }
			case *D.SVCB:
				owner = rr.Hdr.Name
				rrType = D.TypeSVCB
				priority = rr.Priority
				target = rr.Target
				values = rr.Value
				setValue = func(value []D.SVCBKeyValue) { rr.Value = value }
			default:
				continue
			}

			if priority == 0 { // AliasMode parameters are ignored by clients.
				continue
			}

			effectiveTarget := strings.TrimSuffix(target, ".")
			if target == "." {
				effectiveTarget = strings.TrimSuffix(owner, ".")
			}

			rewritten, changed := rewriteFakeIPSVCBValues(effectiveTarget, values, fakePool, fakePool6)
			if !changed {
				continue
			}

			setValue(rewritten)
			ttl := max(fakeIPTTL, 1)
			record.Header().Ttl = uint32(ttl)
			modifiedRRsets[newServiceRRSet(owner, rrType)] = struct{}{}
		}
	}

	rewriteSection(msg.Answer)
	rewriteSection(msg.Ns)
	rewriteSection(msg.Extra)
	if len(modifiedRRsets) == 0 {
		return false
	}

	msg.Answer = removeServiceRRSIG(msg.Answer, modifiedRRsets)
	msg.Ns = removeServiceRRSIG(msg.Ns, modifiedRRsets)
	msg.Extra = removeServiceRRSIG(msg.Extra, modifiedRRsets)
	msg.AuthenticatedData = false
	return true
}

func rewriteFakeIPSVCBValues(
	effectiveTarget string,
	values []D.SVCBKeyValue,
	fakePool, fakePool6 *fakeip.Pool,
) ([]D.SVCBKeyValue, bool) {
	allowIPv4 := effectiveTarget != "" && fakePool != nil && fakePool.IPNet().Addr().Is4()
	allowIPv6 := effectiveTarget != "" && fakePool6 != nil && fakePool6.IPNet().Addr().Is6()
	// Preserve the upstream ECHConfig. Domain recovery does not depend on the
	// cleartext ClientHello because every retained address hint is rewritten to
	// an effective-target fake IP that can be looked back up by the tunnel.
	removedKeys := map[D.SVCBKey]bool{
		D.SVCB_IPV4HINT: !allowIPv4,
		D.SVCB_IPV6HINT: !allowIPv6,
	}

	// Assigned hint keys with an unexpected representation cannot be safely
	// rewritten. Drop them, and keep mandatory consistent, instead of leaking
	// the upstream endpoint.
	for _, value := range values {
		switch value.Key() {
		case D.SVCB_IPV4HINT:
			if _, ok := value.(*D.SVCBIPv4Hint); !ok {
				removedKeys[D.SVCB_IPV4HINT] = true
			}
		case D.SVCB_IPV6HINT:
			if _, ok := value.(*D.SVCBIPv6Hint); !ok {
				removedKeys[D.SVCB_IPV6HINT] = true
			}
		}
	}

	rewritten := make([]D.SVCBKeyValue, 0, len(values))
	changed := false
	var fakeIPv4, fakeIPv6 net.IP

	for _, value := range values {
		switch value.Key() {
		case D.SVCB_IPV4HINT:
			if removedKeys[D.SVCB_IPV4HINT] {
				changed = true
				continue
			}
			if fakeIPv4 == nil {
				fakeIPv4 = net.IP(fakePool.Lookup(effectiveTarget).AsSlice())
			}
			hint := value.(*D.SVCBIPv4Hint)
			if len(hint.Hint) == 1 && hint.Hint[0].Equal(fakeIPv4) {
				rewritten = append(rewritten, value)
				continue
			}
			rewritten = append(rewritten, &D.SVCBIPv4Hint{Hint: []net.IP{fakeIPv4}})
			changed = true

		case D.SVCB_IPV6HINT:
			if removedKeys[D.SVCB_IPV6HINT] {
				changed = true
				continue
			}
			if fakeIPv6 == nil {
				fakeIPv6 = net.IP(fakePool6.Lookup(effectiveTarget).AsSlice())
			}
			hint := value.(*D.SVCBIPv6Hint)
			if len(hint.Hint) == 1 && hint.Hint[0].Equal(fakeIPv6) {
				rewritten = append(rewritten, value)
				continue
			}
			rewritten = append(rewritten, &D.SVCBIPv6Hint{Hint: []net.IP{fakeIPv6}})
			changed = true

		case D.SVCB_MANDATORY:
			mandatory, ok := value.(*D.SVCBMandatory)
			if !ok {
				changed = true
				continue
			}
			codes := make([]D.SVCBKey, 0, len(mandatory.Code))
			for _, code := range mandatory.Code {
				if removedKeys[code] {
					changed = true
					continue
				}
				codes = append(codes, code)
			}
			if len(codes) == 0 {
				changed = true
				continue
			}
			if len(codes) == len(mandatory.Code) {
				rewritten = append(rewritten, value)
				continue
			}
			rewritten = append(rewritten, &D.SVCBMandatory{Code: codes})

		default:
			rewritten = append(rewritten, value)
		}
	}

	return rewritten, changed
}

func newServiceRRSet(name string, rrType uint16) serviceRRSet {
	return serviceRRSet{name: strings.ToLower(D.Fqdn(name)), rrType: rrType}
}

func removeServiceRRSIG(records []D.RR, modified map[serviceRRSet]struct{}) []D.RR {
	filtered := records[:0]
	for _, record := range records {
		if signature, ok := record.(*D.RRSIG); ok {
			if _, invalid := modified[newServiceRRSet(signature.Hdr.Name, signature.TypeCovered)]; invalid {
				continue
			}
		}
		filtered = append(filtered, record)
	}
	return filtered
}
