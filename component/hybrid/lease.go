package hybrid

import (
	"crypto/sha256"
	"errors"
	"time"
)

// The real QUIC packet is also sent on the stream. Only its digest is used
// as a one-use raw-path proof; no marker is added to UDP.
func (f *clientFlow) requestLeaseLocked(p []byte, now time.Time) error {
	if f.leaseProbe != nil {
		return nil
	}
	f.leaseSeq++
	f.leaseSent = now
	f.leaseProbe = append([]byte(nil), p...)
	return writeLease(f.stream, leaseControl{kind: leaseBind, seq: f.leaseSeq, digest: sha256.Sum256(p)})
}
func (f *clientFlow) acceptLease(c leaseControl) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	if !f.lease || (c.kind != leaseBound && c.kind != leaseRenewed && c.kind != leaseConfirmed) {
		return errors.New("hybrid: unexpected server lease control")
	}
	if f.disabled.Load() || c.seq != f.leaseSeq {
		return nil
	}
	// Start from request transmission, not ACK arrival: network delay cannot
	// extend the client's permission past the server's 30-second lease.
	until := f.leaseSent.Add(leaseDuration)
	if !time.Now().Before(until) {
		return nil
	}
	f.leaseUntil.Store(until.UnixNano())
	f.leaseNext = f.leaseSent.Add(10 * time.Second)
	if c.kind == leaseConfirmed {
		f.probeEnd = time.Time{}
		f.lastRaw.Store(time.Now().UnixNano())
		f.confirmedRaw.Store(true)
		if !f.active.Swap(true) {
			f.diagnostic.countOne(rawActivations)
		}
		f.diagnostic.update("raw", f.relay.String(), "", false, false)
	}
	return nil
}

func (f *clientFlow) confirmLeasePacket(p []byte) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	if f.disabled.Load() || f.active.Load() || time.Now().UnixNano() >= f.leaseUntil.Load() {
		return nil
	}
	return writeLease(f.stream, leaseControl{kind: leaseActivate, seq: f.leaseSeq, digest: sha256.Sum256(p)})
}
