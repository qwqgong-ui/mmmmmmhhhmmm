package dialer

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func installNetworkSampler(t *testing.T, f func(string) NetworkStatus) {
	t.Helper()
	old := readNetworkStatus
	networkStatusCache.Lock()
	clear(networkStatusCache.entries)
	networkStatusCache.Unlock()
	readNetworkStatus = f
	t.Cleanup(func() {
		readNetworkStatus = old
		networkStatusCache.Lock()
		clear(networkStatusCache.entries)
		networkStatusCache.Unlock()
	})
}

func TestNetworkStatusRefreshCoalescesAndTracksEvents(t *testing.T) {
	var calls atomic.Int32
	gate := make(chan struct{})
	installNetworkSampler(t, func(name string) NetworkStatus {
		calls.Add(1)
		<-gate
		return NetworkStatus{Interface: name, NetworkScope: name, AddressesKnown: true}
	})
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if s := cachedNetworkStatus("scope-a"); s.NetworkScope != "scope-a" {
				t.Error(s)
			}
		})
	}
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent samples=%d", calls.Load())
	}
	cachedNetworkStatus("scope-b")
	if calls.Load() != 2 {
		t.Fatal("interfaces share samples")
	}
	NotifyNetworkChange()
	cachedNetworkStatus("scope-a")
	if calls.Load() != 3 {
		t.Fatal("network event failed to invalidate")
	}
	networkStatusCache.Lock()
	entry := networkStatusCache.entries["scope-a"]
	entry.due = time.Now().Add(-time.Second)
	networkStatusCache.entries["scope-a"] = entry
	networkStatusCache.Unlock()
	for range 32 {
		wg.Go(func() { cachedNetworkStatus("scope-a") })
	}
	wg.Wait()
	if calls.Load() != 4 {
		t.Fatalf("expired samples=%d", calls.Load())
	}
}

func TestNetworkChangeDuringSamplingCannotPublishOldScope(t *testing.T) {
	var calls atomic.Int32
	installNetworkSampler(t, func(name string) NetworkStatus {
		n := calls.Add(1)
		if n == 1 {
			NotifyNetworkChange()
			return NetworkStatus{NetworkScope: "old"}
		}
		return NetworkStatus{NetworkScope: "new"}
	})
	if s := cachedNetworkStatus("scope"); s.NetworkScope != "new" {
		t.Fatal(s)
	}
	if s := cachedNetworkStatus("scope"); s.NetworkScope != "new" || calls.Load() != 2 {
		t.Fatalf("%+v samples=%d", s, calls.Load())
	}
}

func TestRepeatedNetworkChangesUseIsolatedTransitionScope(t *testing.T) {
	installNetworkSampler(t, func(string) NetworkStatus { NotifyNetworkChange(); return NetworkStatus{NetworkScope: "old"} })
	a, b := cachedNetworkStatus("scope-a"), cachedNetworkStatus("scope-b")
	if a.NetworkScope == "old" || a.NetworkScope == b.NetworkScope || a.Reason != "network_changed_during_sample" {
		t.Fatalf("%+v %+v", a, b)
	}
}

func TestNetworkScopeUsesCurrentInterfaceAndPlatformIdentity(t *testing.T) {
	oldEnv, oldInterface := directNetworkEnvironment.Swap(""), DefaultInterface.Load()
	t.Cleanup(func() { directNetworkEnvironment.Store(oldEnv); DefaultInterface.Store(oldInterface) })
	var calls atomic.Int32
	installNetworkSampler(t, func(name string) NetworkStatus { calls.Add(1); return NetworkStatus{NetworkScope: name} })
	DefaultInterface.Store("a")
	if s := NetworkScope(); s != "a" {
		t.Fatal(s)
	}
	DefaultInterface.Store("b")
	if s := NetworkScope(); s != "b" {
		t.Fatal(s)
	}
	directNetworkEnvironment.Store("platform")
	if s := NetworkScope(); s != EnvironmentScope("platform") || calls.Load() != 2 {
		t.Fatalf("%s calls=%d", s, calls.Load())
	}
	directNetworkEnvironment.Store("")
	if s := NetworkScope(); s != "b" {
		t.Fatal(s)
	}
}
