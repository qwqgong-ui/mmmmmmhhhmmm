package dialer

import "testing"

func TestNetworkGenerationFollowsPlatformChanges(t *testing.T) {
	previous := directNetworkEnvironment.Load()
	t.Cleanup(func() { SetDirectNetworkEnvironment(previous) })
	SetDirectNetworkEnvironment("mtu-test-wifi")
	generation := NetworkGeneration()
	SetDirectNetworkEnvironment(" mtu-test-wifi ")
	if got := NetworkGeneration(); got != generation {
		t.Fatalf("unchanged environment invalidated cache: %d -> %d", generation, got)
	}
	SetDirectNetworkEnvironment("mtu-test-mobile")
	if got := NetworkGeneration(); got <= generation {
		t.Fatal("network handover did not invalidate caches")
	}
}
