package cachefile

import "testing"

func TestUnavailableDNSCacheReportsFailure(t *testing.T) {
	c := new(CacheFile)
	if err := c.SetDNSCache(nil); err == nil {
		t.Fatal("unavailable database reported successful flush")
	}
	if _, err := c.ReadDNSCache(); err == nil {
		t.Fatal("unavailable database reported successful load")
	}
}
