package cachefile

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

type FakeIpStore struct {
	*CacheFile
	bucketName []byte

	writeMu sync.Mutex
	viewMu  sync.RWMutex
	// Only keys touched by an unconfirmed write are kept here. nil means the
	// key was absent before the write; all other reads still use the database.
	before map[string][]byte
}

func (c *CacheFile) FakeIpStore() *FakeIpStore {
	return c.fakeIpStore(0, bucketFakeip)
}

func (c *CacheFile) FakeIpStore6() *FakeIpStore {
	return c.fakeIpStore(1, bucketFakeip6)
}

func (c *CacheFile) fakeIpStore(index int, bucketName []byte) *FakeIpStore {
	c.fakeipOnce[index].Do(func() {
		c.fakeipStores[index] = &FakeIpStore{CacheFile: c, bucketName: bucketName}
	})
	return c.fakeipStores[index]
}

// PutMapping commits both directions together, including replacement of a
// recycled IP. DB.Update avoids Batch's timer on the DNS response path; readers
// continue to use the previous committed snapshot until the pair is durable.
func (c *FakeIpStore) PutMapping(host string, ip netip.Addr) error {
	if c.DB == nil {
		return errors.New("cache database unavailable")
	}
	return c.putMapping(host, ip, c.DB.Update)
}

func (c *FakeIpStore) putMapping(host string, ip netip.Addr, commit func(func(*bbolt.Tx) error) error) error {
	addr := ip.AsSlice()
	return c.mutate(commit, func(_ *bbolt.Bucket, remember func([]byte) []byte) error {
		oldHost := remember(addr)
		remember([]byte(host))
		if len(oldHost) > 0 {
			remember(oldHost)
		}
		return nil
	}, func(_ *bbolt.Tx, bucket *bbolt.Bucket) error {
		if oldHost := bucket.Get(addr); len(oldHost) > 0 {
			if err := bucket.Delete(oldHost); err != nil {
				return err
			}
		}
		if err := bucket.Put(addr, []byte(host)); err != nil {
			return err
		}
		return bucket.Put([]byte(host), addr)
	})
}

// mutate keeps affected reads on the last confirmed values while bbolt writes
// and syncs. Its meta page can become visible before the final sync returns,
// including when that sync fails. The next successful mutation also repairs
// any such unconfirmed values before applying its own changes.
func (c *FakeIpStore) mutate(
	commit func(func(*bbolt.Tx) error) error,
	prepare func(*bbolt.Bucket, func([]byte) []byte) error,
	change func(*bbolt.Tx, *bbolt.Bucket) error,
) error {
	if c.DB == nil {
		return errors.New("cache database unavailable")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.viewMu.Lock()
	before := make(map[string][]byte, len(c.before)+3)
	for key, value := range c.before {
		before[key] = value
	}
	err := c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(c.bucketName)
		remember := func(key []byte) []byte {
			name := string(key)
			if value, ok := before[name]; ok {
				return value
			}
			var value []byte
			if bucket != nil {
				value = bytes.Clone(bucket.Get(key))
			}
			before[name] = value
			return value
		}
		return prepare(bucket, remember)
	})
	if err == nil {
		c.before = before
	}
	c.viewMu.Unlock()
	if err != nil {
		return err
	}

	// Never hold viewMu during disk I/O or Batch's merge timer.
	err = commit(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(c.bucketName)
		if err != nil {
			return err
		}
		for key, value := range before {
			key := []byte(key)
			if bytes.Equal(bucket.Get(key), value) {
				continue
			}
			if value == nil {
				err = bucket.Delete(key)
			} else {
				err = bucket.Put(key, value)
			}
			if err != nil {
				return err
			}
		}
		return change(t, bucket)
	})

	c.viewMu.Lock()
	if err == nil {
		c.before = nil
	} else {
		// Callback errors usually leave the old snapshot intact. Retain only
		// differences so repeated failures do not accumulate unrelated keys.
		pending := make(map[string][]byte)
		if viewErr := c.DB.View(func(t *bbolt.Tx) error {
			bucket := t.Bucket(c.bucketName)
			for key, value := range before {
				var current []byte
				if bucket != nil {
					current = bucket.Get([]byte(key))
				}
				if !bytes.Equal(current, value) {
					pending[key] = value
				}
			}
			return nil
		}); viewErr == nil {
			c.before = pending
		}
	}
	c.viewMu.Unlock()
	return err
}

func (c *FakeIpStore) GetByHost(host string) (ip netip.Addr, exist bool) {
	if c.DB == nil {
		return
	}
	c.viewMu.RLock()
	defer c.viewMu.RUnlock()
	if value, ok := c.before[host]; ok {
		return netip.AddrFromSlice(value)
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(c.bucketName); bucket != nil {
			if v := bucket.Get([]byte(host)); v != nil {
				ip, exist = netip.AddrFromSlice(v)
			}
		}
		return nil
	})
	return
}

func (c *FakeIpStore) PutByHost(host string, ip netip.Addr) {
	if c.DB == nil {
		return
	}
	err := c.mutate(c.DB.Batch, func(_ *bbolt.Bucket, remember func([]byte) []byte) error {
		remember([]byte(host))
		return nil
	}, func(_ *bbolt.Tx, bucket *bbolt.Bucket) error {
		return bucket.Put([]byte(host), ip.AsSlice())
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) GetByIP(ip netip.Addr) (host string, exist bool) {
	if c.DB == nil {
		return
	}
	c.viewMu.RLock()
	defer c.viewMu.RUnlock()
	if value, ok := c.before[string(ip.AsSlice())]; ok {
		return string(value), len(value) > 0
	}
	c.DB.View(func(t *bbolt.Tx) error {
		if bucket := t.Bucket(c.bucketName); bucket != nil {
			if v := bucket.Get(ip.AsSlice()); v != nil {
				host, exist = string(v), true
			}
		}
		return nil
	})
	return
}

func (c *FakeIpStore) PutByIP(ip netip.Addr, host string) {
	if c.DB == nil {
		return
	}
	err := c.mutate(c.DB.Batch, func(_ *bbolt.Bucket, remember func([]byte) []byte) error {
		remember(ip.AsSlice())
		return nil
	}, func(_ *bbolt.Tx, bucket *bbolt.Bucket) error {
		return bucket.Put(ip.AsSlice(), []byte(host))
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) DelByIP(ip netip.Addr) {
	if c.DB == nil {
		return
	}

	addr := ip.AsSlice()
	err := c.mutate(c.DB.Batch, func(_ *bbolt.Bucket, remember func([]byte) []byte) error {
		host := remember(addr)
		if len(host) > 0 {
			remember(host)
		}
		return nil
	}, func(_ *bbolt.Tx, bucket *bbolt.Bucket) error {
		host := bucket.Get(addr)
		if err := bucket.Delete(addr); err != nil {
			return err
		}
		if len(host) > 0 {
			return bucket.Delete(host)
		}
		return nil
	})
	if err != nil {
		log.Warnln("[CacheFile] write cache to %s failed: %s", c.DB.Path(), err.Error())
	}
}

func (c *FakeIpStore) FlushFakeIP() error {
	if c.DB == nil {
		return errors.New("cache database unavailable")
	}
	return c.mutate(c.DB.Batch, func(bucket *bbolt.Bucket, remember func([]byte) []byte) error {
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(key, _ []byte) error {
			remember(key)
			return nil
		})
	}, func(t *bbolt.Tx, _ *bbolt.Bucket) error {
		return t.DeleteBucket(c.bucketName)
	})
}
