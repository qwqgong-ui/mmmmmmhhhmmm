package cachefile

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/metacubex/bbolt"
)

var bucketDNSCache = []byte("dnscache")

// DNSEntry is one persisted DNS answer: the cache key, the packed DNS message
// and the moment the answer expires. Expiry is stored explicitly because the
// ARC cache does not evict on expiry, so a restored entry would otherwise be
// indistinguishable from a fresh one.
type DNSEntry struct {
	Key     string
	Msg     []byte
	Expires time.Time
}

// SetDNSCache replaces the persisted DNS cache with entries.
//
// The whole snapshot is written in a single transaction: the cache holds up to
// cache-max-size entries, and writing them one at a time would turn an hourly
// save into tens of thousands of bbolt commits.
func (c *CacheFile) SetDNSCache(entries []DNSEntry) error {
	if c.DB == nil {
		return errors.New("cache database unavailable")
	}

	// Update, not Batch: Batch defers the commit to coalesce callers, and the
	// shutdown path exits before that fires, so the snapshot was silently lost.
	return c.DB.Update(func(t *bbolt.Tx) error {
		if err := t.DeleteBucket(bucketDNSCache); err != nil && err != bbolt.ErrBucketNotFound {
			return err
		}
		bucket, err := t.CreateBucket(bucketDNSCache)
		if err != nil {
			return err
		}
		buf := make([]byte, 8)
		for _, entry := range entries {
			binary.BigEndian.PutUint64(buf, uint64(entry.Expires.Unix()))
			if err := bucket.Put([]byte(entry.Key), append(buf[:8:8], entry.Msg...)); err != nil {
				return err
			}
		}
		return nil
	})
}

// DNSCache returns every persisted DNS answer. A malformed record is dropped
// rather than failing the whole restore.
func (c *CacheFile) DNSCache() []DNSEntry {
	entries, _ := c.ReadDNSCache()
	return entries
}

func (c *CacheFile) ReadDNSCache() ([]DNSEntry, error) {
	if c.DB == nil {
		return nil, errors.New("cache database unavailable")
	}

	var entries []DNSEntry
	err := c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketDNSCache)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			if len(v) <= 8 {
				return nil
			}
			msg := make([]byte, len(v)-8)
			copy(msg, v[8:])
			entries = append(entries, DNSEntry{
				Key:     string(k),
				Msg:     msg,
				Expires: time.Unix(int64(binary.BigEndian.Uint64(v[:8])), 0),
			})
			return nil
		})
	})
	return entries, err
}

// FlushDNSCache drops the persisted DNS cache.
func (c *CacheFile) FlushDNSCache() error {
	if c.DB == nil {
		return nil
	}
	return c.DB.Batch(func(t *bbolt.Tx) error {
		if err := t.DeleteBucket(bucketDNSCache); err != nil && err != bbolt.ErrBucketNotFound {
			return err
		}
		return nil
	})
}
