package cachefile

import (
	"errors"
	"github.com/metacubex/bbolt"
)

var bucketDevCache = []byte("dev_cache_v1")

func (c *CacheFile) DevCache() (data []byte, err error) {
	if c.DB == nil {
		return nil, errors.New("cache database unavailable")
	}
	err = c.DB.View(func(tx *bbolt.Tx) error {
		if b := tx.Bucket(bucketDevCache); b != nil {
			data = append([]byte(nil), b.Get([]byte("snapshot"))...)
		}
		return nil
	})
	return
}

func (c *CacheFile) SetDevCache(data []byte) error {
	if c.DB == nil {
		return errors.New("cache database unavailable")
	}
	return c.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketDevCache)
		if err != nil {
			return err
		}
		return b.Put([]byte("snapshot"), data)
	})
}
