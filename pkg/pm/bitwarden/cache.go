package bitwarden

import (
	"sync"
)

func newCacheSet() *cacheSet {
	return &cacheSet{
		m: make(map[cacheKey]*cacheValue),
	}
}

type cacheSet struct {
	m map[cacheKey]*cacheValue
}

func (s *cacheSet) Add(
	// key combination
	itemName, itemKey string,
	// values
	cipherID string,
	value []byte, url string,
	key *bitwardenKey,
) {
	s.m[cacheKey{
		ItemName: itemName,
		ItemKey:  itemKey,
	}] = &cacheValue{
		CipherID: cipherID,
		Value:    value,
		URL:      url,
		Key:      key,
	}
}

func (s *cacheSet) Get(itemName, itemKey string) *cacheValue {
	return s.m[cacheKey{ItemName: itemName, ItemKey: itemKey}]
}

type cacheKey struct {
	// plaintext
	// item name
	ItemName string

	// plaintext
	// field name or attachment filename
	ItemKey string
}

type cacheValue struct {
	// CipherID this value belongs to
	CipherID string

	// plaintext value
	Value []byte

	// plaintext url for attachment
	URL string

	// decrypted attachment key or org key
	Key *bitwardenKey
}

func newCipherCache() *cipherCache {
	return &cipherCache{
		m:  make(map[cacheKey]*cacheValue),
		mu: &sync.RWMutex{},
	}
}

type cipherCache struct {
	m map[cacheKey]*cacheValue

	mu *sync.RWMutex
}

func (d *cipherCache) Add(
	s *cacheSet,
) {
	if s == nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for k := range s.m {
		d.m[k] = s.m[k]
	}
}

func (d *cipherCache) Get(
	itemName, itemKey string,
) *cacheValue {
	d.mu.RLock()
	defer d.mu.RUnlock()

	val, ok := d.m[cacheKey{
		ItemName: itemName,
		ItemKey:  itemKey,
	}]
	if !ok {
		return nil
	}

	return val
}

func (d *cipherCache) Clear(filter func(k cacheKey, v *cacheValue) bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var keys []*cacheKey
	for k, v := range d.m {
		if !filter(k, v) {
			continue
		}

		keys = append(keys, &cacheKey{
			ItemName: k.ItemName,
			ItemKey:  k.ItemKey,
		})
	}

	for _, k := range keys {
		delete(d.m, *k)
	}
}
