package bitwarden

import (
	"fmt"
	"sync"
)

// TODO: generalize cipher index and move to pm/utils.go

type cacheKey struct {
	// plaintext
	// item name
	ItemName string

	// plaintext
	// field name or attachment filename
	ItemKey string
}

type cacheValue struct {
	// encrypted value
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
	// key combination
	itemName, itemKey string,
	// values
	value []byte, url string, key *bitwardenKey,
) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.m[cacheKey{
		ItemName: itemName,
		ItemKey:  itemKey,
	}] = &cacheValue{
		Value: value,
		URL:   url,
		Key:   key,
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

func (d *cipherCache) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()

	keys := make([]*cacheKey, len(d.m))
	i := 0
	for k := range d.m {
		keys[i] = &cacheKey{
			ItemName: k.ItemName,
			ItemKey:  k.ItemKey,
		}

		i++
	}

	for _, k := range keys {
		delete(d.m, *k)
	}

	if len(d.m) != 0 {
		panic(fmt.Errorf("cache not cleared, %d remains", len(d.m)))
	}
}
