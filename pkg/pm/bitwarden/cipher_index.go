package bitwarden

import "sync"

// TODO: generalize cipher index and move to pm/utils.go

func newCipherIndex() *cipherIndex {
	return &cipherIndex{
		m: &sync.Map{},
	}
}

type cipherIndex struct {
	m *sync.Map
}

func (d *cipherIndex) updateCipherIndex(
	// key combination
	itemName, itemKey string,
	// values
	value []byte, url string, key *bitwardenKey,
) {
	d.m.Store(cipherIndexKey{
		ItemName: itemName,
		ItemKey:  itemKey,
	}, &cipherValue{
		Value: value,
		URL:   url,
		Key:   key,
	})
}

func (d *cipherIndex) lookupIndexedCipher(
	itemName, itemKey string,
) *cipherValue {
	val, ok := d.m.Load(cipherIndexKey{
		ItemName: itemName,
		ItemKey:  itemKey,
	})
	if !ok {
		return nil
	}

	return val.(*cipherValue)
}
