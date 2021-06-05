package bitwarden

import (
	"sync"

	"arhat.dev/credentialfs/pkg/pm"
)

type subKey struct {
	cipherID string
}

type subValue struct {
	subID string
}

func newSubManager() *subManager {
	return &subManager{
		m: make(map[subKey][]*subValue),

		mu: &sync.RWMutex{},
	}
}

type subManager struct {
	m map[subKey][]*subValue

	mu *sync.RWMutex
}

func (m *subManager) Add(subID, cipherID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := subKey{cipherID: cipherID}
	val, ok := m.m[k]
	if ok {
		for _, v := range val {
			if v.subID == subID {
				return
			}
		}

		m.m[k] = append(m.m[k], &subValue{subID: subID})
	} else {
		m.m[k] = []*subValue{{
			subID: subID,
		}}
	}
}

// Check cipherID is subscribed
func (m *subManager) Check(cipherID string, subID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.m[subKey{cipherID: cipherID}]
	if !ok {
		return false
	}

	for _, v := range val {
		if v.subID == subID {
			return true
		}
	}

	return false
}

func (m *subManager) PrepareUpdates(cipherID string) []*pm.CredentialUpdate {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, ok := m.m[subKey{cipherID: cipherID}]
	if !ok {
		return nil
	}

	result := make([]*pm.CredentialUpdate, len(val))
	for i, v := range val {
		result[i] = &pm.CredentialUpdate{
			Key: v.subID,
		}
	}

	return result
}
