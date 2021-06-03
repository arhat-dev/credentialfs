package fs

import (
	"context"
	"sync"
	"time"

	"arhat.dev/pkg/queue"

	"arhat.dev/credentialfs/pkg/auth"
)

func newAuthManager() *authManager {
	return &authManager{
		tq: queue.NewTimeoutQueue(),
		mu: &sync.Mutex{},
	}
}

type authManager struct {
	tq *queue.TimeoutQueue
	mu *sync.Mutex
}

type (
	timeoutDataKey struct {
		authReqKey string
	}

	timeoutDataValue struct {
		timeout  time.Duration
		authData auth.AuthorizationData
	}
)

// Start in background
func (m *authManager) Start(ctx context.Context) {
	m.tq.Start(ctx.Done())
	ch := m.tq.TakeCh()

	go func() {
		for td := range ch {
			k := td.Data.(*timeoutDataValue)
			err := auth.DestroyAuthorization(k.authData)
			if err != nil {
				// TODO: log error

				// retry in 1s
				_ = m.tq.OfferWithDelay(td.Key, td.Data, time.Second)
			}
		}
	}()
}

// RequestAuth checks if the authorization is still valid before actually request
// user authorization
// the lock is required to make auth request sequential
func (m *authManager) RequestAuth(authReqKey, prompt string) (auth.AuthorizationData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// requested this request
	v, ok := m.tq.Find(timeoutDataKey{
		authReqKey: authReqKey,
	})
	if ok {
		return v.(*timeoutDataValue).authData, nil
	}

	return auth.RequestAuthorization(authReqKey, prompt)
}

// ScheduleAuthDestroy after a successful auth, it makes sure there will be only one
// timeout task for one authReqKey in queue
//
// caller should not allow further operation if the returned error is not nil
func (m *authManager) ScheduleAuthDestroy(
	authReqKey string,
	authData auth.AuthorizationData,
	after time.Duration,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if after == 0 {
		return auth.DestroyAuthorization(authData)
	}

	v, ok := m.tq.Find(timeoutDataKey{
		authReqKey: authReqKey,
	})
	if ok {
		if v.(*timeoutDataValue).authData != authData {
			// TODO: possible memory leak!
			_ = authData
		}

		return nil
	}

	return m.tq.OfferWithDelay(timeoutDataKey{
		authReqKey: authReqKey,
	}, &timeoutDataValue{
		authData: authData,
		timeout:  after,
	}, after)
}
