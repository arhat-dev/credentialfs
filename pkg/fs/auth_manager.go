package fs

import (
	"context"
	"sync"
	"time"

	"arhat.dev/pkg/queue"
	"go.uber.org/multierr"

	"arhat.dev/credentialfs/pkg/auth"
)

func newAuthManager(runningCtx context.Context) *authManager {
	ctx, cancel := context.WithCancel(runningCtx)

	return &authManager{
		ctx:    ctx,
		cancel: cancel,

		workerExited: make(chan struct{}),

		tq: queue.NewTimeoutQueue(),

		pendingDestroyTasks: &sync.Map{},

		mu: &sync.Mutex{},
	}
}

type authManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	workerExited chan struct{}

	tq *queue.TimeoutQueue

	pendingDestroyTasks *sync.Map

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
func (m *authManager) Start() {
	stopSig := m.ctx.Done()

	m.tq.Start(stopSig)
	ch := m.tq.TakeCh()
	go func() {
		defer close(m.workerExited)

		for {
			select {
			case <-stopSig:
				return
			case td := <-ch:
				k := td.Data.(*timeoutDataValue)
				err := auth.DestroyAuthorization(k.authData)
				if err != nil {
					// TODO: log error

					// retry in 1s
					_ = m.tq.OfferWithDelay(td.Key, td.Data, time.Second)
				}
			}
		}
	}()
}

func (m *authManager) Stop() (err error) {
	m.cancel()

	// wait until no one consumes takeCh
	<-m.workerExited

	destroyAuthWithRetry := func(td *queue.TimeoutData) {
		defer func() {
			// prevent null pointer
			rec := recover()
			if rec != nil {
				// TODO: log error
				_ = rec
			}
		}()

		var err2 error
		for i := 0; i < 5; i++ {
			err2 = auth.DestroyAuthorization(td.Data.(*timeoutDataValue).authData)
			if err2 == nil {
				break
			}
		}

		err = multierr.Append(
			err,
			err2,
		)
	}

	ch := m.tq.TakeCh()

	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}

	// the ch is bufferred, we can drain it without any help
	// by checking its buffered size
	for len(ch) > 0 {
		td := <-ch
		destroyAuthWithRetry(td)

		// if there is no bufferred data in channel,
		// chances are that the sender is not working.
		// wait for 1s for extreme condition
	waitLoop:
		for len(ch) == 0 {
			_ = timer.Reset(time.Second)

			select {
			case td = <-ch:
				if !timer.Stop() {
					<-timer.C
				}

				destroyAuthWithRetry(td)
			case <-timer.C:
				_ = timer.Stop()
				break waitLoop
			}
		}
	}

	// we have drained the ch, now we just need to handle data not timed out

	for _, td := range m.tq.Remains() {
		destroyAuthWithRetry(&td)
	}

	return
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
