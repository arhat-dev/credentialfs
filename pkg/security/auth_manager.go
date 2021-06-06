package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"arhat.dev/pkg/queue"
	"go.uber.org/multierr"
)

func NewAuthorizationManager(
	runningCtx context.Context,
	handler AuthorizationHandler,
	defaultPenaltyDuration time.Duration,
	defaultPermitDuration time.Duration,
) *AuthorizationManager {
	ctx, cancel := context.WithCancel(runningCtx)

	return &AuthorizationManager{
		ctx:    ctx,
		cancel: cancel,

		handler: handler,

		workerExited: make(chan struct{}),

		permitTQ:  queue.NewTimeoutQueue(),
		penaltyTQ: queue.NewTimeoutQueue(),

		defaultPermitDuration:  defaultPermitDuration,
		defaultPenaltyDuration: defaultPenaltyDuration,

		pendingDestroyTasks: &sync.Map{},

		mu: &sync.RWMutex{},
	}
}

type AuthorizationManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	handler AuthorizationHandler

	workerExited chan struct{}

	penaltyTQ *queue.TimeoutQueue
	permitTQ  *queue.TimeoutQueue

	defaultPermitDuration  time.Duration
	defaultPenaltyDuration time.Duration

	pendingDestroyTasks *sync.Map

	mu *sync.RWMutex
}

type (
	timeoutDataKey struct {
		authReqKey string
	}

	timeoutDataValue struct {
		timeout  time.Duration
		authData AuthorizationData
	}
)

// Start in background
func (m *AuthorizationManager) Start() {
	stopSig := m.ctx.Done()

	m.penaltyTQ.Start(stopSig)
	go func() {
		ch := m.penaltyTQ.TakeCh()
		for range ch {
			// we do nothing here
		}
	}()

	m.permitTQ.Start(stopSig)
	go func() {
		defer close(m.workerExited)

		ch := m.permitTQ.TakeCh()

		for {
			select {
			case <-stopSig:
				return
			case td := <-ch:
				k := td.Data.(*timeoutDataValue)
				err := m.handler.Destroy(k.authData)
				if err != nil {
					// TODO: log error

					// retry in 1s
					_ = m.permitTQ.OfferWithDelay(td.Key, td.Data, time.Second)
				}
			}
		}
	}()

}

func (m *AuthorizationManager) Stop() (err error) {
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
			err2 = m.handler.Destroy(td.Data.(*timeoutDataValue).authData)
			if err2 == nil {
				break
			}
		}

		err = multierr.Append(
			err,
			err2,
		)
	}

	ch := m.permitTQ.TakeCh()

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

	for _, td := range m.permitTQ.Remains() {
		destroyAuthWithRetry(&td)
	}

	return
}

// RequestAuth checks if the authorization is still valid before actually request
// user authorization
// the lock is required to make auth request sequential
func (m *AuthorizationManager) RequestAuth(
	authReqKey, prompt string, penaltyDuration *time.Duration,
) (AuthorizationData, error) {
	target := timeoutDataKey{
		authReqKey: authReqKey,
	}

	_, ok := m.penaltyTQ.Find(target)
	if ok {
		return nil, fmt.Errorf("penalty duration not ended")
	}

	// requested this request
	v, ok := m.permitTQ.Find(target)
	if ok {
		return v.(*timeoutDataValue).authData, nil
	}

	m.mu.Lock()
	result, err := m.handler.Request(authReqKey, prompt)
	m.mu.Unlock()

	if err != nil {
		dur := m.defaultPenaltyDuration
		if penaltyDuration != nil {
			dur = *penaltyDuration
		}

		_ = m.penaltyTQ.OfferWithDelay(target, struct{}{}, dur)
	}

	return result, err
}

// ScheduleAuthDestroy after a successful auth, it makes sure there will be only one
// timeout task for one authReqKey in queue
//
// caller should not allow further operation if the returned error is not nil
func (m *AuthorizationManager) ScheduleAuthDestroy(
	authReqKey string,
	authData AuthorizationData,
	permitDuration *time.Duration,
) error {
	dur := m.defaultPermitDuration
	if permitDuration != nil {
		dur = *permitDuration
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if dur == 0 {
		return m.handler.Destroy(authData)
	}

	v, ok := m.permitTQ.Find(timeoutDataKey{
		authReqKey: authReqKey,
	})
	if ok {
		if v.(*timeoutDataValue).authData != authData {
			// TODO: possible memory leak!
			_ = authData
		}

		return nil
	}

	return m.permitTQ.OfferWithDelay(timeoutDataKey{
		authReqKey: authReqKey,
	}, &timeoutDataValue{
		authData: authData,
		timeout:  dur,
	}, dur)
}
