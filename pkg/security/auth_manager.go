package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"arhat.dev/pkg/queue"
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
	}
}

type AuthorizationManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	handler AuthorizationHandler

	workerExited chan struct{}

	policy *AuthPolicy

	penaltyTQ *queue.TimeoutQueue
	permitTQ  *queue.TimeoutQueue

	defaultPermitDuration  time.Duration
	defaultPenaltyDuration time.Duration

	pendingDestroyTasks *sync.Map
}

type (
	timeoutDataKey struct {
		authReqKey string
	}

	timeoutDataValue struct {
		// timeout  time.Duration
		// authData AuthorizationData
	}
)

// Start in background
func (m *AuthorizationManager) Start() {
	stopSig := m.ctx.Done()

	m.penaltyTQ.Start(stopSig)
	go func() {
		ch := m.penaltyTQ.TakeCh()
		for range ch {
			// TODO: maybe do some logging for penalty end?
		}
	}()

	m.permitTQ.Start(stopSig)
	go func() {
		defer close(m.workerExited)

		ch := m.permitTQ.TakeCh()

		for range ch {
			// TODO: maybe do some logging for permit expire?
		}
	}()

}

func (m *AuthorizationManager) Stop() error {
	m.cancel()

	return nil
}

// RequestAuth checks if the authorization is still valid before actually request
// user authorization
func (m *AuthorizationManager) RequestAuth(
	req *AuthRequest,
	permitDuration *time.Duration,
	penaltyDuration *time.Duration,
) error {
	target := timeoutDataKey{
		authReqKey: req.CreateKey(m.policy),
	}

	// check whether failed before
	_, ok := m.penaltyTQ.Find(target)
	if ok {
		return fmt.Errorf("penalty duration not ended")
	}

	// check whether have allowed this request before
	_, ok = m.permitTQ.Find(target)
	if ok {
		return nil
	}

	// this request is new, do actual auth request
	err := m.handler.Authorize(req)
	if err != nil {
		dur := m.defaultPenaltyDuration
		if penaltyDuration != nil {
			dur = *penaltyDuration
		}

		_ = m.penaltyTQ.OfferWithDelay(target, struct{}{}, dur)

		return err
	}

	dur := m.defaultPermitDuration
	if permitDuration != nil {
		dur = *permitDuration
	}

	return m.permitTQ.OfferWithDelay(
		target, &timeoutDataValue{}, dur,
	)
}
