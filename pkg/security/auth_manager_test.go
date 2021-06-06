package security

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAuthManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	_ = cancel
	mgr := NewAuthorizationManager(ctx, &nopAuthHandler{}, 0, 0)

	assert.NotNil(t, mgr.ctx)
	assert.NotNil(t, mgr.cancel)

	assert.NotNil(t, mgr.pendingDestroyTasks)
}
