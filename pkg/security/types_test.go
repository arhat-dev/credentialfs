package security

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateAuthRequest(t *testing.T) {
	uid := strconv.FormatInt(int64(os.Getuid()), 10)

	req, err := CreateAuthRequest(uid, uint64(os.Getpid()), "foo")
	assert.NoError(t, err)

	// TODO: Ensure user display name exists before test
	// assert.NotEmpty(t, req.UserDisplayName)
	assert.NotEmpty(t, req.UserLoginName)
	assert.EqualValues(t, uid, req.UserID)

	assert.NotEmpty(t, req.PrimaryGroupName)
	assert.EqualValues(t, strconv.FormatInt(int64(os.Getgid()), 10), req.PrimaryGroupID)
	assert.NotNil(t, req.SupplementGIDs)

	assert.NotEmpty(t, req.ProcessName)
	assert.EqualValues(t, os.Getpid(), req.ProcessID)

	assert.NotEmpty(t, req.ParentProcessName)
	assert.EqualValues(t, os.Getppid(), req.ParentProcseeID)

	assert.Greater(t, len(req.ProcessCallingPath), 0)

	assert.Equal(t, "foo", req.File)
}
