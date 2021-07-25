package security

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

const testJSONData = `
{
	"user_display_name": "Arhat Dev",
	"user_login_name": "arhatdev",
	"user_id": "1001",
	"primary_group_name": "arhatdev",
	"primary_group_id": "1001",
	"supplement_gids": [
		{"name":"foo","gid":"1002"},
		{"name":"bar","gid":"1003"}
	],
	"process_name": "security.test",
	"process_id": 1000,
	"parent_process_name": "go",
	"parent_process_id": 999,
	"process_calling_path": [
		{"name":"go","pid":999},
		{"name":"bash","pid":900},
		{"name":"make","pid":899},
		{"name":"init","pid":1}
	],
	"operation": "read",
	"file":"foo"
}
`

func TestAuthRequestScheme(t *testing.T) {
	expected := &AuthRequest{
		UserDisplayName:  "Arhat Dev",
		UserLoginName:    "arhatdev",
		UserID:           "1001",
		PrimaryGroupName: "arhatdev",
		PrimaryGroupID:   "1001",
		SupplementGIDs: []GroupNameAndID{
			{Name: "foo", GID: "1002"},
			{Name: "bar", GID: "1003"},
		},
		ProcessName:       "security.test",
		ProcessID:         1000,
		ParentProcessName: "go",
		ParentProcseeID:   999,
		ProcessCallingPath: []ProcessNameAndID{
			{Name: "go", PID: 999},
			{Name: "bash", PID: 900},
			{Name: "make", PID: 899},
			{Name: "init", PID: 1},
		},
		Operation: "read",
		File:      "foo",
	}

	t.Run("json", func(t *testing.T) {
		authReq := &AuthRequest{}
		dec := json.NewDecoder(strings.NewReader(testJSONData))
		dec.DisallowUnknownFields()
		assert.NoError(t, dec.Decode(authReq))

		assert.EqualValues(t, expected, authReq)
	})

	t.Run("yaml", func(t *testing.T) {
		authReq := &AuthRequest{}
		yDec := yaml.NewDecoder(strings.NewReader(testJSONData))
		yDec.KnownFields(true)
		assert.NoError(t, yDec.Decode(authReq))

		assert.EqualValues(t, expected, authReq)
	})
}

func TestCreateAuthRequest(t *testing.T) {
	uid := strconv.FormatInt(int64(os.Getuid()), 10)

	req, err := CreateAuthRequest(uid, uint64(os.Getpid()), OpRead, "foo")
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

	assert.Equal(t, "read", req.Operation)
	assert.Equal(t, "foo", req.File)

	data, err := json.Marshal(req)
	assert.NoError(t, err)
	t.Log(string(data))
}
