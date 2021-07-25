package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os/user"
	"strconv"

	"github.com/mitchellh/go-ps"
)

// Errors require special handling
// nolint:revive
var (
	// login data not found, need to request user input
	ErrNotFound = errors.New("not found")

	// old login data invalid, need to request a new one
	ErrOldInvalid = errors.New("old invalid")

	// operation not supported
	ErrUnsupported = errors.New("not supported")
)

// AuthorizationData returned by security service
type AuthorizationData interface{}

type AuthorizationHandler interface {
	// Request explicit user authorization
	Request(authReqKey, prompt string) (AuthorizationData, error)

	// Destroy granted authorization
	Destroy(d AuthorizationData) error
}

type KeychainHandler interface {
	// SaveLogin saves username and password to system keychain
	SaveLogin(pmDriver, configName, username, password string) error

	// DeleteLogin deletes stored username and password
	DeleteLogin(pmDriver, configName string) error

	// GetLogin retrieves previously stored username and password
	GetLogin(pmDriver, configName string) (username, password string, err error)
}

type OperationKind int

const (
	OpRead OperationKind = iota + 1
	OpWrite
	OpAppend
	OpSeek
	OpRemove
)

func (k OperationKind) String() string {
	return map[OperationKind]string{
		OpRead:   "read",
		OpWrite:  "write",
		OpAppend: "append",
		OpSeek:   "seek",
		OpRemove: "remove",
	}[k]
}

// AuthRequest is the request containing request user and intension
type AuthRequest struct {
	UserDisplayName string `json:"user_display_name" yaml:"user_display_name"`
	UserLoginName   string `json:"user_login_name" yaml:"user_login_name"`
	UserID          string `json:"user_id" yaml:"user_id"`

	PrimaryGroupName string           `json:"primary_group_name" yaml:"primary_group_name"`
	PrimaryGroupID   string           `json:"primary_group_id" yaml:"primary_group_id"`
	SupplementGIDs   []GroupNameAndID `json:"supplement_gids" yaml:"supplement_gids"`

	ProcessName string `json:"process_name" yaml:"process_name"`
	ProcessID   uint64 `json:"process_id" yaml:"process_id"`

	ParentProcessName string `json:"parent_process_name" yaml:"parent_process_name"`
	ParentProcseeID   uint64 `json:"parent_process_id" yaml:"parent_process_id"`

	ProcessCallingPath []ProcessNameAndID `json:"process_calling_path" yaml:"process_calling_path"`

	Operation string `json:"operation" yaml:"operation"`
	File      string `json:"file" yaml:"file"`
}

func (r *AuthRequest) CreateKey(policy *AuthPolicy) string {
	h := sha256.New()

	h.Write([]byte(r.UserID))
	h.Write([]byte("|"))
	h.Write([]byte(r.ProcessName))
	h.Write([]byte("|"))
	h.Write([]byte(r.ParentProcessName + "|" + strconv.FormatUint(r.ParentProcseeID, 10)))
	h.Write([]byte("|"))
	h.Write([]byte(r.File))

	return fmt.Sprintf(
		"dev.arhat.credentialfs.file.read.%s",
		hex.EncodeToString(h.Sum(nil)),
	)
}

func (r *AuthRequest) FormatPrompt() string {
	username := r.UserDisplayName
	if len(username) == 0 {
		username = r.UserLoginName
	}

	processInfo := fmt.Sprintf("%q (pid=%d)", r.ProcessName, r.ProcessID)

	if r.ParentProcseeID == 0 {
		return fmt.Sprintf(
			"%s is using %s to read your credential at %s, authorize to proceed",
			username, processInfo, r.File,
		)
	}

	parentProcessInfo := fmt.Sprintf("%q (pid=%d)", r.ParentProcessName, r.ParentProcseeID)

	return fmt.Sprintf(
		"%s is using %s (invoked in %s) to read your credential at %s, authorize to proceed",
		username, processInfo, parentProcessInfo, r.File,
	)
}

type GroupNameAndID struct {
	Name string `json:"name" yaml:"name"`
	GID  string `json:"gid" yaml:"gid"`
}

type ProcessNameAndID struct {
	Name string `json:"name" yaml:"name"`
	PID  uint64 `json:"pid" yaml:"pid"`
}

func CreateAuthRequest(uid string, pid uint64, op OperationKind, file string) (*AuthRequest, error) {
	pidStr := strconv.FormatUint(pid, 10)

	// basic validation
	{
		if pid == 0 {
			return nil, fmt.Errorf("security: invalid pid value %q", pidStr)
		}

		if uid == "" {
			return nil, fmt.Errorf("security: invalid empty uid")
		}

		if op.String() == "" {
			return nil, fmt.Errorf("unknown operation %d", op)
		}

		if file == "" {
			return nil, fmt.Errorf("security: invalid empty file target")
		}
	}

	u, err := user.LookupId(uid)
	if err != nil {
		return nil, fmt.Errorf("security: failed to lookup uid %q: %w", uid, err)
	}

	group, err := user.LookupGroupId(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("security: failed to lookup primary gid %q: %w", u.Gid, err)
	}

	groupIDs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("security: failed to list all gids of uid %q: %w", uid, err)
	}

	var supplementGIDs []GroupNameAndID
	for _, gid := range groupIDs {
		if gid == group.Gid {
			continue
		}

		sGroup, err2 := user.LookupGroupId(gid)
		if err2 != nil {
			return nil, fmt.Errorf("security: failed to lookup supplement gid %q: %w", gid, err2)
		}

		supplementGIDs = append(supplementGIDs, GroupNameAndID{
			Name: sGroup.Name,
			GID:  sGroup.Gid,
		})
	}

	// check process info
	process, err := ps.FindProcess(int(pid))
	if err != nil {
		return nil, fmt.Errorf("security: failed to lookup pid %q: %w", pidStr, err)
	}

	processName := process.Executable()
	if len(processName) == 0 {
		return nil, fmt.Errorf("security: failed to check executable of pid %q", pidStr)
	}

	// check parent process info
	var (
		parentPID          uint64
		parentProcessName  string
		processCallingPath []ProcessNameAndID
	)

	err = createProcessCallingPath(process.PPid(), &processCallingPath)
	if err != nil {
		return nil, fmt.Errorf("security: failed to create process calling path: %w", err)
	}

	if len(processCallingPath) != 0 {
		parentProcessName = processCallingPath[0].Name
		parentPID = processCallingPath[0].PID
	}

	return &AuthRequest{
		UserDisplayName: u.Name,
		UserLoginName:   u.Username,
		UserID:          u.Uid,

		PrimaryGroupName: group.Name,
		PrimaryGroupID:   group.Gid,
		SupplementGIDs:   supplementGIDs,

		ProcessName: processName,
		ProcessID:   pid,

		ParentProcessName: parentProcessName,
		ParentProcseeID:   parentPID,

		ProcessCallingPath: processCallingPath,

		Operation: op.String(),
		File:      file,
	}, nil
}

func createProcessCallingPath(ppid int, ret *([]ProcessNameAndID)) error {
	if ppid == 0 {
		return nil
	}

	pp, err := ps.FindProcess(ppid)
	if err != nil {
		ppidStr := strconv.FormatInt(int64(ppid), 10)
		return fmt.Errorf("failed to lookup ppid %q: %w", ppidStr, err)
	}

	if pp.Pid() != ppid {
		return fmt.Errorf("unexpected pid not match, expected %d, got %d", ppid, pp.Pid())
	}

	name := pp.Executable()
	if len(name) == 0 {
		ppidStr := strconv.FormatInt(int64(ppid), 10)
		return fmt.Errorf("failed to find process name of pid %q", ppidStr)
	}

	*ret = append(*ret, ProcessNameAndID{
		Name: name,
		PID:  uint64(pp.Pid()),
	})

	return createProcessCallingPath(pp.PPid(), ret)
}

// AuthPolicy to automatically allow/deny certain access
type AuthPolicy struct {
}
