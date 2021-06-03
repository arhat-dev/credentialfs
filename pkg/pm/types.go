package pm

type LoginInputCallbackFunc func() (username, password string, err error)

type Interface interface {
	DriverName() string

	ConfigName() string

	Login(showLoginPrompt LoginInputCallbackFunc) error

	Get(key string) ([]byte, error)

	Update(key string, data []byte) error
}

// Common index keys
const (
	UsernameIndexKey = "username"
	PasswordIndexKey = "password"
)
