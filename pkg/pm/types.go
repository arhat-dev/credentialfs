package pm

type Interface interface {
	Login(password string) error

	Get(key string) ([]byte, error)

	Update(key string, data []byte) error
}
