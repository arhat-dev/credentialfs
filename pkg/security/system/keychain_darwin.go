package system

import (
	"encoding/json"
	"fmt"

	"github.com/keybase/go-keychain"

	"arhat.dev/credentialfs/pkg/security"
)

func init() {
	// for darwin, it should be the default keychain handler
	security.RegisterKeychainHandler("", newKeychainHandler, newKeychainHandlerConfig)
	security.RegisterKeychainHandler("system", newKeychainHandler, newKeychainHandlerConfig)
}

func newKeychainHandlerConfig() interface{} { return &keychainConfig{} }

type keychainConfig struct{}

func newKeychainHandler(config interface{}) (security.KeychainHandler, error) {
	_ = config
	// TODO: check system support
	return &keychainHandler{}, nil
}

const (
	keychainServiceName = "credentialfs"
)

func formatAccessGroup(pmDriver string) string {
	return fmt.Sprintf("%s.credentialfs.dev.arhat", pmDriver)
}

func formatAccount(configName string) string {
	return configName
}

func newKeychainItem(pmDriver, configName string) *keychain.Item {
	item := keychain.NewItem()

	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainServiceName)
	item.SetAccount(formatAccount(configName))
	item.SetAccessGroup(formatAccessGroup(pmDriver))

	return &item
}

type loginData struct {
	username []byte
	password []byte
}

func (t *loginData) Marshal() []byte {
	// TODO: currently made compatible with previous version

	data, err := json.Marshal(map[string]string{
		"username": string(t.username),
		"password": string(t.password),
	})

	if err != nil {
		panic(err)
	}

	return data
}

func (t *loginData) Unmarshal(data []byte) error {
	m := make(map[string]string)
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	t.password = []byte(m["password"])
	t.username = []byte(m["username"])

	return nil
}

type keychainHandler struct{}

func (h *keychainHandler) SaveLogin(pmDriver, configName string, username, password []byte) error {
	item := newKeychainItem(pmDriver, configName)

	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	item.SetData((&loginData{
		username: username,
		password: password,
	}).Marshal())

	err := keychain.AddItem(*item)
	if err == nil {
		return nil
	}

	if err != keychain.ErrorDuplicateItem {
		return fmt.Errorf("keychain: failed to add login: %w", err)
	}

	err = keychain.UpdateItem(*newKeychainItem(pmDriver, configName), *item)
	if err != nil {
		return fmt.Errorf("keychain: failed to update login: %w", err)
	}

	return nil
}

func (h *keychainHandler) DeleteLogin(pmDriver, configName string) error {
	err := keychain.DeleteItem(*newKeychainItem(pmDriver, configName))
	if err != nil && err != keychain.ErrorItemNotFound {
		return fmt.Errorf("keychain: failed to delete login: %w", err)
	}

	return nil
}

func (h *keychainHandler) GetLogin(pmDriver, configName string) (username, password []byte, err error) {
	query := newKeychainItem(pmDriver, configName)

	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(*query)
	if err != nil {
		return nil, nil, fmt.Errorf("keychain: failed to query item: %w", err)
	}

	if len(results) != 1 {
		return nil, nil, security.ErrNotFound
	}

	login := &loginData{}
	err = login.Unmarshal(results[0].Data)
	if err != nil {
		_ = h.DeleteLogin(pmDriver, configName)
		return nil, nil, fmt.Errorf("keychain: failed to unmarshal login data: %w", security.ErrOldInvalid)
	}

	return login.username, login.password, nil
}
