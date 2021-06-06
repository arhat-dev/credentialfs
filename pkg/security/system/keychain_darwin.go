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

// nolint:unused,deadcode
type loginData struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

type keychainHandler struct{}

func (h *keychainHandler) SaveLogin(pmDriver, configName, username, password string) error {
	login := &loginData{
		Username: username,
		Password: password,
	}

	data, err := json.Marshal(login)
	if err != nil {
		return fmt.Errorf("keychain: failed to marshal login: %w", err)
	}

	item := newKeychainItem(pmDriver, configName)

	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	item.SetData(data)

	err = keychain.AddItem(*item)
	if err != nil {
		if err == keychain.ErrorDuplicateItem {
			err = keychain.UpdateItem(*newKeychainItem(pmDriver, configName), *item)
			if err != nil {
				return fmt.Errorf("keychain: failed to update login: %w", err)
			}

			return nil
		}

		return fmt.Errorf("keychain: failed to add login: %w", err)
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
func (h *keychainHandler) GetLogin(pmDriver, configName string) (username, password string, err error) {
	query := newKeychainItem(pmDriver, configName)

	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(*query)
	if err != nil {
		return "", "", fmt.Errorf("keychain: failed to query item: %w", err)
	}

	if len(results) != 1 {
		return "", "", security.ErrNotFound
	}

	login := &loginData{}
	err = json.Unmarshal(results[0].Data, login)
	if err != nil {
		_ = h.DeleteLogin(pmDriver, configName)
		return "", "", fmt.Errorf("keychain: failed to unmarshal login data: %w", security.ErrOldInvalid)
	}

	return login.Username, login.Password, nil
}
