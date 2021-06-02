package auth

import (
	"encoding/json"
	"fmt"

	"github.com/keybase/go-keychain"
)

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

// SaveLogin saves username and password to system keychain
func SaveLogin(pmDriver, configName, username, password string) error {
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

// DeleteLogin deletes previously stored username and password
func DeleteLogin(pmDriver, configName string) error {
	err := keychain.DeleteItem(*newKeychainItem(pmDriver, configName))
	if err != nil && err != keychain.ErrorItemNotFound {
		return fmt.Errorf("keychain: failed to delete login: %w", err)
	}

	return nil
}

func GetLogin(pmDriver, configName string) (username, password string, err error) {
	query := newKeychainItem(pmDriver, configName)

	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(*query)
	if err != nil {
		return "", "", fmt.Errorf("keychain: failed to query item: %w", err)
	}

	if len(results) != 1 {
		return "", "", ErrNotFound
	}

	login := &loginData{}
	err = json.Unmarshal(results[0].Data, login)
	if err != nil {
		_ = DeleteLogin(pmDriver, configName)
		return "", "", fmt.Errorf("keychain: failed to unmarshal login data: %w", ErrOldInvalid)
	}

	return login.Username, login.Password, nil
}
