package fs

// https://developer.apple.com/documentation/security/authorization_services

/*

#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

*/
import "C"
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

// request user authorization from Authorization Service
func requestAuth() (bool, error) {
	return false, fmt.Errorf("unimplemented")
}

func newKeychainItem(pmDriver, configName string) *keychain.Item {
	item := keychain.NewItem()

	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(keychainServiceName)
	item.SetAccount(formatAccount(configName))
	item.SetAccessGroup(formatAccessGroup(pmDriver))

	return &item
}

func getLogin(pmDriver, configName string) (username, password string, err error) {
	query := newKeychainItem(pmDriver, configName)

	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(*query)
	if err != nil {
		return "", "", fmt.Errorf("failed to query keychain item: %w", err)
	}

	if len(results) != 1 {
		return "", "", ErrNotFound
	}

	login := &loginData{}
	err = json.Unmarshal(results[0].Data, login)
	if err != nil {
		// TODO: delete invalid keychain item
		return "", "", fmt.Errorf("failed to unmarshal login data: %w", ErrOldInvalid)
	}

	return login.Username, login.Password, nil
}

// save username and password to system keychain
func saveLogin(pmDriver, configName, username, password string) error {
	login := &loginData{
		Username: username,
		Password: password,
	}

	data, err := json.Marshal(login)
	if err != nil {
		return fmt.Errorf("failed to marshal login: %w", err)
	}

	item := newKeychainItem(pmDriver, configName)

	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	item.SetData(data)

	err = keychain.AddItem(*item)
	if err != nil {
		return fmt.Errorf("failed to add login: %w", err)
	}

	return nil
}
