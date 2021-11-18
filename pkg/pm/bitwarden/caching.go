package bitwarden

import (
	"fmt"

	bw "arhat.dev/bitwardenapi/bwinternal"

	"arhat.dev/credentialfs/pkg/constant"
	"arhat.dev/credentialfs/pkg/pm"
)

func (d *Driver) buildCache(globalEncKey, _ *bitwardenKey) error {
	resp, err := d.client.GetSync(d.ctx, &bw.GetSyncParams{
		ExcludeDomains: constant.True(),
	}, d.prependPath("api"))
	if err != nil {
		return fmt.Errorf("failed to request sync: %w", err)
	}

	sr, err := bw.ParseGetSyncResponse(resp)
	if err != nil {
		return fmt.Errorf("failed to parse sync response: %w", err)
	}

	if sr.JSON200 == nil {
		return fmt.Errorf("sync failed %s: %s", sr.Status(), string(sr.Body))
	}

	if sr.JSON200.Ciphers == nil {
		// no data to sync
		return nil
	}

	orgKeys := make(map[string]*bitwardenKey)

	if profile := sr.JSON200.Profile; profile != nil && profile.Organizations != nil {
		userPrivateKey := profile.PrivateKey
		var upk *bitwardenKey
		if userPrivateKey != nil {
			var upkd *protectedData
			upkd, err = decodeProtectedData(*userPrivateKey)
			if err != nil {
				return fmt.Errorf("failed to decode user private key: %w", err)
			}

			upk, err = upkd.decrypt_as_key(globalEncKey)
			if err != nil {
				return fmt.Errorf("failed to decrypt user private key: %w", err)
			}
		}

		for _, org := range *profile.Organizations {
			if org.Key == nil || org.Id == nil {
				continue
			}

			orgKeyData, err := decodeProtectedData(*org.Key)
			if err != nil {
				return fmt.Errorf("failed to decode org key: %w", err)
			}

			orgKey, err := orgKeyData.decrypt_as_key(upk)
			if err != nil {
				return fmt.Errorf("failed to decrypt org key: %w", err)
			}

			orgKeys[*org.Id] = orgKey
		}
	}

	for _, c := range *sr.JSON200.Ciphers {
		if c.Name == nil || c.Id == nil {
			continue
		}

		encKey := globalEncKey
		var orgKey *bitwardenKey
		if c.OrganizationId != nil {
			var ok bool
			orgKey, ok = orgKeys[*c.OrganizationId]
			if ok {
				encKey = orgKey
			}
		}

		cipherNameData, err := decodeProtectedData(*c.Name)
		if err != nil {
			return fmt.Errorf("failed to decode org key: %w", err)
		}

		cipherNameBytes, err := cipherNameData.decrypt(encKey)
		if err != nil {
			return err
		}

		cipherName := string(cipherNameBytes)
		cipherID := *c.Id

		loginSet, err := parseCipherLogin(cipherName, cipherID, c.Login, encKey)
		if err != nil {
			return fmt.Errorf("failed to parse cipher login: %w", err)
		}

		fieldSet, err := parseCipherFields(cipherName, cipherID, c.Fields, encKey)
		if err != nil {
			return fmt.Errorf("failed to parse cipher fields: %w", err)
		}

		attachmentSet, err := parseCipherAttachments(cipherName, cipherID, c.Attachments, encKey)
		if err != nil {
			return fmt.Errorf("failed to parse cipher attachments: %w", err)
		}

		d.cache.Add(loginSet)
		d.cache.Add(fieldSet)
		d.cache.Add(attachmentSet)
	}

	return nil
}

func parseCipherLogin(
	cipherName, cipherID string,
	login *bw.CipherLoginModel,
	key *bitwardenKey,
) (ret *cacheSet, err error) {
	switch {
	case login == nil:
		return
	case login.Username == nil && login.Password == nil:
		return
	}

	ret = newCacheSet()
	if u := login.Username; u != nil {
		var (
			usernameData *protectedData
			username     []byte
		)

		usernameData, err = decodeProtectedData(*u)
		if err != nil {
			err = fmt.Errorf("failed to decode field name: %w", err)
			return
		}

		username, err = usernameData.decrypt(key)
		if err != nil {
			err = fmt.Errorf("failed to decrypt field name: %w", err)
			return
		}

		ret.Add(cipherName, pm.IndexKeyUsername, cipherID, username, "", key)
	}

	if p := login.Password; p != nil {
		var (
			passwordData *protectedData
			password     []byte
		)
		passwordData, err = decodeProtectedData(*p)
		if err != nil {
			err = fmt.Errorf("failed to decode field name: %w", err)
			return
		}

		password, err = passwordData.decrypt(key)
		if err != nil {
			err = fmt.Errorf("failed to decrypt field name: %w", err)
			return
		}

		ret.Add(cipherName, pm.IndexKeyPassword, cipherID, password, "", key)
	}

	return
}

func parseCipherFields(
	cipherName, cipherID string,
	fields *[]bw.CipherFieldModel,
	key *bitwardenKey,
) (ret *cacheSet, err error) {
	if fields == nil {
		return
	}

	ret = newCacheSet()
	for _, f := range *fields {
		if f.Name == nil {
			continue
		}

		var (
			fieldNameData *protectedData
			fieldName     []byte
		)

		fieldNameData, err = decodeProtectedData(*f.Name)
		if err != nil {
			err = fmt.Errorf("failed to decode field name: %w", err)
			return
		}

		fieldName, err = fieldNameData.decrypt(key)
		if err != nil {
			err = fmt.Errorf("failed to decrypt field name: %w", err)
			return
		}

		var (
			fieldValueData *protectedData
			fieldValue     []byte
		)

		if f.Value != nil {
			fieldValueData, err = decodeProtectedData(*f.Value)
			if err != nil {
				err = fmt.Errorf("failed to decode field value: %w", err)
				return
			}

			fieldValue, err = fieldValueData.decrypt(key)
			if err != nil {
				err = fmt.Errorf("failed to decrypt field value: %w", err)
				return
			}
		}

		ret.Add(cipherName, string(fieldName), cipherID, fieldValue, "", key)
	}

	return
}

func parseCipherAttachments(
	cipherName, cipherID string,
	attachments *[]bw.AttachmentResponseModel,
	key *bitwardenKey,
) (ret *cacheSet, err error) {
	if attachments == nil {
		return
	}

	ret = newCacheSet()
	for _, a := range *attachments {
		if a.FileName == nil || a.Url == nil {
			continue
		}

		var (
			filenameData *protectedData
			filename     []byte
		)

		filenameData, err = decodeProtectedData(*a.FileName)
		if err != nil {
			err = fmt.Errorf("failed to decode attachment filename: %w", err)
			return
		}

		filename, err = filenameData.decrypt(key)
		if err != nil {
			err = fmt.Errorf("failed to decrypt attachment filename: %w", err)
			return
		}

		attachmentEncKey := key
		if a.Key != nil {
			var keyData *protectedData
			keyData, err = decodeProtectedData(*a.Key)
			if err != nil {
				err = fmt.Errorf("failed to decode attachment key: %w", err)
				return
			}

			attachmentEncKey, err = keyData.decrypt_as_key(key)
			if err != nil {
				err = fmt.Errorf("failed to decrypt attachment key: %w", err)
				return
			}
		}

		ret.Add(cipherName, string(filename), cipherID, nil, *a.Url, attachmentEncKey)
	}

	return
}
