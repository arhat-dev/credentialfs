package bitwarden

import (
	"fmt"

	bw "arhat.dev/bitwardenapi/bwinternal"

	"arhat.dev/credentialfs/pkg/constant"
	"arhat.dev/credentialfs/pkg/pm"
)

func (d *Driver) buildCache(globalEncKey *bitwardenKey) error {
	resp, err := d.client.GetSync(d.ctx, &bw.GetSyncParams{
		ExcludeDomains: constant.True(),
	}, d.prependPath("api"))
	if err != nil {
		return fmt.Errorf("failed to request sync: %w", err)
	}

	sr, err := bw.ParseGetSyncResponse(resp)
	_ = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to parse sync response: %w", err)
	}

	if sr.JSON200 == nil {
		return fmt.Errorf("sync failed %s: %s", sr.Status(), string(sr.Body))
	}

	if sr.JSON200.Ciphers == nil {
		return nil
	}

	orgKeys := make(map[string]*bitwardenKey)

	if sr.JSON200.Profile != nil && sr.JSON200.Profile.Organizations != nil {
		for _, org := range *sr.JSON200.Profile.Organizations {
			if org.Key == nil || org.Id == nil {
				continue
			}

			orgKeyData, err := decodeProtectedData(*org.Key)
			if err != nil {
				return fmt.Errorf("failed to decode org key: %w", err)
			}

			orgKey, err := orgKeyData.decryptAsKey(globalEncKey)
			if err != nil {
				return fmt.Errorf("failed to parse org key: %w", err)
			}

			orgKeys[*org.Id] = orgKey
		}
	}

	for _, c := range *sr.JSON200.Ciphers {
		if c.Attachments == nil || c.Name == nil {
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

		itemNameData, err := decodeProtectedData(*c.Name)
		if err != nil {
			return fmt.Errorf("failed to decode org key: %w", err)
		}

		itemName, err := itemNameData.decrypt(encKey)
		if err != nil {
			return err
		}

		err = d.parseAndCacheCipherLogin(string(itemName), c.Login, encKey)
		if err != nil {
			return fmt.Errorf("failed to parse cipher login: %w", err)
		}

		err = d.parseAndCacheCipherFields(string(itemName), c.Fields, encKey)
		if err != nil {
			return fmt.Errorf("failed to parse cipher fields: %w", err)
		}

		err = d.parseAndCacheCipherAttachments(string(itemName), c.Attachments, encKey)
		if err != nil {
			return fmt.Errorf("failed to parse cipher attachments: %w", err)
		}
	}

	return nil
}

func (d *Driver) parseAndCacheCipherLogin(
	itemName string,
	login *bw.CipherLoginModel,
	key *bitwardenKey,
) error {
	switch {
	case login == nil:
		return nil
	case login.Username == nil && login.Password == nil:
		return nil
	}

	if u := login.Username; u != nil {
		usernameData, err := decodeProtectedData(*u)
		if err != nil {
			return fmt.Errorf("failed to decode field name: %w", err)
		}

		username, err := usernameData.decrypt(key)
		if err != nil {
			return fmt.Errorf("failed to decrypt field name: %w", err)
		}

		d.cache.Add(itemName, pm.IndexKeyUsername, username, "", nil)
	}

	if p := login.Password; p != nil {
		passwordData, err := decodeProtectedData(*p)
		if err != nil {
			return fmt.Errorf("failed to decode field name: %w", err)
		}

		password, err := passwordData.decrypt(key)
		if err != nil {
			return fmt.Errorf("failed to decrypt field name: %w", err)
		}

		d.cache.Add(itemName, pm.IndexKeyPassword, password, "", nil)
	}

	return nil
}

func (d *Driver) parseAndCacheCipherFields(
	itemName string,
	fields *[]bw.CipherFieldModel,
	key *bitwardenKey,
) error {
	if fields == nil {
		return nil
	}

	for _, f := range *fields {
		if f.Name == nil {
			continue
		}

		fieldNameData, err := decodeProtectedData(*f.Name)
		if err != nil {
			return fmt.Errorf("failed to decode field name: %w", err)
		}

		fieldName, err := fieldNameData.decrypt(key)
		if err != nil {
			return fmt.Errorf("failed to decrypt field name: %w", err)
		}

		var fieldValue []byte
		if f.Value != nil {
			fieldValueData, err := decodeProtectedData(*f.Value)
			if err != nil {
				return fmt.Errorf("failed to decode field value: %w", err)
			}

			fieldValue, err = fieldValueData.decrypt(key)
			if err != nil {
				return fmt.Errorf("failed to decrypt field value: %w", err)
			}
		}

		d.cache.Add(itemName, string(fieldName), fieldValue, "", nil)
	}

	return nil
}

func (d *Driver) parseAndCacheCipherAttachments(
	itemName string,
	attachments *[]bw.AttachmentResponseModel,
	key *bitwardenKey,
) error {
	if attachments == nil {
		return nil
	}

	for _, a := range *attachments {
		if a.FileName == nil || a.Url == nil {
			continue
		}

		filenameData, err := decodeProtectedData(*a.FileName)
		if err != nil {
			return fmt.Errorf("failed to decode attachment filename: %w", err)
		}

		filename, err := filenameData.decrypt(key)
		if err != nil {
			return fmt.Errorf("failed to decrypt attachment filename: %w", err)
		}

		attachmentEncKey := key
		if a.Key != nil {
			keyData, err := decodeProtectedData(*a.Key)
			if err != nil {
				return fmt.Errorf("failed to decode attachment key: %w", err)
			}

			attachmentEncKey, err = keyData.decryptAsKey(key)
			if err != nil {
				return fmt.Errorf("failed to decrypt attachment key: %w", err)
			}
		}

		d.cache.Add(itemName, string(filename), nil, *a.Url, attachmentEncKey)
	}

	return nil
}
