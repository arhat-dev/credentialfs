package bitwarden

import (
	"fmt"

	bw "arhat.dev/bitwardenapi/bwinternal"

	"arhat.dev/credentialfs/pkg/constant"
)

func (d *Driver) sync(globalEncKey *bitwardenKey) error {
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

		var orgKey *bitwardenKey
		if c.OrganizationId != nil {
			orgKey = orgKeys[*c.OrganizationId]
		}

		itemNameData, err := decodeProtectedData(*c.Name)
		if err != nil {
			return fmt.Errorf("failed to decode org key: %w", err)
		}

		encKey := globalEncKey
		if orgKey != nil {
			encKey = orgKey
		}
		itemName, err := itemNameData.decrypt(encKey)
		if err != nil {
			return err
		}

		for _, a := range *c.Attachments {
			if a.FileName == nil || a.Url == nil {
				continue
			}

			filenameData, err := decodeProtectedData(*a.FileName)
			if err != nil {
				return fmt.Errorf("failed to decode org key: %w", err)
			}

			filename, err := filenameData.decrypt(encKey)
			if err != nil {
				return err
			}

			attachmentEncKey := encKey
			if a.Key != nil {
				keyData, err := decodeProtectedData(*a.Key)
				if err != nil {
					return fmt.Errorf("failed to decode org key: %w", err)
				}

				attachmentEncKey, err = keyData.decryptAsKey(encKey)
				if err != nil {
					return fmt.Errorf("failed to parse attachment key: %w", err)
				}
			}

			d.attachments.Store(attachmentKey{
				ItemName: string(itemName),
				Filename: string(filename),
			}, &attachmentValue{
				Key: attachmentEncKey,
				URL: *a.Url,
			})
		}
	}

	return nil
}
