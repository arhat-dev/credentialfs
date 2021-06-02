package bitwarden

import (
	"fmt"

	bw "arhat.dev/bitwardenapi/bwinternal"

	"arhat.dev/credentialfs/pkg/constant"
)

func (d *Driver) sync(encKey *symmetricKey) error {
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

	orgKeys := make(map[string]*symmetricKey)

	if sr.JSON200.Profile != nil && sr.JSON200.Profile.Organizations != nil {
		for _, org := range *sr.JSON200.Profile.Organizations {
			if org.Key == nil || org.Id == nil {
				continue
			}

			orgKey, err := parseSymmetricKey(*org.Key, encKey)
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

		itemName, err := decryptEncodedCryptoData(*c.Name, encKey)
		if err != nil {
			return err
		}

		var orgKey *symmetricKey
		if c.OrganizationId != nil {
			orgKey = orgKeys[*c.OrganizationId]
		}

		for _, a := range *c.Attachments {
			if a.FileName == nil || a.Url == nil {
				continue
			}

			filename, err := decryptEncodedCryptoData(*a.FileName, encKey)
			if err != nil {
				return err
			}

			key := orgKey
			if a.Key != nil {
				key, err = parseSymmetricKey(*a.Key, encKey)
				if err != nil {
					return fmt.Errorf("failed to parse attachment key: %w", err)
				}
			}

			d.attachments.Store(attachmentKey{
				ItemName: string(itemName),
				Filename: string(filename),
			}, &attachmentValue{
				Key: key,
				URL: *a.Url,
			})
		}
	}

	return nil
}
