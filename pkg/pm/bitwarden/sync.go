package bitwarden

import (
	"fmt"

	bw "arhat.dev/bitwardenapi/bwinternal"

	"arhat.dev/credentialfs/pkg/constant"
)

func (d *Driver) sync(encKey []byte, hmacKey []byte) error {
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

	for _, c := range *sr.JSON200.Ciphers {
		if c.Attachments == nil || c.Name == nil {
			continue
		}

		itemName, err := decrypt(*c.Name, encKey, hmacKey)
		if err != nil {
			return err
		}

		for _, a := range *c.Attachments {
			if a.FileName == nil || a.Url == nil {
				continue
			}

			filename, err := decrypt(*a.FileName, encKey, hmacKey)
			if err != nil {
				return err
			}

			d.attachments.Store(attachmentKey{
				ItemName: itemName,
				Filename: filename,
			}, *a.Url)
		}
	}

	return nil
}
