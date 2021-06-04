package bitwarden

import (
	"context"
	"net/http"
)

func (d *Driver) fixRequest(ctx context.Context, req *http.Request) error {
	req.Header.Set("Device-Type", getDeviceType())
	req.Header.Set("Accept", "application/json")

	d.mu.RLock()
	if len(d.accessToken) != 0 {
		req.Header.Set("Authorization", "Bearer "+d.accessToken)
	}
	d.mu.RUnlock()

	return nil
}
