package bitwarden

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	bw "arhat.dev/bitwardenapi/bwinternal"
)

func getCacheKey(s string) *cacheKey {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return nil
	}

	return &cacheKey{
		ItemName: parts[0],
		ItemKey:  parts[1],
	}
}

func (d *Driver) update(f func()) {
	d.mu.Lock()
	defer d.mu.Unlock()

	f()
}

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

func (d *Driver) prependPath(p string) bw.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		// if d.endpointURL == officialServiceEndpointURL {
		// 	// official bitwarden service
		// 	host := ""

		// 	switch {
		// 	case strings.HasPrefix(p, "api"):
		// 		host = officialAPIEndpointHost
		// 	case strings.HasPrefix(p, "identity"):
		// 		host = officialIdentityEndpointHost
		// 	case strings.HasPrefix(p, "events"):
		// 		host = officialEventsEndpointHost
		// 	case strings.HasPrefix(p, "notification"):
		// 		host = officialNotificationEndpointHost
		// 	}

		// 	req.URL.Host = host
		// 	req.Header.Set("Host", host)

		// 	return nil
		// }

		req.URL.Path = strings.TrimPrefix(req.URL.Path, d.endpointPathPrefix)
		req.URL.Path = path.Join(d.endpointPathPrefix, p, req.URL.Path)
		if !strings.HasPrefix(req.URL.Path, "/") {
			req.URL.Path = "/" + req.URL.Path
		}

		req.Header.Set("Path", req.URL.RequestURI())
		return nil
	}
}

func (d *Driver) downloadAttachment(cipher *cacheValue) ([]byte, error) {
	if len(cipher.URL) == 0 {
		return nil, fmt.Errorf("not an attachment cache")
	}

	if cipher.Key == nil {
		return nil, fmt.Errorf("invalid cipher cache: key not found")
	}

	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, cipher.URL, nil)
	if err != nil {
		return nil, err
	}

	err = d.fixRequest(d.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fix attachment request: %w", err)
	}

	resp, err := d.client.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request attachment: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read attachment data: %w", err)
	}

	data, err = decryptData(data, cipher.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt attachment content: %w", err)
	}

	return data, nil
}
