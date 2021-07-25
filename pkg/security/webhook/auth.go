package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"arhat.dev/pkg/tlshelper"

	"arhat.dev/credentialfs/pkg/security"
)

func init() {
	// for darwin, it should be the default auth handler
	security.RegisterAuthorizationHandler("webhook", newAuthHandler, newAuthHandlerConfig)
}

func newAuthHandlerConfig() interface{} {
	return &Config{}
}

type Config struct {
	EndpointURL string              `json:"endpoint_url" yaml:"endpoint_url"`
	Headers     []NameValuePair     `json:"headers" yaml:"headers"`
	TLS         tlshelper.TLSConfig `json:"tls" yaml:"tls"`
}

type NameValuePair struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

func newAuthHandler(config interface{}) (security.AuthorizationHandler, error) {
	c, ok := config.(*Config)
	if !ok {
		return nil, fmt.Errorf("unexpected non webhook config: %T", config)
	}

	tlsConfig, err := c.TLS.GetTLSConfig(false)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tls config: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:       30 * time.Second,
				KeepAlive:     30 * time.Second,
				FallbackDelay: 300 * time.Millisecond,
			}).DialContext,
			ForceAttemptHTTP2:     tlsConfig != nil,
			TLSClientConfig:       tlsConfig,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,

			DialTLSContext:         nil,
			DisableKeepAlives:      false,
			DisableCompression:     false,
			MaxConnsPerHost:        0,
			ResponseHeaderTimeout:  0,
			TLSNextProto:           nil,
			ProxyConnectHeader:     nil,
			MaxResponseHeaderBytes: 0,
			WriteBufferSize:        0,
			ReadBufferSize:         0,
		},
		CheckRedirect: nil,
		Jar:           nil,
		Timeout:       0,
	}

	return &authHandler{
		client: client,
	}, nil
}

type authHandler struct {
	endpointURL string
	headers     []NameValuePair
	client      *http.Client
}

func (h *authHandler) Authorize(authReq *security.AuthRequest) error {
	data, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, h.endpointURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	for _, p := range h.headers {
		req.Header.Add(p.Name, p.Value)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request authorization: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == 200 {
		return nil
	}

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read error message: %w", err)
	}

	return fmt.Errorf("authorization denied with code %d: %s", resp.StatusCode, string(respData))
}
