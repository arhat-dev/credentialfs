package bitwarden

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"runtime"
	"strings"
	"time"

	bw "arhat.dev/bitwardenapi/bwinternal"
	"github.com/deepmap/oapi-codegen/pkg/types"
	"golang.org/x/crypto/pbkdf2"
)

func (d *Driver) prependPath(p string) bw.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.URL.Path = strings.TrimPrefix(req.URL.Path, d.endpointPathPrefix)
		req.URL.Path = path.Join(d.endpointPathPrefix, p, req.URL.Path)
		if !strings.HasPrefix(req.URL.Path, "/") {
			req.URL.Path = "/" + req.URL.Path
		}

		req.Header.Set("Path", req.URL.RequestURI())
		return nil
	}
}

func (d *Driver) login(masterPassword, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	resp, err := d.client.PostAccountsPrelogin(d.ctx, bw.PostAccountsPreloginJSONRequestBody{
		Email: types.Email(email),
	}, d.prependPath("api"))
	if err != nil {
		return fmt.Errorf("failed to request prelogin: %w", err)
	}

	pr, err := bw.ParsePostAccountsPreloginResponse(resp)
	_ = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to parse prelogin response: %w", err)
	}

	var (
		kdfTypePtr       *bw.KdfType
		kdfIterationsPtr *int32
	)

	if pr.JSON200 != nil {
		kdfTypePtr = pr.JSON200.Kdf
		kdfIterationsPtr = pr.JSON200.KdfIterations
	}

	masterKey, err := makeMasterKey(masterPassword, email, kdfTypePtr, kdfIterationsPtr)
	if err != nil {
		return fmt.Errorf("failed to make kdf key: %w", err)
	}

	values := &url.Values{}
	values.Set("grant_type", "password")
	values.Set("scope", "api offline_access")
	values.Set("client_id", "test")
	values.Set("username", email)
	values.Set("deviceIdentifier", "test")
	values.Set("deviceName", "credentialfs")
	values.Set("deviceType", getDeviceType())

	hashedPassword := hashPassword(masterPassword, masterKey)
	values.Set("password", hashedPassword)

	loginURL, err := url.Parse(d.client.Server)
	if err != nil {
		return fmt.Errorf("failed to bitwarden server url: %w", err)
	}
	loginURL.Path = path.Join(loginURL.Path, "identity/connect/token")

	req, err := http.NewRequestWithContext(
		d.ctx,
		http.MethodPost,
		loginURL.String(),
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	resp, err = d.client.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to request login: %w", err)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed %s: %s", resp.Status, string(respBody))
	}

	// https://github.com/bitwarden/jslib/blob/master/src/models/response/identityTokenResponse.ts
	type identityTokenResp struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`

		// fields below need special parse
		ResetMasterPassword bool       `json:"resetmasterpassword"`
		PrivateKey          string     `json:"privatekey"`
		EncKey              string     `json:"key"`
		TwoFactorToken      string     `json:"twofactortoken"`
		Kdf                 bw.KdfType `json:"kdf"`
		KdfIterations       int        `json:"kdfiterations"`
	}

	respData := make(map[string]interface{})
	err = json.Unmarshal(respBody, &respData)
	if err != nil {
		return err
	}

	finalRespData := make(map[string]interface{})
	for k := range respData {
		finalRespData[strings.ToLower(k)] = respData[k]
	}

	respBody, err = json.Marshal(finalRespData)
	if err != nil {
		return fmt.Errorf("invalid login response body: %w", err)
	}

	data := &identityTokenResp{}
	err = json.Unmarshal(respBody, data)
	if err != nil {
		return fmt.Errorf("failed to decode identity token: %w", err)
	}

	user, err := parseUserFromAccessToken(data.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to parse user info from access token: %w", err)
	}

	encKeyData, err := decodeProtectedData(data.EncKey)
	if err != nil {
		return fmt.Errorf("failed to decode master key: %w", err)
	}

	encKey, err := encKeyData.decryptAsKey(&bitwardenKey{
		kind: encKeyData.encryptedWith,
		key:  masterKey,
	})
	if err != nil {
		return fmt.Errorf("failed to decrypt master key: %w", err)
	}

	pkData, err := decodeProtectedData(data.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	pk, err := pkData.decryptAsKey(encKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt private key: %w", err)
	}

	d.update(func() {
		d.accessToken = data.AccessToken
		d.user = user

		d.refreshToken = data.RefreshToken

		d.masterKey = masterKey
		d.hashedPassword = hashedPassword

		d.encKey = encKey
		d.privateKey = pk
	})

	return nil
}

func hashPassword(password string, key []byte) string {
	return base64.StdEncoding.EncodeToString(
		pbkdf2.Key(key, []byte(password), 1, sha256.Size, sha256.New),
	)
}

func getDeviceType() string {
	// https://github.com/bitwarden/jslib/blob/master/src/enums/deviceType.ts

	switch runtime.GOOS {
	case "windows":
		return "6" /* Windows desktop */
	case "darwin":
		return "7" /* macOS desktop */
	case "linux":
		return "8" /* Linux desktop */
	default:
		return "14" /* Unknown browser */
	}
}

type bitwardenUser struct {
	UserID        string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Premium       bool   `json:"premium"`
	Name          string `json:"name"`
	Issuer        string `json:"iss"`
	ExpireAt      int64  `json:"exp"` // unix time seconds (UTC)
}

// nolint:unused
func (u *bitwardenUser) needToRefreshToken() bool {
	return time.Unix(u.ExpireAt, 0).Before(time.Now())
}

func parseUserFromAccessToken(accessToken string) (*bitwardenUser, error) {
	parts := strings.SplitN(accessToken, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid access token")
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid jwt encoded user: %w", err)
	}

	user := &bitwardenUser{}
	err = json.Unmarshal(data, user)
	return user, err
}
