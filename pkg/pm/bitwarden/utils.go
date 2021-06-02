package bitwarden

import (
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

	bw "arhat.dev/bitwardenapi/bwinternal"
	"github.com/deepmap/oapi-codegen/pkg/types"
	"golang.org/x/crypto/pbkdf2"
)

func (d *Driver) login(password, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))

	resp, err := d.client.PostAccountsPrelogin(d.ctx, bw.PostAccountsPreloginJSONRequestBody{
		Email: types.Email(email),
	})
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

	key, err := d.makeKey(password, email, kdfTypePtr, kdfIterationsPtr)
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

	hashedPassword := d.hashPassword(password, key)
	values.Set("password", hashedPassword)

	loginURL, err := url.Parse(d.client.Server)
	if err != nil {
		return fmt.Errorf("failed to bitwarden server url: %w", err)
	}
	parent := path.Dir(strings.TrimSuffix(loginURL.Path, "/"))
	loginURL.Path = path.Join(parent, "identity/connect/token")

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
		Key                 string     `json:"key"`
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
		return err
	}

	data := &identityTokenResp{}
	err = json.Unmarshal(respBody, data)
	if err != nil {
		return err
	}

	d.update(func() {
		d.accessToken = data.AccessToken
		d.refreshToken = data.RefreshToken

		d.preLoginKey = key
		d.hashedPassword = hashedPassword

		d.encKey = []byte(data.Key)
		d.encPrivateKey = []byte(data.PrivateKey)
	})

	return nil
}

func (d *Driver) hashPassword(password string, key []byte) string {
	return base64.StdEncoding.EncodeToString(
		pbkdf2.Key(key, []byte(password), 1, sha256.Size, sha256.New),
	)
}

func (d *Driver) makeKey(password, email string, kdfTypePtr *bw.KdfType, kdfIterationsPtr *int32) ([]byte, error) {
	const (
		// https://github.com/bitwarden/jslib/blob/master/src/enums/kdfType.ts
		pbkdf2SHA256            bw.KdfType = 0
		minimumPBKDF2Iterations int        = 5000
	)

	var (
		kdfType       bw.KdfType = pbkdf2SHA256
		kdfIterations            = minimumPBKDF2Iterations
	)

	if kdfIterationsPtr != nil {
		kdfIterations = int(*kdfIterationsPtr)
	}

	if kdfTypePtr != nil {
		kdfType = *kdfTypePtr
	}

	switch kdfType {
	case pbkdf2SHA256:
		if kdfIterations < minimumPBKDF2Iterations {
			return nil, fmt.Errorf("pbkdf2 iteration minimum is %d", minimumPBKDF2Iterations)
		}

		return pbkdf2.Key([]byte(password), []byte(email), kdfIterations, sha256.Size, sha256.New), nil
	default:
		return nil, fmt.Errorf("unknown kdf")
	}
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
