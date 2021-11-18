package bitwarden

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	bw "arhat.dev/bitwardenapi/bwinternal"
	"github.com/deepmap/oapi-codegen/pkg/types"
	"golang.org/x/crypto/pbkdf2"

	"arhat.dev/credentialfs/pkg/pm"
)

// prelogin to generate master key
func (d *Driver) _prelogin(email, password []byte) ([]byte, error) {
	resp, err := d.client.PostAccountsPrelogin(d.ctx, bw.PostAccountsPreloginJSONRequestBody{
		Email: types.Email(email),
	}, d.prependPath("api"))
	if err != nil {
		return nil, fmt.Errorf("failed to request prelogin: %w", err)
	}

	pr, err := bw.ParsePostAccountsPreloginResponse(resp)
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to parse prelogin response: %w", err)
	}

	if pr.JSON200 == nil {
		return nil, fmt.Errorf("failed to get prelogin config %s: %s", pr.Status(), string(pr.Body))
	}

	kdfTypePtr := pr.JSON200.Kdf
	kdfType := KDFType_PBKDF2_SHA256
	if kdfTypePtr != nil {
		kdfType = *kdfTypePtr
	}

	kdfIterationsPtr := pr.JSON200.KdfIterations
	kdfIterations := minimumPBKDF2Iterations
	if kdfIterationsPtr != nil {
		kdfIterations = int(*kdfIterationsPtr)
	}

	return makeMasterKey(email, password, kdfType, kdfIterations)
}

func (d *Driver) login(input *pm.LoginInput) error {
	email := bytes.ToLower(bytes.TrimSpace(input.Username))

	masterKey, err := d._prelogin(email, input.Password)
	if err != nil {
		return err
	}

	values := &url.Values{}
	values.Set("grant_type", "password")
	values.Set("scope", "api offline_access")
	values.Set("client_id", "cli")
	values.Set("username", string(email))
	values.Set("deviceIdentifier", d.deviceID)
	values.Set("deviceName", "credentialfs")
	values.Set("deviceType", getDeviceType())

	mph := generateMasterPasswordHash(input.Password, masterKey)
	values.Set("password", mph)

	req, err := http.NewRequestWithContext(
		d.ctx,
		http.MethodPost,
		d.endpointURL+"/identity/connect/token",
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}

	_ = d.fixRequest(d.ctx, req)
	req.Header.Set("Auth-Email", string(email))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")

	resp, err := d.client.Client.Do(req)
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

	// https://github.com/bitwarden/jslib/blob/master/common/src/models/response/identityTokenResponse.ts
	type identityTokenResp struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`

		// fields below need special parsing
		// refs:
		// 	https://github.com/bitwarden/jslib/blob/ea9a8b979d5b5797ddf010bbc625843b149065e9/common/src/models/response/identityTokenResponse.ts#L28
		// 	https://github.com/bitwarden/jslib/blob/ea9a8b979d5b5797ddf010bbc625843b149065e9/common/src/models/response/baseResponse.ts#L8
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

	encKey, err := encKeyData.decrypt_as_key(&bitwardenKey{
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

	pk, err := pkData.decrypt_as_key(encKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt private key: %w", err)
	}

	d.update(func() {
		d.accessToken = data.AccessToken
		d.user = user

		d.refreshToken = data.RefreshToken

		d.masterKey = masterKey
		d.hashedPassword = mph

		d.encKey = encKey
		d.privateKey = pk
	})

	return nil
}

// generateMasterPasswordHash generates master password hash using master key
func generateMasterPasswordHash(masterPassword, masterKey []byte) string {
	return base64.StdEncoding.EncodeToString(
		pbkdf2.Key(masterKey, masterPassword, 1, sha256.Size, sha256.New),
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
