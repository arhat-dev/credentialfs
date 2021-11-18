package bitwarden

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"go.uber.org/multierr"
)

func decodeProtectedData(s string) (ret *protectedData, err error) {
	var t suiteKind
	parts := strings.Split(s, ".")
	if len(parts) == 2 {
		var v int64
		v, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return
		}

		t = suiteKind(v)
		parts = strings.Split(parts[1], "|")
	} else {
		parts = strings.Split(s, "|")
		switch len(parts) {
		case 3:
			t = AES_128_CBC_HMAC_SHA256_B64
		default:
			t = AES_256_CBC_B64
		}
	}

	ret = &protectedData{
		encryptedWith: t,
	}
	var err2 error
	switch t {
	case AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		if len(parts) != 3 {
			err = fmt.Errorf(
				"invalid aes-128/256-cbc-hmac-sha256 enc key, want 3 parts, got %d",
				len(parts),
			)
			return
		}

		ret.iv, err2 = base64.StdEncoding.DecodeString(parts[0])
		err = multierr.Append(err, err2)
		ret.encryptedData, err2 = base64.StdEncoding.DecodeString(parts[1])
		err = multierr.Append(err, err2)
		ret.mac, err2 = base64.StdEncoding.DecodeString(parts[2])
		err = multierr.Append(err, err2)
		ret.newHash = sha256.New
	case AES_256_CBC_B64:
		if len(parts) != 2 {
			err = fmt.Errorf("invalid aes-256-cbc-b64 enc key")
			return
		}

		ret.iv, err2 = base64.StdEncoding.DecodeString(parts[0])
		err = multierr.Append(err, err2)
		ret.encryptedData, err2 = base64.StdEncoding.DecodeString(parts[1])
		err = multierr.Append(err, err2)
	case RSA_2048_OAEP_SHA1_B64,
		RSA_2048_OAEP_SHA256_B64,
		RSA_2048_OAEP_SHA1_HMAC_SHA256_B64,
		RSA_2048_OAEP_SHA256_HMAC_SHA256_B64:
		if len(parts) != 1 {
			err = fmt.Errorf(
				"invalid rsa-2048-oaep-sha1/sha256 enc key, want 1 part, got %d",
				len(parts),
			)
			return
		}

		switch t {
		case RSA_2048_OAEP_SHA1_B64, RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:
			ret.newHash = sha1.New
		case RSA_2048_OAEP_SHA256_B64, RSA_2048_OAEP_SHA256_HMAC_SHA256_B64:
			ret.newHash = sha256.New
		default:
			panic("unreachable")
		}

		ret.encryptedData, err2 = base64.StdEncoding.DecodeString(parts[0])
		err = multierr.Append(err, err2)
	default:
		err = fmt.Errorf("unsupported enc key type %q", t.String())
		return
	}

	if err != nil {
		return nil, err
	}

	return
}
