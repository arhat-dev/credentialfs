package bitwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"

	bw "arhat.dev/bitwardenapi/bwinternal"
	"go.uber.org/multierr"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type suiteKind int

// https://github.com/bitwarden/jslib/blob/master/src/enums/encryptionType.ts
// nolint:revive
const (
	AES_256_CBC_B64                      suiteKind = 0
	AES_128_CBC_HMAC_SHA256_B64          suiteKind = 1
	AES_256_CBC_HMAC_SHA256_B64          suiteKind = 2
	RSA_2048_OAEP_SHA256_B64             suiteKind = 3
	RSA_2048_OAEP_SHA1_B64               suiteKind = 4
	RSA_2048_OAEP_SHA256_HMAC_SHA256_B64 suiteKind = 5
	RSA_2048_OAEP_SHA1_HMAC_SHA256_B64   suiteKind = 6
)

type protectedData struct {
	encryptedWith suiteKind

	newHash func() hash.Hash

	iv   []byte
	data []byte
	mac  []byte
}

func (d *protectedData) decrypt(key *bitwardenKey) (result []byte, err error) {
	if len(d.mac) != 0 {
		if len(key.hmacKey) == 0 {
			return nil, fmt.Errorf("hmac key not found but required")
		}

		if !validateHMAC(d.newHash, key.hmacKey, d.iv, d.data, d.mac) {
			return nil, fmt.Errorf("protected data hmac invalid")
		}
	}

	switch d.encryptedWith {
	case AES_256_CBC_B64,
		AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		result, err = decryptAES_CBC(d.data, key.key, d.iv)
		if err != nil {
			return nil, fmt.Errorf("failed to decode symmetric key: %w", err)
		}
	case RSA_2048_OAEP_SHA1_B64,
		RSA_2048_OAEP_SHA256_B64,
		RSA_2048_OAEP_SHA1_HMAC_SHA256_B64,
		RSA_2048_OAEP_SHA256_HMAC_SHA256_B64:

		panic("rsa not implemented")
		// _, _ = rsa.DecryptOAEP(d.newHash(), rand.Reader, nil, nil, nil)
	}

	return
}

func (d *protectedData) decryptAsKey(keyForDecryption *bitwardenKey) (*bitwardenKey, error) {
	if d.encryptedWith != keyForDecryption.kind {
		return nil, fmt.Errorf("data encryption and key not match")
	}

	var (
		key     = keyForDecryption.key
		hmacKey = keyForDecryption.hmacKey

		ret = &bitwardenKey{kind: d.encryptedWith}

		err error
	)

	// check target used encryption method, the key should match
	switch d.encryptedWith {
	case AES_256_CBC_B64:
		hmacKey = nil
	case AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:

		if hmacKey == nil {
			// stretch key when keyForDecruption has no hmacKey
			//
			// only used when the keyForDecruption.key is the prelogin key
			newKey := make([]byte, 64)

			_, _ = hkdf.Expand(d.newHash, keyForDecryption.key, []byte("enc")).Read(newKey[:32])
			_, _ = hkdf.Expand(d.newHash, keyForDecryption.key, []byte("mac")).Read(newKey[32:])

			key = newKey[:32]
			hmacKey = newKey[32:]
		}
	case RSA_2048_OAEP_SHA256_B64,
		RSA_2048_OAEP_SHA1_B64:

		hmacKey = nil
	case RSA_2048_OAEP_SHA256_HMAC_SHA256_B64,
		RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:
	default:
		return nil, fmt.Errorf("unsupported key type %d", d.encryptedWith)
	}

	if hmacKey != nil && !validateHMAC(d.newHash, hmacKey, d.iv, d.data, d.mac) {
		return nil, fmt.Errorf("key mac invalid")
	}

	// match source key
	switch d.encryptedWith {
	case AES_256_CBC_B64,
		AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		ret.key, err = decryptAES_CBC(d.data, key, d.iv)
		if err != nil {
			return nil, fmt.Errorf("failed to decode symmetric key: %w", err)
		}

		switch d.encryptedWith {
		case AES_256_CBC_B64:
			ret.key = ret.key[:256/8]
		case AES_128_CBC_HMAC_SHA256_B64:
			ret.key = ret.key[:128/8]
			ret.hmacKey = ret.key[128/8 : 128/8+256/8]
		case AES_256_CBC_HMAC_SHA256_B64:
			ret.key = ret.key[:256/8]
			ret.hmacKey = ret.key[256/8 : 256/8+256/8]
		case RSA_2048_OAEP_SHA256_B64,
			RSA_2048_OAEP_SHA1_B64,
			RSA_2048_OAEP_SHA256_HMAC_SHA256_B64,
			RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:

			ret.key = ret.key[:2048/8]
			ret.hmacKey = ret.key[2048/8:]
		}
	default:
		panic("unreachable")
	}

	return ret, nil
}

type bitwardenKey struct {
	kind suiteKind

	key     []byte
	hmacKey []byte
}

func decryptData(d []byte, key *bitwardenKey) (result []byte, err error) {
	if len(d) == 0 {
		return d, nil
	}

	data := &protectedData{}
	switch suiteKind(d[0]) {
	case AES_256_CBC_B64:
		if len(d) <= 17 {
			return nil, fmt.Errorf("invalid aes-256-cbc data")
		}

		data.iv = d[1:17]
		data.data = d[17:]

		result, err = decryptAES_CBC(data.data, key.key, data.iv)
	case AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:

		data.iv = d[1:17]
		data.mac = d[17:49]
		data.data = d[49:]

		if !validateHMAC(sha256.New, key.hmacKey, data.iv, data.data, data.mac) {
			return nil, fmt.Errorf("data mac value invalid")
		}

		result, err = decryptAES_CBC(data.data, key.key, data.iv)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported crypto suite: %d", key.kind)
	}

	return
}

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
			err = fmt.Errorf("invalid enc key")
			return
		}

		ret.iv, err2 = base64.StdEncoding.DecodeString(parts[0])
		err = multierr.Append(err, err2)
		ret.data, err2 = base64.StdEncoding.DecodeString(parts[1])
		err = multierr.Append(err, err2)
		ret.mac, err2 = base64.StdEncoding.DecodeString(parts[2])
		err = multierr.Append(err, err2)
		ret.newHash = sha256.New
	case AES_256_CBC_B64:
		if len(parts) != 2 {
			err = fmt.Errorf("invalid aes-cbc256-b64 enc key")
			return
		}

		ret.iv, err2 = base64.StdEncoding.DecodeString(parts[0])
		err = multierr.Append(err, err2)
		ret.data, err2 = base64.StdEncoding.DecodeString(parts[1])
		err = multierr.Append(err, err2)
	case RSA_2048_OAEP_SHA1_B64, RSA_2048_OAEP_SHA256_B64:
		if len(parts) != 1 {
			err = fmt.Errorf("invalid enc key")
			return
		}

		switch t {
		case RSA_2048_OAEP_SHA1_B64, RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:
			ret.newHash = sha1.New
		case RSA_2048_OAEP_SHA256_B64, RSA_2048_OAEP_SHA256_HMAC_SHA256_B64:
			ret.newHash = sha256.New
		}

		ret.data, err2 = base64.StdEncoding.DecodeString(parts[0])
		err = multierr.Append(err, err2)
	default:
		err = fmt.Errorf("unsupported enc key type")
		return
	}

	if err != nil {
		return nil, err
	}

	return
}

func makeMasterKey(password, email string, kdfTypePtr *bw.KdfType, kdfIterationsPtr *int32) ([]byte, error) {
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

func validateHMAC(newHash func() hash.Hash, hmacKey, iv, data, mac []byte) bool {
	hm := hmac.New(newHash, hmacKey)
	hm.Write(iv)
	hm.Write(data)

	return hmac.Equal(mac, hm.Sum(nil))
}

// remove padding
// https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2
func unpad(buf []byte) []byte {
	if len(buf) == 0 {
		return buf
	}

	paddingLen := int(buf[len(buf)-1])
	if paddingLen >= len(buf) {
		// no padding
		return buf
	}

	// possible padding exists
	return bytes.TrimSuffix(buf, buf[len(buf)-paddingLen:])
}

// nolint:revive
func decryptAES_CBC(data, key, iv []byte) (_ []byte, err error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if left := len(data) % b.BlockSize(); left != 0 {
		paddingSize := b.BlockSize() - left
		dataWithPadding := make([]byte, len(data)+paddingSize)
		subtle.ConstantTimeCopy(1, dataWithPadding[:len(data)], data)
		for i := len(data); i < len(dataWithPadding); i++ {
			dataWithPadding[i] = byte(paddingSize)
		}

		data = dataWithPadding
	}

	cbcDec := cipher.NewCBCDecrypter(b, iv)
	buf := make([]byte, len(data))
	cbcDec.CryptBlocks(buf, data)

	return unpad(buf), nil
}
