package bitwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
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

type cryptoData struct {
	t suiteKind

	newHash func() hash.Hash

	iv   []byte
	data []byte
	mac  []byte
}

type symmetricKey struct {
	key     []byte
	hmacKey []byte

	raw cryptoData
}

// nolint:deadcode,unused
func decryptData(d []byte, key *symmetricKey) ([]byte, error) {
	switch key.raw.t {
	case AES_256_CBC_B64,
		AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:

		return decryptAES_CBC(d, key.key, key.raw.iv)
	default:
		return nil, fmt.Errorf("unsupported crypto suite: %d", key.raw.t)
	}
}

// s to be decrypted
// encKey is the key derived from prelogin key when user login
func decryptEncodedCryptoData(s string, encKey *symmetricKey) (result []byte, err error) {
	ed, err := parseEncodedCryptoData(s)
	if err != nil {
		return nil, err
	}

	if encKey.hmacKey != nil && !validateHMAC(ed.newHash, encKey.hmacKey, ed.iv, ed.data, ed.mac) {
		// TODO: validate hmac before decrypt
		// return nil, fmt.Errorf("data hmac invalid")
		_ = encKey.hmacKey
	}

	switch ed.t {
	case AES_256_CBC_B64,
		AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		result, err = decryptAES_CBC(ed.data, encKey.key, ed.iv)
		if err != nil {
			return nil, fmt.Errorf("failed to decode symmetric key: %w", err)
		}
	case RSA_2048_OAEP_SHA1_B64,
		RSA_2048_OAEP_SHA256_B64,
		RSA_2048_OAEP_SHA1_HMAC_SHA256_B64,
		RSA_2048_OAEP_SHA256_HMAC_SHA256_B64:

		// TODO
		_, _ = rsa.DecryptOAEP(ed.newHash(), rand.Reader, nil, nil, nil)
	}

	return
}

func parseEncodedCryptoData(s string) (ret *cryptoData, err error) {
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

	ret = &cryptoData{
		t: t,
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

func parseSymmetricKey(s string, keyForDecryption *symmetricKey) (*symmetricKey, error) {
	ek, err := parseEncodedCryptoData(s)
	if err != nil {
		return nil, err
	}

	key := keyForDecryption.key

	ret := &symmetricKey{
		raw: *ek,
	}
	switch ek.t {
	case AES_256_CBC_B64:
	case AES_256_CBC_HMAC_SHA256_B64:
		if keyForDecryption.hmacKey == nil {
			// stretch key when keyForDecruption has no hmacKey
			//
			// only used when the keyForDecruption.key is the prelogin key
			newKey := make([]byte, 64)

			_, _ = hkdf.Expand(ek.newHash, keyForDecryption.key, []byte("enc")).Read(newKey[:32])
			_, _ = hkdf.Expand(ek.newHash, keyForDecryption.key, []byte("mac")).Read(newKey[32:])

			key = newKey[:32]
			ret.hmacKey = newKey[32:]
		}
	default:
		return nil, fmt.Errorf("unsupported symmetric key type %d", ek.t)
	}

	if ret.hmacKey != nil && !validateHMAC(ek.newHash, ret.hmacKey, ek.iv, ek.data, ek.mac) {
		return nil, fmt.Errorf("enc key hmac invalid")
	}

	switch ek.t {
	case AES_256_CBC_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		ret.key, err = decryptAES_CBC(ek.data, key, ek.iv)
		if err != nil {
			return nil, fmt.Errorf("failed to decode symmetric key: %w", err)
		}

		ret.key = ret.key[:32]
		ret.hmacKey = ret.key[32:]
	default:
		panic("unreachable")
	}

	return ret, nil
}

func makePreloginKey(password, email string, kdfTypePtr *bw.KdfType, kdfIterationsPtr *int32) ([]byte, error) {
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

func validateHMAC(newHash func() hash.Hash, key, iv, data, mac []byte) bool {
	hm := hmac.New(newHash, key)
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

	cbcDec := cipher.NewCBCDecrypter(b, iv)
	buf := make([]byte, len(data))
	cbcDec.CryptBlocks(buf, data)

	return unpad(buf), nil
}
