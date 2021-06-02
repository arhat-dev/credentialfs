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

type encType int

// https://github.com/bitwarden/jslib/blob/master/src/enums/encryptionType.ts
// nolint:revive
const (
	AES_256_CBC_B64                      encType = 0
	AES_128_CBC_HMAC_SHA256_B64          encType = 1
	AES_256_CBC_HMAC_SHA256_B64          encType = 2
	RSA_2048_OAEP_SHA256_B64             encType = 3
	RSA_2048_OAEP_SHA1_B64               encType = 4
	RSA_2048_OAEP_SHA256_HMAC_SHA256_B64 encType = 5
	RSA_2048_OAEP_SHA1_HMAC_SHA256_B64   encType = 6
)

type encryptedData struct {
	t encType

	newHash func() hash.Hash

	iv   []byte
	data []byte
	mac  []byte
}

// s to be decrypted
// key is the prelogin key
func decrypt(s string, encKey []byte, hmacKey []byte) (result string, err error) {
	ed, err := parseEncryptedData(s)
	if err != nil {
		return "", err
	}

	if hmacKey != nil && !validateHMAC(ed.newHash, hmacKey, ed.iv, ed.data, ed.mac) {
		// TODO: validate hmac before decrypt
		_ = hmacKey
		// return "", fmt.Errorf("data hmac invalid")
	}

	switch ed.t {
	case AES_256_CBC_B64,
		AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		b, err := aes.NewCipher(encKey)
		if err != nil {
			return "", err
		}

		cbcDec := cipher.NewCBCDecrypter(b, ed.iv)
		buf := make([]byte, len(ed.data))
		cbcDec.CryptBlocks(buf, ed.data)

		// remove padding
		// https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2
		paddingLen := int(buf[len(buf)-1])
		result = string(bytes.TrimSuffix(buf, buf[len(buf)-paddingLen:]))
	case RSA_2048_OAEP_SHA1_B64,
		RSA_2048_OAEP_SHA256_B64,
		RSA_2048_OAEP_SHA1_HMAC_SHA256_B64,
		RSA_2048_OAEP_SHA256_HMAC_SHA256_B64:

		_, _ = rsa.DecryptOAEP(ed.newHash(), rand.Reader, nil, nil, nil)
	}

	return
}

func parseEncryptedData(s string) (ret *encryptedData, err error) {
	var t encType
	parts := strings.Split(s, ".")
	if len(parts) == 2 {
		var v int64
		v, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return
		}

		t = encType(v)
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

	ret = &encryptedData{
		t: t,
	}
	var err2 error
	switch t {
	case AES_128_CBC_HMAC_SHA256_B64, AES_256_CBC_HMAC_SHA256_B64:
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

func parseEncKey(encKey string, preLoginKey []byte) (key, hmacKey []byte, err error) {
	ek, err := parseEncryptedData(encKey)
	if err != nil {
		return nil, nil, err
	}

	switch ek.t {
	case AES_256_CBC_B64:
		hmacKey = nil
	case AES_256_CBC_HMAC_SHA256_B64:
		hashSize := ek.newHash().Size()
		newKey := make([]byte, hashSize*2)

		_, _ = hkdf.Expand(ek.newHash, preLoginKey, []byte("enc")).Read(newKey[:hashSize])
		_, _ = hkdf.Expand(ek.newHash, preLoginKey, []byte("mac")).Read(newKey[hashSize:])

		preLoginKey = newKey[:hashSize]
		hmacKey = newKey[hashSize:]
	default:
		return nil, nil, fmt.Errorf("unsupported enc key type %d", ek.t)
	}

	if hmacKey != nil && !validateHMAC(ek.newHash, hmacKey, ek.iv, ek.data, ek.mac) {
		return nil, nil, fmt.Errorf("enc key hmac invalid")
	}

	b, err := aes.NewCipher(preLoginKey)
	if err != nil {
		return nil, nil, err
	}

	cbcDec := cipher.NewCBCDecrypter(b, ek.iv)
	buf := make([]byte, len(ek.data))
	cbcDec.CryptBlocks(buf, ek.data)

	// always aes-256-cbc, so the cipher length is always 32
	return buf[:32], hmacKey, nil
}

func makeKey(password, email string, kdfTypePtr *bw.KdfType, kdfIterationsPtr *int32) ([]byte, error) {
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
