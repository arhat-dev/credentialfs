package bitwarden

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"hash"

	bw "arhat.dev/bitwardenapi/bwinternal"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type suiteKind int

// ref: https://github.com/bitwarden/jslib/blob/master/common/src/enums/encryptionType.ts
// nolint:revive
const (
	AES_256_CBC_B64 suiteKind = 0

	AES_128_CBC_HMAC_SHA256_B64 suiteKind = 1
	AES_256_CBC_HMAC_SHA256_B64 suiteKind = 2

	RSA_2048_OAEP_SHA256_B64 suiteKind = 3
	RSA_2048_OAEP_SHA1_B64   suiteKind = 4

	// Deprecated HMAC
	RSA_2048_OAEP_SHA256_HMAC_SHA256_B64 suiteKind = 5
	RSA_2048_OAEP_SHA1_HMAC_SHA256_B64   suiteKind = 6
)

func (k suiteKind) String() string {
	switch k {
	case AES_256_CBC_B64:
		return "AES_256_CBC_B64"
	case AES_128_CBC_HMAC_SHA256_B64:
		return "AES_128_CBC_HMAC_SHA256_B64"
	case AES_256_CBC_HMAC_SHA256_B64:
		return "AES_256_CBC_HMAC_SHA256_B64"
	case RSA_2048_OAEP_SHA256_B64:
		return "RSA_2048_OAEP_SHA256_B64"
	case RSA_2048_OAEP_SHA1_B64:
		return "RSA_2048_OAEP_SHA1_B64"
	case RSA_2048_OAEP_SHA256_HMAC_SHA256_B64:
		return "RSA_2048_OAEP_SHA256_HMAC_SHA256_B64"
	case RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:
		return "RSA_2048_OAEP_SHA1_HMAC_SHA256_B64"
	default:
		panic(fmt.Errorf("unknown suite kind %d", k))
	}
}

type protectedData struct {
	encryptedWith suiteKind

	newHash func() hash.Hash

	iv  []byte
	mac []byte

	encryptedData []byte
}

func (d *protectedData) decrypt(key *bitwardenKey) (result []byte, err error) {
	if len(d.mac) != 0 {
		if len(key.hmacKey) == 0 {
			return nil, fmt.Errorf("hmac key required but not found")
		}

		if !validateHMAC(d.newHash, key.hmacKey, d.iv, d.encryptedData, d.mac) {
			return nil, fmt.Errorf("invalid hmac for protected data")
		}
	}

	switch d.encryptedWith {
	case AES_256_CBC_B64,
		AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		result, err = decrypt_aes_cbc(d.encryptedData, key.key, d.iv)
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

func (d *protectedData) decrypt_as_key(keyForDecryption *bitwardenKey) (*bitwardenKey, error) {
	var (
		key     = keyForDecryption.key
		hmacKey = keyForDecryption.hmacKey

		ret = &bitwardenKey{kind: d.encryptedWith}

		err error
	)

	// prepare for key verification

	// check target used encryption method, the key should match
	switch d.encryptedWith {
	case AES_256_CBC_B64:
		// do nothing
	case AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:

		if hmacKey == nil {
			// stretch key when keyForDecruption has no hmacKey
			//
			// only used when the keyForDecruption.key is the prelogin key
			newKey := make([]byte, 64)

			_, _ = hkdf.Expand(d.newHash, keyForDecryption.key, []byte("enc")).Read(newKey[:32])
			_, _ = hkdf.Expand(d.newHash, keyForDecryption.key, []byte("mac")).Read(newKey[32:])

			key, hmacKey = newKey[:32], newKey[32:]
		}
	case RSA_2048_OAEP_SHA256_B64,
		RSA_2048_OAEP_SHA1_B64:
		// do nothing
	case RSA_2048_OAEP_SHA256_HMAC_SHA256_B64,
		RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:
		// do nothing
	default:
		return nil, fmt.Errorf("unsupported key type %d", d.encryptedWith)
	}

	// verify key

	if d.mac != nil {
		if !validateHMAC(d.newHash, hmacKey, d.iv, d.encryptedData, d.mac) {
			return nil, fmt.Errorf("key mac invalid")
		}
	}

	// decrypt key

	switch d.encryptedWith {
	case AES_256_CBC_B64,
		AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:
		ret.key, err = decrypt_aes_cbc(d.encryptedData, key, d.iv)
		if err != nil {
			return nil, fmt.Errorf("failed to decode symmetric key: %w", err)
		}

		size := len(ret.key)

		switch d.encryptedWith {
		case AES_256_CBC_B64:
		case AES_128_CBC_HMAC_SHA256_B64:
			ret.key, ret.hmacKey = ret.key[:size-256/8], ret.key[size-256/8:]
		case AES_256_CBC_HMAC_SHA256_B64:
			ret.key, ret.hmacKey = ret.key[:size-256/8], ret.key[size-256/8:]
		default:
			panic("unreachable")
		}
	case RSA_2048_OAEP_SHA256_B64,
		RSA_2048_OAEP_SHA1_B64,
		RSA_2048_OAEP_SHA256_HMAC_SHA256_B64,
		RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:

		k, err := x509.ParsePKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid pkcs#8 private key: %w", err)
		}

		pk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid non rsa private key: %T", k)
		}

		ret.key, err = rsa.DecryptOAEP(d.newHash(), rand.Reader, pk, d.encryptedData, []byte("decrypt"))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt rsa-oaep private key: %w", err)
		}

		ret.key = ret.key[:2048/8]

		switch d.encryptedWith {
		case RSA_2048_OAEP_SHA256_HMAC_SHA256_B64,
			RSA_2048_OAEP_SHA1_HMAC_SHA256_B64:
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

func (key *bitwardenKey) decrypt(d []byte) (result []byte, err error) {
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
		data.encryptedData = d[17:]

		result, err = decrypt_aes_cbc(data.encryptedData, key.key, data.iv)
	case AES_128_CBC_HMAC_SHA256_B64,
		AES_256_CBC_HMAC_SHA256_B64:

		data.iv = d[1:17]
		data.mac = d[17:49]
		data.encryptedData = d[49:]

		if !validateHMAC(sha256.New, key.hmacKey, data.iv, data.encryptedData, data.mac) {
			return nil, fmt.Errorf("data mac value invalid")
		}

		result, err = decrypt_aes_cbc(data.encryptedData, key.key, data.iv)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported crypto suite: %d", key.kind)
	}

	return
}

// refs: https://github.com/bitwarden/jslib/blob/master/common/src/enums/kdfType.ts
const (
	KDFType_PBKDF2_SHA256   bw.KdfType = bw.KdfTypeN0
	minimumPBKDF2Iterations int        = 5000
)

// makeMasterKey creates a master key from email and password using pbkdf2
// n is the iteration count
func makeMasterKey(email, password []byte, kt bw.KdfType, n int) ([]byte, error) {
	if n == 0 {
		n = minimumPBKDF2Iterations
	}

	switch kt {
	case KDFType_PBKDF2_SHA256:
		if n < minimumPBKDF2Iterations {
			return nil, fmt.Errorf("pbkdf2 iteration minimum is %d", minimumPBKDF2Iterations)
		}

		return pbkdf2.Key(password, email, n, sha256.Size, sha256.New), nil
	default:
		return nil, fmt.Errorf("unknown kdf type %d", kt)
	}
}

func validateHMAC(newHash func() hash.Hash, hmacKey, iv, data, mac []byte) bool {
	hm := hmac.New(newHash, hmacKey)
	hm.Write(iv)
	hm.Write(data)

	return hmac.Equal(mac, hm.Sum(nil))
}
