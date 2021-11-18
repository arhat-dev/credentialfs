package system

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

// encryptionKey is a base64 encoded string as an AES-256-GCM key
// to encrypt login data stored in system keychain
// the encryptionKey is hashed with sha256 before being used as cipher key
//
// can be overriden using ldflag
// "-X arhat.dev/credentialfs/pkg/security/system.encryptionKey=<NEW ENCRYPTION KEY>"
var (
	encryptionKey = base64.StdEncoding.EncodeToString([]byte("arhat.dev"))
)

var (
	encrypt func(d []byte) []byte
	decrypt func(d []byte) ([]byte, error)
)

func init() {
	encKey, err := base64.StdEncoding.DecodeString(encryptionKey)
	if err != nil {
		panic(err)
	}

	h := sha256.New()
	_, err = h.Write(encKey)
	if err != nil {
		panic(err)
	}

	c, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		panic(err)
	}

	const (
		salt = "credentialfs"
	)

	nonce := argon2.IDKey(encKey, []byte(salt), 1024, 1024, 4, uint32(aesgcm.NonceSize()))

	encrypt = func(d []byte) []byte {
		return aesgcm.Seal(nil, nonce, d, nil)
	}

	decrypt = func(d []byte) ([]byte, error) {
		return aesgcm.Open(nil, nonce, d, nil)
	}
}
