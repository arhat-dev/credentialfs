package bitwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// nolint:revive
func decrypt_aes_cbc(data, key, iv []byte) (_ []byte, err error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	data, err = pkcs7Pad(data, b.BlockSize())
	if err != nil {
		return nil, err
	}

	decryptor := cipher.NewCBCDecrypter(b, iv)

	decryptedBytes := make([]byte, len(data))
	decryptor.CryptBlocks(decryptedBytes, data)

	return pkcs7Unpad(decryptedBytes, decryptor.BlockSize())
}

func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, fmt.Errorf("invalid blocksize %d", blocksize)
	}

	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)

	subtle.ConstantTimeCopy(1, pb[:len(b)], b)
	subtle.ConstantTimeCopy(1, pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return b, nil
}

func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, fmt.Errorf("invalid blocksize %d", blocksize)
	}
	if b == nil || len(b) == 0 {
		return nil, fmt.Errorf("invalid data")
	}
	if len(b)%blocksize != 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	c := b[len(b)-1]
	n := int(c)

	if n == 0 || n > len(b) {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return b[:len(b)-n], nil
}
