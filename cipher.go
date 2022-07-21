package webref

import (
	"crypto/aes"
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20"
)

type Decryptor = func(x io.ReadCloser, key, nonce []byte) (io.ReadCloser, error)

func ChaCha20Decrypt(x io.ReadCloser, key, nonce []byte) (io.ReadCloser, error) {
	ciph, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, err
	}
	return closer{
		Reader: cipher.StreamReader{
			S: ciph,
			R: x,
		},
		close: x.Close,
	}, nil
}

func AES256CTRDecrypt(x io.ReadCloser, key, nonce []byte) (io.ReadCloser, error) {
	blockCiph, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return closer{
		Reader: cipher.StreamReader{
			S: cipher.NewCTR(blockCiph, nonce),
			R: x,
		},
	}, nil
}
