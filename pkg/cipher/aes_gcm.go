package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

type AES256GCM struct {
	AEAD cipher.AEAD
}

func NewAES256GCMWithPassPhrase(passphrase string, kdf *KDF) (*AES256GCM, error) {
	key := kdf.PBKDF2(passphrase)
	if key == nil {
		return nil, fmt.Errorf("PBKDF2 failed")
	}
	return NewAES256GCM(key)
}

func NewAES256GCM(key []byte) (*AES256GCM, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, err
	}

	return &AES256GCM{
		AEAD: aesGCM,
	}, nil
}

func (algo *AES256GCM) Encrypt(msg []byte) ([]byte, error) {
	nonce := make([]byte, algo.AEAD.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return algo.AEAD.Seal(nonce, nonce, msg, nil), nil
}

func (algo *AES256GCM) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := algo.AEAD.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("cipher text is not valid")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return algo.AEAD.Open(nil, nonce, ciphertext, nil)
}
