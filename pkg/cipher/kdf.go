package cipher

import (
	"crypto"
	"crypto/rand"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	"golang.org/x/crypto/pbkdf2"
)

type KDF struct {
	Length     int         `json:"length"`
	Iterations int         `json:"iterations"`
	Salt       string      `json:"salt"`
	HashType   crypto.Hash `json:"hash_type"`
	HashName   string      `json:"hash_name"`
}

func NewKDF(length int, iterations int, hash crypto.Hash) *KDF {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil
	}
	return &KDF{
		Length:     length,
		Iterations: iterations,
		Salt:       utils.Encode(salt),
		HashType:   hash,
		HashName:   hash.String(),
	}
}

func (kdf *KDF) PBKDF2(passphrase string) []byte {
	if kdf == nil || kdf.HashType == 0 {
		return nil
	}
	salt, err := utils.Decode(kdf.Salt)
	if err != nil {
		return nil
	}
	return pbkdf2.Key([]byte(passphrase), salt, kdf.Iterations, kdf.Length, kdf.HashType.New)
}
