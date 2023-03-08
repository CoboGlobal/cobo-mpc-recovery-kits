package crypto

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/FactomProject/basen"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck
)

// BitcoinBase58Encoding is the encoding used for bitcoin addresses.
var BitcoinBase58Encoding = basen.NewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

//
// Hashes
//

func hashSha256(data []byte) ([]byte, error) {
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hashDoubleSha256(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashSha256(hash1)
	if err != nil {
		return nil, err
	}
	return hash2, nil
}

func hashRipeMD160(data []byte) ([]byte, error) {
	hasher := ripemd160.New()
	_, err := io.WriteString(hasher, string(data))
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func hash160(data []byte) ([]byte, error) {
	hash1, err := hashSha256(data)
	if err != nil {
		return nil, err
	}

	hash2, err := hashRipeMD160(hash1)
	if err != nil {
		return nil, err
	}

	return hash2, nil
}

//
// Encoding
//

func checksum(data []byte) ([]byte, error) {
	hash, err := hashDoubleSha256(data)
	if err != nil {
		return nil, err
	}

	return hash[:4], nil
}

func addChecksumToBytes(data []byte) ([]byte, error) {
	checksum, err := checksum(data)
	if err != nil {
		return nil, err
	}
	return append(data, checksum...), nil
}

func base58Encode(data []byte) string {
	return BitcoinBase58Encoding.EncodeToString(data)
}

func base58Decode(data string) ([]byte, error) {
	return BitcoinBase58Encoding.DecodeString(data)
}

func addPrivateKeys(curve elliptic.Curve, key1 []byte, key2 []byte) []byte {
	var key1Int big.Int
	var key2Int big.Int
	key1Int.SetBytes(key1)
	key2Int.SetBytes(key2)

	key1Int.Add(&key1Int, &key2Int)
	key1Int.Mod(&key1Int, curve.Params().N)

	b := key1Int.Bytes()
	if len(b) < 32 {
		extra := make([]byte, 32-len(b))
		b = append(extra, b...) //nolint:makezero
	}
	return b
}

func validatePrivateKey(curve elliptic.Curve, key []byte) error {
	if fmt.Sprintf("%x", key) == "0000000000000000000000000000000000000000000000000000000000000000" || // if the key is zero
		bytes.Compare(key, curve.Params().N.Bytes()) >= 0 || // or is outside of the curve
		len(key) != 32 { // or is too short
		return ErrInvalidPrivateKey
	}

	return nil
}

// Numerical.
func uint32Bytes(i uint32) []byte {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, i)
	return bytes
}
