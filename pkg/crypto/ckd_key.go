package crypto

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/tyler-smith/go-bip32"
)

type KeyType int32

const (
	ECDSAKey KeyType = 1
	EDDSAKey KeyType = 2
)

type CKDKey interface {
	NewChildKey(childIdx uint32) (CKDKey, error)
	PublicKey() CKDKey
	Serialize() ([]byte, error)
	B58Serialize() string
	String() string
	IsPrivateKey() bool
	GetKey() []byte
	GetChainCode() []byte
	GetType() KeyType
}

func Derive(key CKDKey, path string) (CKDKey, error) {
	if path == "" {
		return nil, fmt.Errorf("path is nil")
	}
	indexes, err := parsePath(path)
	if err != nil {
		return nil, err
	}
	dk := key
	for _, index := range indexes {
		dk, err = dk.NewChildKey(index)
		if err != nil {
			return nil, fmt.Errorf("derive key failed: %v", err)
		}
	}
	return dk, nil
}

func parsePath(path string) ([]uint32, error) {
	path = strings.TrimSpace(strings.ReplaceAll(path, " ", ""))
	path = strings.TrimPrefix(path, "m")
	path = strings.TrimPrefix(path, "/m")
	path = strings.TrimPrefix(path, "/")

	segments := strings.Split(path, "/")

	indexes := make([]uint32, 0)
	if len(segments) == 0 || (len(segments) == 1 && segments[0] == "") {
		return nil, nil
	}

	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("segment nil")
		}
		var i uint32
		if strings.HasSuffix(segment, "'") || strings.HasSuffix(segment, "H") {
			num, err := strconv.Atoi(segment[:len(segment)-1])
			if err != nil {
				return nil, err
			}
			i = 1<<31 + uint32(num)
		} else {
			num, err := strconv.Atoi(segment)
			if err != nil {
				return nil, err
			}
			i = uint32(num)
		}
		indexes = append(indexes, i)
	}
	return indexes, nil
}

func B58Deserialize(data string) (CKDKey, error) {
	b, err := base58Decode(data)
	if err != nil {
		return nil, err
	}
	id := b[0:4]
	if bytes.Equal(id, EDDSAHDPrivateKeyID[:]) || bytes.Equal(id, EDDSAHDPublicKeyID[:]) {
		return B58DeserializeEDDSAExtendedKey(data)
	} else if bytes.Equal(id, bip32.PrivateWalletVersion) || bytes.Equal(id, bip32.PublicWalletVersion[:]) {
		return B58DeserializeECDSAExtendedKey(data)
	}

	return nil, fmt.Errorf("error key version 0x%x", id)
}
