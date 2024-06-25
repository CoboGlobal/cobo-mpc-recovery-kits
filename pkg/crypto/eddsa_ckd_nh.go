package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// The functions below do not implement the full BIP-32 specification.
// we only use non-hardened derived keys for eddsa

// FirstHardenedChild is the index of the firxt "harded" child key as per the
// bip32 spec.
const FirstHardenedChild = uint32(0x80000000)

var (
	EDDSAHDPublicKeyID  = [4]byte{0x02, 0xe8, 0xde, 0x90} // starts with cpub
	EDDSAHDPrivateKeyID = [4]byte{0x02, 0xe8, 0xda, 0x54} // starts with cprv

	// ErrSerializedKeyWrongSize is returned when trying to deserialize a key that
	// has an incorrect length.
	ErrSerializedKeyWrongSize = errors.New("Serialized keys should by exactly 82 bytes")

	// ErrHardnedChildKey is returned when trying to create a harded child key.
	ErrHardnedChildKey = errors.New("Can't create hardened child key")

	// ErrInvalidChecksum is returned when deserializing a key with an incorrect
	// checksum.
	ErrInvalidChecksum = errors.New("Checksum doesn't match")

	// ErrInvalidPrivateKey is returned when a derived private key is invalid.
	ErrInvalidPrivateKey = errors.New("Invalid private key")

	// ErrInvalidPublicKey is returned when a derived public key is invalid.
	ErrInvalidPublicKey = errors.New("Invalid public key")
)

// EDDSAExtendedKey represents a non-hardened bip32 extended key

// private key 32 bytes
// public key 0x00 + 32 bytes

type EDDSAExtendedKey struct {
	Key         []byte // 33 bytes
	Version     []byte // 4 bytes
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	Depth       byte   // 1 bytes
	IsPrivate   bool   // unserialized
}

// NewEDDSAExtendedKey creates a new extended key.
func NewEDDSAExtendedKey(key []byte, chainCode []byte, isPrivate bool) *EDDSAExtendedKey {
	extkey := &EDDSAExtendedKey{
		ChainCode:   chainCode,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   isPrivate,
	}
	if isPrivate {
		if len(key) < 32 {
			extra := make([]byte, 32-len(key))
			key = append(extra, key...) //nolint:makezero
		}
		extkey.Version = EDDSAHDPrivateKeyID[:]
		extkey.Key = key
	} else {
		extkey.Version = EDDSAHDPublicKeyID[:]
		extkey.Key = key
	}
	return extkey
}

// NewChildKey derives a child key from a given parent as outlined by bip32.
func (key *EDDSAExtendedKey) NewChildKey(childIdx uint32) (CKDKey, error) {
	// Fail early if trying to create hardened child from public key
	if childIdx >= FirstHardenedChild {
		return nil, ErrHardnedChildKey
	}

	intermediary, err := key.getIntermediary(childIdx)
	if err != nil {
		return nil, err
	}

	// Create child EDDSAExtendedKey with data common to all both scenarios
	childKey := &EDDSAExtendedKey{
		ChildNumber: uint32Bytes(childIdx),
		ChainCode:   intermediary[32:],
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
	}

	// Bip32 CKDpriv
	if key.IsPrivate {
		childKey.Version = EDDSAHDPrivateKeyID[:]
		d := new(big.Int).SetBytes(key.Key)
		sk, err := CreateEDDSAPrivateKey(d)
		if err != nil {
			return nil, err
		}
		parentPubBytes := CompressEDDSAPubKey(sk.PubKey())
		fingerprint, err := hash160(parentPubBytes)
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
		childKey.Key = addPrivateKeys(Edwards(), intermediary[:32], key.Key)

		// Validate key
		err = validatePrivateKey(Edwards(), childKey.Key)
		if err != nil {
			return nil, err
		}
		// Bip32 CKDpub
	} else {
		d := new(big.Int).SetBytes(intermediary[:32])
		sk, err := CreateEDDSAPrivateKey(d)
		if err != nil {
			return nil, err
		}

		childKey.Version = EDDSAHDPublicKeyID[:]
		fingerprint, err := hash160(key.Key)
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]

		parentPub, err := DecompressEDDSAPubKey(key.Key)
		if err != nil {
			return nil, err
		}
		x, y := parentPub.Add(sk.PubKey().X, sk.PubKey().Y, parentPub.X, parentPub.Y)
		childPub := edwards.NewPublicKey(x, y)
		childKey.Key = CompressEDDSAPubKey(childPub)
	}

	return childKey, nil
}

func (key *EDDSAExtendedKey) getIntermediary(childIdx uint32) ([]byte, error) {
	// Get intermediary to create key and chaincode from
	// Hardened children are based on the private key
	// NonHardened children are based on the public key
	childIndexBytes := uint32Bytes(childIdx)

	var data []byte
	if childIdx >= FirstHardenedChild {
		data = append([]byte{0x0}, key.Key...)
	} else {
		if key.IsPrivate {
			d := new(big.Int).SetBytes(key.Key)
			sk, err := CreateEDDSAPrivateKey(d)
			if err != nil {
				return nil, err
			}
			data = CompressEDDSAPubKey(sk.PubKey())
		} else {
			data = key.Key
		}
	}
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, key.ChainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

// PublicKey returns the public version of key or return a copy
// The 'Neuter' function from the bip32 spec.
func (key *EDDSAExtendedKey) PublicKey() CKDKey {
	keyBytes := key.Key

	if key.IsPrivate {
		d := new(big.Int).SetBytes(key.Key)
		sk, err := CreateEDDSAPrivateKey(d)
		if err != nil {
			return nil
		}
		keyBytes = CompressEDDSAPubKey(sk.PubKey())
	}

	return &EDDSAExtendedKey{
		Version:     EDDSAHDPublicKeyID[:],
		Key:         keyBytes,
		Depth:       key.Depth,
		ChildNumber: key.ChildNumber,
		FingerPrint: key.FingerPrint,
		ChainCode:   key.ChainCode,
		IsPrivate:   false,
	}
}

// Serialize a EDDSAExtendedKey to a 78 byte byte slice.
func (key *EDDSAExtendedKey) Serialize() ([]byte, error) {
	// Private keys should be prepended with a single null byte
	keyBytes := key.Key
	if key.IsPrivate {
		keyBytes = append([]byte{0x0}, keyBytes...)
	}

	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	buffer.Write(key.Version)
	buffer.WriteByte(key.Depth)
	buffer.Write(key.FingerPrint)
	buffer.Write(key.ChildNumber)
	buffer.Write(key.ChainCode)
	buffer.Write(keyBytes)

	// Append the standard doublesha256 checksum
	serializedKey, err := addChecksumToBytes(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return serializedKey, nil
}

// B58Serialize encodes the EDDSAExtendedKey in the standard Bitcoin base58 encoding.
func (key *EDDSAExtendedKey) B58Serialize() string {
	serializedKey, err := key.Serialize()
	if err != nil {
		return ""
	}

	return base58Encode(serializedKey)
}

// String encodes the EDDSAExtendedKey in the standard Bitcoin base58 encoding.
func (key *EDDSAExtendedKey) String() string {
	return key.B58Serialize()
}

func (key *EDDSAExtendedKey) IsPrivateKey() bool {
	return key.IsPrivate
}

func (key *EDDSAExtendedKey) GetKey() []byte {
	return key.Key
}

func (key *EDDSAExtendedKey) GetChainCode() []byte {
	return key.ChainCode
}

func (key *EDDSAExtendedKey) GetType() KeyType {
	return EDDSAKey
}

// DeserializeEDDSAExtendedKey a byte slice into a EDDSAExtendedKey.
func DeserializeEDDSAExtendedKey(data []byte) (CKDKey, error) {
	if len(data) != 82 {
		return nil, ErrSerializedKeyWrongSize
	}
	key := &EDDSAExtendedKey{}
	key.Version = data[0:4]
	key.Depth = data[4]
	key.FingerPrint = data[5:9]
	key.ChildNumber = data[9:13]
	key.ChainCode = data[13:45]

	if bytes.Equal(key.Version, EDDSAHDPrivateKeyID[:]) {
		key.IsPrivate = true
		key.Key = data[46:78]
	} else if bytes.Equal(key.Version, EDDSAHDPublicKeyID[:]) {
		key.IsPrivate = false
		key.Key = data[45:78]
	} else {
		return nil, fmt.Errorf("invalid EDDSA HD key id")
	}

	// validate checksum
	cs1, err := checksum(data[0 : len(data)-4])
	if err != nil {
		return nil, err
	}

	cs2 := data[len(data)-4:]
	for i := range cs1 {
		if cs1[i] != cs2[i] {
			return nil, ErrInvalidChecksum
		}
	}
	return key, nil
}

// B58DeserializeEDDSAExtendedKey deserializes a EDDSAExtendedKey encoded in base58 encoding.
func B58DeserializeEDDSAExtendedKey(data string) (CKDKey, error) {
	b, err := base58Decode(data)
	if err != nil {
		return nil, err
	}
	return DeserializeEDDSAExtendedKey(b)
}
