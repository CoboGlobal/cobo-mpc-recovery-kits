package crypto

import "github.com/tyler-smith/go-bip32"

type ECDSAExtendedKey struct {
	*bip32.Key
}

func NewECDSAExtendedKey(key *bip32.Key) *ECDSAExtendedKey {
	return &ECDSAExtendedKey{key}
}

func (e *ECDSAExtendedKey) NewChildKey(childIdx uint32) (CKDKey, error) {
	childKey, err := e.Key.NewChildKey(childIdx)
	return NewECDSAExtendedKey(childKey), err
}

func (e *ECDSAExtendedKey) PublicKey() CKDKey {
	return NewECDSAExtendedKey(e.Key.PublicKey())
}

func (e *ECDSAExtendedKey) IsPrivateKey() bool {
	return e.Key.IsPrivate
}

func (e *ECDSAExtendedKey) GetKey() []byte {
	return e.Key.Key
}

func (e *ECDSAExtendedKey) GetChainCode() []byte {
	return e.Key.ChainCode
}

func (e *ECDSAExtendedKey) GetType() KeyType {
	return ECDSAKey
}

func B58DeserializeECDSAExtendedKey(data string) (CKDKey, error) {
	key, err := bip32.B58Deserialize(data)
	if err != nil {
		return nil, err
	}
	return &ECDSAExtendedKey{key}, nil
}
