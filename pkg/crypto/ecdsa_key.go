package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip32"
)

func CompressECDSAPubKey(pubKey *ecdsa.PublicKey) []byte {
	return elliptic.MarshalCompressed(pubKey.Curve, pubKey.X, pubKey.Y)
}

//func UnCompressPubKey(curve elliptic.Curve, pubBytes []byte) (*big.Int, *big.Int) {
//	return elliptic.UnmarshalCompressed(curve, pubBytes)
//}

func DecompressECDSAPubKey(pubKey []byte) (*ecdsa.PublicKey, error) {
	pub, err := secp.ParsePubKey(pubKey)
	if err != nil {
		return nil, err
	}
	return pub.ToECDSA(), nil
}

//func UnmarshalPubKey(curve elliptic.Curve, pubBytes []byte) (*big.Int, *big.Int) {
//	return elliptic.Unmarshal(curve, pubBytes)
//}

func CreateECDSAPrivateKey(curve elliptic.Curve, d *big.Int) *ecdsa.PrivateKey {
	prv := new(ecdsa.PrivateKey)
	prv.PublicKey.Curve = curve
	prv.D = d
	prv.PublicKey.X, prv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return prv
}

func CreateECDSAExtendedPublicKey(pub *ecdsa.PublicKey, chaincode []byte) *bip32.Key {
	extPubKey := &bip32.Key{
		Version:     bip32.PublicWalletVersion,
		Key:         CompressECDSAPubKey(pub),
		ChainCode:   chaincode,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   false,
	}
	return extPubKey
}

func CreateECDSAExtendedPrivateKey(private *ecdsa.PrivateKey, chaincode []byte) *bip32.Key {
	extPrivateKey := &bip32.Key{
		Version:     bip32.PrivateWalletVersion,
		ChainCode:   chaincode,
		Key:         private.D.Bytes(),
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
	}
	return extPrivateKey
}
