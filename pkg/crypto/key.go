package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip32"
)

var EDDSAHDPublicKeyID = [4]byte{0x02, 0xe8, 0xde, 0x90} // starts with cpub

func CreateEDDSAPubKey(pub *ecdsa.PublicKey) *edwards.PublicKey {
	ed := &edwards.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
	return ed
}

func CompressPubKey(pubKey *ecdsa.PublicKey) []byte {
	return elliptic.MarshalCompressed(pubKey.Curve, pubKey.X, pubKey.Y)
}

// CompressEDDSAPubKey serializes a public key in a 32-byte compressed little endian format.
func CompressEDDSAPubKey(pubKey *edwards.PublicKey) []byte {
	return pubKey.SerializeCompressed()
}

// SerializeEDDSAPubKey serializes a public key 33-byte compressed format.
func SerializeEDDSAPubKey(pubKey *edwards.PublicKey) []byte {
	b := make([]byte, 0, 33)
	b = append(b, 0x0)
	b = append(b, pubKey.SerializeCompressed()...)

	return b
}

//func UnCompressPubKey(curve elliptic.Curve, pubBytes []byte) (*big.Int, *big.Int) {
//	return elliptic.UnmarshalCompressed(curve, pubBytes)
//}

func DecompressPubKey(pubKey []byte) (*ecdsa.PublicKey, error) {
	pub, err := secp.ParsePubKey(pubKey)
	if err != nil {
		return nil, err
	}
	return pub.ToECDSA(), nil
}

func DecompressEDDSAPubKey(pubKey []byte) (*edwards.PublicKey, error) {
	if len(pubKey) != 32 {
		return nil, fmt.Errorf("not 32 length")
	}
	return edwards.ParsePubKey(pubKey)
}

func UnmarshalPubKey(curve elliptic.Curve, pubBytes []byte) (*big.Int, *big.Int) {
	return elliptic.Unmarshal(curve, pubBytes)
}

func CreateECDSAPrivateKey(curve elliptic.Curve, d *big.Int) *ecdsa.PrivateKey {
	prv := new(ecdsa.PrivateKey)
	prv.PublicKey.Curve = curve
	prv.D = d
	prv.PublicKey.X, prv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return prv
}

func CreateEDDSAPrivateKey(d *big.Int) (*edwards.PrivateKey, error) {
	share := d
	c := Edwards()
	if share.Cmp(c.Params().N) > 0 {
		share = c.Params().N.Mod(share, c.Params().N)
	}
	e := utils.BigIntTo32BytesBE(share)
	prv, _, err := edwards.PrivKeyFromScalar(e[:])
	return prv, err
}

func CreateExtendedPubKey(curveType CurveType, chaincode []byte, pub *ecdsa.PublicKey) (string, error) {
	extPubKey := &bip32.Key{
		ChainCode:   chaincode,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   false,
	}
	switch curveType {
	case SECP256K1:
		extPubKey.Version = bip32.PublicWalletVersion
		extPubKey.Key = CompressPubKey(pub)
	case ED25519:
		edPubKey := CreateEDDSAPubKey(pub)
		extPubKey.Version = EDDSAHDPublicKeyID[:]
		extPubKey.Key = SerializeEDDSAPubKey(edPubKey)
	default:
		return "", fmt.Errorf("not support curve type: %v", curveType)
	}
	return extPubKey.String(), nil
}
