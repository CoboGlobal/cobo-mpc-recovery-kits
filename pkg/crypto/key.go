package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func CompressPubKey(pubKey *ecdsa.PublicKey) []byte {
	return elliptic.MarshalCompressed(pubKey.Curve, pubKey.X, pubKey.Y)
}

//func UnCompressPubKey(curve elliptic.Curve, pubBytes []byte) (*big.Int, *big.Int) {
//	return elliptic.UnmarshalCompressed(curve, pubBytes)
//}

func DecompressPubKey(curveType CurveType, pubKey []byte) (x, y *big.Int) {
	if curveType == SECP256K1 {
		key, err := secp.ParsePubKey(pubKey)
		if err != nil {
			return nil, nil
		}
		x, y = UnmarshalPubKey(S256(), key.SerializeUncompressed())
		return
	} else {
		return nil, nil
	}
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

func ParseECDSAPublicKey(public string) (x, y *big.Int, err error) {
	shareBytes, err := utils.Decode(public)
	if err != nil {
		return nil, nil, fmt.Errorf("share public key parse error: %v", err)
	}

	if shareBytes[0] == 0o4 && len(shareBytes) == 65 {
		x, y = UnmarshalPubKey(S256(), shareBytes)
		if x == nil || y == nil {
			return nil, nil, fmt.Errorf("unmarshal public key failed")
		}
	} else if (shareBytes[0] == 0o2 || shareBytes[0] == 0o3) && len(shareBytes) == 33 {
		x, y = DecompressPubKey(SECP256K1, shareBytes)
		if x == nil || y == nil {
			return nil, nil, fmt.Errorf("uncompress public key failed")
		}
	} else {
		return nil, nil, fmt.Errorf("share public key not support")
	}
	return x, y, nil
}
