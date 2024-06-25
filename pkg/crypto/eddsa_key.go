package crypto

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/edwards"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
)

func ConvertECDSAPubkeyToEDDSA(pub *ecdsa.PublicKey) *edwards.PublicKey {
	ed := &edwards.PublicKey{
		Curve: pub.Curve,
		X:     pub.X,
		Y:     pub.Y,
	}
	return ed
}

// CompressEDDSAPubKey serializes a public key 33-byte compressed format.
func CompressEDDSAPubKey(pubKey *edwards.PublicKey) []byte {
	b := make([]byte, 0, 33)
	b = append(b, 0x0)
	b = append(b, pubKey.SerializeCompressed()...)

	return b
}

func DecompressEDDSAPubKey(pubKey []byte) (*edwards.PublicKey, error) {
	var pk []byte
	if len(pubKey) == 33 {
		pk = pubKey[1:]
	} else if len(pubKey) == 32 {
		pk = pubKey[:]
	} else {
		return nil, fmt.Errorf("not 32 or 33 length")
	}

	return edwards.ParsePubKey(pk)
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

func CreateEDDSAExtendedPublicKey(pubKey *edwards.PublicKey, chaincode []byte) *EDDSAExtendedKey {
	return NewEDDSAExtendedKey(CompressEDDSAPubKey(pubKey), chaincode, false)
}

func CreateEDDSAExtendedPrivateKey(privKey *edwards.PrivateKey, chaincode []byte) *EDDSAExtendedKey {
	return NewEDDSAExtendedKey(privKey.GetD().Bytes(), chaincode, true)
}
