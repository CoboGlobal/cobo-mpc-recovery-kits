package crypto

import (
	"crypto/elliptic"

	s256k1 "github.com/btcsuite/btcd/btcec/v2"
)

type CurveType int32

const (
	SECP256K1 CurveType = 0
	ED25519   CurveType = 1
)

var CurveNameType = map[string]CurveType{
	"secp256k1": SECP256K1,
	"ed25519":   ED25519,
}

// S256 secp256k1.
func S256() elliptic.Curve {
	return s256k1.S256()
}
