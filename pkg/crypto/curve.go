package crypto

import (
	"crypto/elliptic"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type CurveType int32

const (
	SECP256K1 CurveType = 1
	ED25519   CurveType = 2
)

var CurveNameType = map[string]CurveType{
	"secp256k1": SECP256K1,
	"ed25519":   ED25519,
}

// S256 secp256k1.
func S256() elliptic.Curve {
	return secp.S256()
}

// Edwards ed25519.
func Edwards() elliptic.Curve {
	return edwards.Edwards()
}
