package tss

import (
	"crypto/elliptic"
	"math/big"
)

type (
	Share struct {
		ID, Xi *big.Int
	}
	Shares []*Share
)

//nolint:unparam
func (shares Shares) reconstruct(curve elliptic.Curve) (*big.Int, error) {
	var secret *big.Int
	n := curve.Params().N

	shareIDs := make([]*big.Int, 0)
	for _, share := range shares {
		shareIDs = append(shareIDs, share.ID)
	}

	secret = big.NewInt(0)
	for i, share := range shares {
		t := big.NewInt(1)
		for j := 0; j < len(shareIDs); j++ {
			if j == i {
				continue
			}
			sub := new(big.Int)
			sub.Sub(shareIDs[j], share.ID)
			sub.Mod(sub, n)

			inv := new(big.Int)
			inv.ModInverse(sub, n)

			mul := new(big.Int)
			mul.Mul(shareIDs[j], inv)
			mul.Mod(mul, n)

			tMul := new(big.Int)
			tMul.Mul(t, mul)
			t = tMul.Mod(tMul, n)
		}

		sMul := new(big.Int)
		sMul.Mul(share.Xi, t)
		sMul.Mod(sMul, n)

		sAdd := new(big.Int)
		sAdd.Add(secret, sMul)
		secret = sAdd.Mod(sAdd, n)
	}
	return secret, nil
}
