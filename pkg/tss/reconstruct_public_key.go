package tss

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
)

type (
	SharePub struct {
		ID       *big.Int
		SharePub *ecdsa.PublicKey
	}
	SharePubs []*SharePub
)

func (shares SharePubs) ReconstructKey(threshold int) (*ecdsa.PublicKey, error) {
	if shares == nil || threshold < 1 {
		return nil, fmt.Errorf("input error")
	}
	if threshold > len(shares) {
		return nil, fmt.Errorf("too little shares for threshold to reconstruct")
	}

	curve := shares[0].SharePub.Curve
	n := curve.Params().N

	shareIDs := make([]*big.Int, 0)
	for _, share := range shares {
		shareIDs = append(shareIDs, share.ID)
	}

	var public *ecdsa.PublicKey
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

		x, y := curve.ScalarMult(share.SharePub.X, share.SharePub.Y, t.Bytes())
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("point not on the curve")
		}
		if public == nil {
			public = &ecdsa.PublicKey{
				Curve: curve,
				X:     x,
				Y:     y,
			}
		} else {
			newX, newY := curve.Add(public.X, public.Y, x, y)
			if !curve.IsOnCurve(newX, newY) {
				return nil, fmt.Errorf("point not on the curve")
			}
			public = &ecdsa.PublicKey{
				Curve: curve,
				X:     newX,
				Y:     newY,
			}
		}
	}
	return public, nil
}
