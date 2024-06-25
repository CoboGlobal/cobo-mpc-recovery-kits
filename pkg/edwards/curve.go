// Copyright (c) 2015-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package edwards

import (
	"crypto/elliptic"
	"math/big"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// TwistedEdwardsCurve extended an elliptical curve set of
// parameters to satisfy the interface of the elliptic package.
type TwistedEdwardsCurve struct {
	*elliptic.CurveParams
	H int // Cofactor of the curve

	A, D, I *big.Int // Edwards curve equation parameter constants

	// byteSize is simply the bit size / 8 and is provided for convenience
	// since it is calculated repeatedly.
	byteSize int
}

// Params returns the parameters for the curve.
func (curve TwistedEdwardsCurve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// recoverXBigInt recovers the X value for some Y value, for a coordinate
// on the Ed25519 curve given as a big integer Y value.
func (curve *TwistedEdwardsCurve) recoverXBigInt(xIsNeg bool, y *big.Int) *big.Int {
	// (y^2 - 1)
	l := new(big.Int).Mul(y, y)
	l.Sub(l, one)

	// inv(d*y^2+1)
	temp := new(big.Int).Mul(y, y)
	temp.Mul(temp, curve.D)
	temp.Add(temp, one)
	r := curve.invert(temp)

	// x2 = (y^2 - 1) * invert(d*y^2+1)
	x2 := new(big.Int).Mul(r, l)

	// x = exp(x^2,(P+3)/8, P)
	qp3 := new(big.Int).Add(curve.P, three)
	qp3.Div(qp3, eight) // /= curve.H
	x := new(big.Int).Exp(x2, qp3, curve.P)

	// check (x^2 - x2) % q != 0
	x22 := new(big.Int).Mul(x, x)
	xsub := new(big.Int).Sub(x22, x2)
	xsub.Mod(xsub, curve.P)
	if xsub.Cmp(zero) != 0 {
		ximod := new(big.Int)
		ximod.Mul(x, curve.I)
		ximod.Mod(ximod, curve.P)
		x.Set(ximod)
	}

	xmod2 := new(big.Int).Mod(x, two)
	if xmod2.Cmp(zero) != 0 {
		x.Sub(curve.P, x)
	}

	// We got the wrong x, negate it to get the right one.
	if xIsNeg != (x.Bit(0) == 1) {
		x.Sub(curve.P, x)
	}

	return x
}

// recoverXFieldElement recovers the X value for some Y value, for a coordinate
// on the Ed25519 curve given as a field element. Y value. Probably the fastest
// way to get your respective X from Y.
func (curve *TwistedEdwardsCurve) recoverXFieldElement(xIsNeg bool, y *field.Element) *field.Element {
	// (y^2 - 1)
	l := new(field.Element)
	l = l.Square(y)
	l = l.Subtract(l, feOne)

	// inv(d*y^2+1)
	r := new(field.Element)
	r = r.Square(y)
	r = r.Multiply(r, feD)
	r = r.Add(r, feOne)
	r = r.Invert(r)

	x2 := new(field.Element)
	x2 = x2.Multiply(r, l)

	// Get a big int so we can do the exponentiation.
	x2Big := fieldElementToBigInt(x2)

	// x = exp(x^2,(P+3)/8, P)
	qp3 := new(big.Int).Add(curve.P, three)
	qp3.Div(qp3, eight) // /= curve.H
	xBig := new(big.Int).Exp(x2Big, qp3, curve.P)

	// Convert back to a field element and do
	// the rest.
	x := bigIntToFieldElement(xBig)

	// check (x^2 - x2) % q != 0
	x22 := new(field.Element)
	x22 = x22.Square(x)
	xsub := new(field.Element)
	xsub = xsub.Subtract(x22, x2)
	xsubBig := fieldElementToBigInt(xsub)
	xsubBig.Mod(xsubBig, curve.P)

	if xsubBig.Cmp(zero) != 0 {
		xi := new(field.Element)
		xi = xi.Multiply(x, sqrtM1)
		xiModBig := fieldElementToBigInt(xi)
		xiModBig.Mod(xiModBig, curve.P)
		xiMod := bigIntToFieldElement(xiModBig)

		x = xiMod
	}

	xBig = fieldElementToBigInt(x)
	xmod2 := new(big.Int).Mod(xBig, two)
	if xmod2.Cmp(zero) != 0 {
		// TODO replace this with FeSub
		xBig.Sub(curve.P, xBig)
		x = bigIntToFieldElement(xBig)
	}

	// We got the wrong x, negate it to get the right one.
	isNegative := x.IsNegative() == 1
	if xIsNeg != isNegative {
		x = x.Negate(x)
	}

	return x
}

// IsOnCurve returns bool to say if the point (x,y) is on the curve by
// checking (y^2 - x^2 - 1 - dx^2y^2) % P == 0.
func (curve *TwistedEdwardsCurve) IsOnCurve(x *big.Int, y *big.Int) bool {
	// Convert to field elements.
	xB := bigIntToEncodedBytes(x)
	yB := bigIntToEncodedBytes(y)

	yfe, err := new(field.Element).SetBytes(yB[:])
	if err != nil {
		return false
	}
	xfe, err := new(field.Element).SetBytes(xB[:])
	if err != nil {
		return false
	}

	x2 := new(field.Element)
	x2 = x2.Square(xfe)
	y2 := new(field.Element)
	y2 = y2.Square(yfe)

	dx2y2 := new(field.Element)
	dx2y2 = dx2y2.Multiply(feD, x2)
	dx2y2 = dx2y2.Multiply(dx2y2, y2)

	enum := new(field.Element)
	enum = enum.Subtract(y2, x2)
	enum = enum.Subtract(enum, feOne)
	enum = enum.Subtract(enum, dx2y2)

	enumBig := fieldElementToBigInt(enum)
	enumBig.Mod(enumBig, curve.P)

	if enumBig.Cmp(zero) != 0 {
		return false
	}

	// Check if we're in the cofactor of the curve (8).
	modEight := new(big.Int)
	modEight.Mod(enumBig, eight)

	return modEight.Cmp(zero) == 0
}

// Add adds two points represented by pairs of big integers on the elliptical
// curve.
func (curve *TwistedEdwardsCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	// Convert to extended from affine.
	p := bigIntPointToEncodedBytes(x1, y1)
	pP, err := new(edwards25519.Point).SetBytes(p[:])
	if err != nil {
		return nil, nil
	}

	q := bigIntPointToEncodedBytes(x2, y2)
	qP, err := new(edwards25519.Point).SetBytes(q[:])
	if err != nil {
		return nil, nil
	}

	rPoint := new(edwards25519.Point).Add(pP, qP)

	rB := rPoint.Bytes()
	s := new([32]byte)
	copy(s[:], rB)
	x, y, _ = curve.encodedBytesToBigIntPoint(s)

	return
}

// Double adds the same pair of big integer coordinates to itself on the
// elliptical curve.
func (curve *TwistedEdwardsCurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	// Convert to extended projective coordinates.
	p := bigIntPointToEncodedBytes(x1, y1)
	pP, err := new(edwards25519.Point).SetBytes(p[:])
	if err != nil {
		return nil, nil
	}

	p2 := new(projP2).FromP3(pP)
	p1xp1 := new(projP1xP1).Double(p2)

	r := pointFromP1xP1(p1xp1)
	rB := r.Bytes()
	s := new([32]byte)
	copy(s[:], rB)
	x, y, err = curve.encodedBytesToBigIntPoint(s)
	if err != nil {
		return nil, nil
	}
	return
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form. This
// uses the repeated doubling method, which is variable time.
// TODO use a constant time method to prevent side channel attacks.
func (curve *TwistedEdwardsCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	// Convert the scalar to a big int.
	s := new(big.Int).SetBytes(k)

	// Get a new group element to do cached doubling
	// calculations in.
	p := pointFromP2(new(projP2).Zero())

	// Use the doubling method for the multiplication.
	// p := given point
	// q := point(zero)
	// for each bit in the scalar, descending:
	//   double(q)
	//   if bit == 1:
	//     add(q, p)
	// return q
	//
	// Note that the addition is skipped for zero bits,
	// making this variable time and thus vulnerable to
	// side channel attack vectors.
	for i := s.BitLen() - 1; i >= 0; i-- {
		p2 := new(projP2).FromP3(p)
		p1xp1 := new(projP1xP1).Double(p2)
		p = pointFromP1xP1(p1xp1)
		if s.Bit(i) == 1 {
			ss := new([32]byte)
			copy(ss[:], p.Bytes())
			var err error
			xi, yi, err := curve.encodedBytesToBigIntPoint(ss)
			if err != nil {
				return nil, nil
			}
			xAdd, yAdd := curve.Add(xi, yi, x1, y1)
			dTempBytes := bigIntPointToEncodedBytes(xAdd, yAdd)
			p, err = p.SetBytes(dTempBytes[:])
			if err != nil {
				return nil, nil
			}
		}
	}

	finalBytes := new([32]byte)
	copy(finalBytes[:], p.Bytes())
	var err error
	x, y, err = curve.encodedBytesToBigIntPoint(finalBytes)
	if err != nil {
		return nil, nil
	}

	return
}

// ScalarBaseMult returns k*G, where G is the base point of the group
// and k is an integer in big-endian form.
// TODO Optimize this with field elements
func (curve *TwistedEdwardsCurve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

// scalarAdd adds two scalars and returns the sum mod N.
func scalarAdd(a, b *big.Int) *big.Int {
	feA := bigIntToFieldElement(a)
	feB := bigIntToFieldElement(b)
	sum := new(field.Element)

	sum = sum.Add(feA, feB)
	sumArray := new([32]byte)
	sumB := sum.Bytes()
	copy(sumArray[:], sumB)
	return encodedBytesToBigInt(sumArray)
}

// initParam25519 initializes an instance of the Ed25519 curve.
func (curve *TwistedEdwardsCurve) initParam25519() {
	// The prime modulus of the field.
	// P = 2^255-19
	curve.CurveParams = new(elliptic.CurveParams)
	curve.P = new(big.Int)
	curve.P.SetBit(zero, 255, 1).Sub(curve.P, big.NewInt(19))

	// The prime order for the base point.
	// N = 2^252 + 27742317777372353535851937790883648493
	qs, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	curve.N = new(big.Int)
	curve.N.SetBit(zero, 252, 1).Add(curve.N, qs) // AKA Q

	curve.A = new(big.Int)
	curve.A.SetInt64(-1).Add(curve.P, curve.A)

	// d = -121665 * inv(121666)
	da := new(big.Int).SetInt64(-121665)
	ds := new(big.Int).SetInt64(121666)
	di := curve.invert(ds)
	curve.D = new(big.Int).Mul(da, di)

	// I = expmod(2,(q-1)/4,q)
	psn := new(big.Int)
	psn.SetBit(zero, 255, 1).Sub(psn, big.NewInt(19))
	psn.Sub(psn, one)
	psn.Div(psn, four)
	curve.I = psn.Exp(two, psn, curve.P)

	// The base point.
	curve.Gx = new(big.Int)
	curve.Gx.SetString("151122213495354007725011514095885315"+
		"11454012693041857206046113283949847762202", 10)
	curve.Gy = new(big.Int)
	curve.Gy.SetString("463168356949264781694283940034751631"+
		"41307993866256225615783033603165251855960", 10)

	curve.BitSize = 256
	curve.H = 8

	// Provided for convenience since this gets computed repeatedly.
	curve.byteSize = curve.BitSize / 8
}

// Edwards returns a Curve which implements Ed25519.
func Edwards() *TwistedEdwardsCurve {
	c := new(TwistedEdwardsCurve)
	c.initParam25519()
	return c
}
