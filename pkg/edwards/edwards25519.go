package edwards

import (
	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// Point types.

type projP1xP1 struct {
	X, Y, Z, T field.Element
}

type projP2 struct {
	X, Y, Z field.Element
}

func (v *projP2) Zero() *projP2 {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	return v
}

func (v *projP2) FromP3(p *edwards25519.Point) *projP2 {
	x, y, z, _ := p.ExtendedCoordinates()
	v.X.Set(x)
	v.Y.Set(y)
	v.Z.Set(z)
	return v
}

func (v *projP2) FromP1xP1(p *projP1xP1) *projP2 {
	v.X.Multiply(&p.X, &p.T)
	v.Y.Multiply(&p.Y, &p.Z)
	v.Z.Multiply(&p.Z, &p.T)
	return v
}

func (v *projP1xP1) Double(p *projP2) *projP1xP1 {
	var XX, YY, ZZ2, XplusYsq field.Element

	XX.Square(&p.X)
	YY.Square(&p.Y)
	ZZ2.Square(&p.Z)
	ZZ2.Add(&ZZ2, &ZZ2)
	XplusYsq.Add(&p.X, &p.Y)
	XplusYsq.Square(&XplusYsq)

	v.Y.Add(&YY, &XX)
	v.Z.Subtract(&YY, &XX)

	v.X.Subtract(&XplusYsq, &v.Y)
	v.T.Subtract(&ZZ2, &v.Z)
	return v
}

func pointFromP1xP1(p *projP1xP1) *edwards25519.Point {
	var x, y, z, t field.Element
	x.Multiply(&p.X, &p.T)
	y.Multiply(&p.Y, &p.Z)
	z.Multiply(&p.Z, &p.T)
	t.Multiply(&p.X, &p.Y)
	v, err := new(edwards25519.Point).SetExtendedCoordinates(&x, &y, &z, &t)
	if err != nil {
		return nil
	}
	return v
}

func pointFromP2(p *projP2) *edwards25519.Point {
	var x, y, z, t field.Element
	x.Multiply(&p.X, &p.Z)
	y.Multiply(&p.Y, &p.Z)
	z.Square(&p.Z)
	t.Multiply(&p.X, &p.Y)
	v, err := new(edwards25519.Point).SetExtendedCoordinates(&x, &y, &z, &t)
	if err != nil {
		return nil
	}
	return v
}
