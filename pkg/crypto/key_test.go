package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"testing"
)

func TestParseECDSAPublicKey(t *testing.T) {
	x := new(big.Int)
	x, ok := x.SetString("9f4db6ea8ea62401f76f018b959d267bfb285391130fc8520bacb6a029df643a", 16)
	if !ok {
		t.Fatalf("x parse error")
	}
	y := new(big.Int)
	y, ok = y.SetString("f196a29d5575ca26cb965e73a4f4b022c7263edb22f2c96480ce0e89f7492b75", 16)
	if !ok {
		t.Fatalf("y parse error")
	}
	pub1 := "0x039f4db6ea8ea62401f76f018b959d267bfb285391130fc8520bacb6a029df643a"
	x1, y1, err := ParseECDSAPublicKey(pub1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("public key differ")
	}

	pub2 := "0x049f4db6ea8ea62401f76f018b959d267bfb285391130fc8520bacb6a029df643af196a29d5575" +
		"ca26cb965e73a4f4b022c7263edb22f2c96480ce0e89f7492b75"
	x2, y2, err := ParseECDSAPublicKey(pub2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x.Bytes(), x2.Bytes()) || !bytes.Equal(y.Bytes(), y2.Bytes()) {
		t.Fatal("public key differ")
	}
}

func TestCompressPublicKey(t *testing.T) {
	x := new(big.Int)
	x, ok := x.SetString("9f4db6ea8ea62401f76f018b959d267bfb285391130fc8520bacb6a029df643a", 16)
	if !ok {
		t.Fatalf("x parse error")
	}
	y := new(big.Int)
	y, ok = y.SetString("f196a29d5575ca26cb965e73a4f4b022c7263edb22f2c96480ce0e89f7492b75", 16)
	if !ok {
		t.Fatalf("y parse error")
	}
	pub := &ecdsa.PublicKey{
		Curve: S256(),
		X:     x,
		Y:     y,
	}
	compressPub := CompressPubKey(pub)
	if compressPub == nil {
		t.Fatalf("compress failed")
	}

	x1, y1 := DecompressPubKey(SECP256K1, compressPub)
	if !bytes.Equal(x.Bytes(), x1.Bytes()) || !bytes.Equal(y.Bytes(), y1.Bytes()) {
		t.Fatal("public key differ")
	}
}
