package crypto

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
)

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

	pub1, err := DecompressPubKey(compressPub)
	if err != nil {
		t.Fatal(err)
	}
	if !pub1.Equal(pub) {
		t.Fatal("public key differ")
	}

	pub2str := "0x049f4db6ea8ea62401f76f018b959d267bfb285391130fc8520bacb6a029df643af196a29d5575" +
		"ca26cb965e73a4f4b022c7263edb22f2c96480ce0e89f7492b75"
	pubBytes2, _ := utils.Decode(pub2str)
	pub2, err := DecompressPubKey(pubBytes2)
	if err != nil {
		t.Fatal(err)
	}
	if !pub2.Equal(pub1) {
		t.Fatal("public key differ")
	}
}
