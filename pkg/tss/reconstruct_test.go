package tss

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
)

func TestReconstructPrivateKey(t *testing.T) {
	shares := make(Shares, 0)
	id1 := new(big.Int)
	id1, ok := id1.SetString("c5218a708d35aa726bc5c4cf3712a2036c2245a0e996d201e4e661ab598bdf36", 16)
	if !ok {
		t.Fatalf("id1 parse error")
	}
	xi1 := new(big.Int)
	xi1, ok = xi1.SetString("2e67c995c3b8aa49d02ffe13ad32926253f4b9b0e1bca458eccf82ba69dd9029", 16)
	if !ok {
		t.Fatalf("xi1 parse error")
	}
	id2 := new(big.Int)
	id2, ok = id2.SetString("c5218a708d35aa726bc5c4cf3712a2036c2245a0e996d201e4e661ab598bdf37", 16)
	if !ok {
		t.Fatalf("id2 parse error")
	}
	xi2 := new(big.Int)
	xi2, ok = xi2.SetString("c15f0e0d4689a34c6a36859fc2cda818265da481f2ba592fd506991300541577", 16)
	if !ok {
		t.Fatalf("xi2 parse error")
	}
	d := new(big.Int)
	d, ok = d.SetString("ca82cd1cee09478cfd275fd427b5abacdfe9a0f7c6c4c96edf003d3b42ff027f", 16)
	if !ok {
		t.Fatalf("d parse error")
	}

	share1 := &Share{
		Xi: xi1,
		ID: id1,
	}
	share2 := &Share{
		Xi: xi2,
		ID: id2,
	}
	shares = append(shares, share1)
	shares = append(shares, share2)
	private, err := shares.reconstruct(crypto.S256())
	if err != nil {
		t.Fatalf("reconstructKey failed: %v", err)
	}
	if !bytes.Equal(private.Bytes(), d.Bytes()) {
		t.Fatalf("private error")
	}
}

func TestReconstructPublicKey(t *testing.T) {
	sharePubs := make(SharePubs, 0)
	id1 := new(big.Int)
	id1, ok := id1.SetString("c5218a708d35aa726bc5c4cf3712a2036c2245a0e996d201e4e661ab598bdf36", 16)
	if !ok {
		t.Fatalf("id1 parse error")
	}
	x1 := new(big.Int)
	x1, ok = x1.SetString("9f4db6ea8ea62401f76f018b959d267bfb285391130fc8520bacb6a029df643a", 16)
	if !ok {
		t.Fatalf("x1 parse error")
	}
	y1 := new(big.Int)
	y1, ok = y1.SetString("f196a29d5575ca26cb965e73a4f4b022c7263edb22f2c96480ce0e89f7492b75", 16)
	if !ok {
		t.Fatalf("y1 parse error")
	}
	pub1 := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x1,
		Y:     y1,
	}

	id2 := new(big.Int)
	id2, ok = id2.SetString("c5218a708d35aa726bc5c4cf3712a2036c2245a0e996d201e4e661ab598bdf37", 16)
	if !ok {
		t.Fatalf("id2 parse error")
	}
	x2 := new(big.Int)
	x2, ok = x2.SetString("4076b3088b29f133e38316d7da14978e06828a0e7121436ac4db88c7011a705a", 16)
	if !ok {
		t.Fatalf("x2 parse error")
	}
	y2 := new(big.Int)
	y2, ok = y2.SetString("b48c83cadf366d7cd912609d6e1292d168c7878a71a042bb295e0679625973b5", 16)
	if !ok {
		t.Fatalf("y2 parse error")
	}
	pub2 := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x2,
		Y:     y2,
	}

	x := new(big.Int)
	x, ok = x.SetString("cd8f9e866bf71c80106079ae374c8187e88a94cc7f9ea56b6c7fffc83633c7d2", 16)
	if !ok {
		t.Fatalf("x parse error")
	}
	y := new(big.Int)
	y, ok = y.SetString("d1b5099477e9276b0822836b2ea5868f7abf8f0bc4b49bc6a1fe0101d9ca1eaa", 16)
	if !ok {
		t.Fatalf("y parse error")
	}

	sharePub1 := &SharePub{
		ID:       id1,
		SharePub: pub1,
	}
	sharePub2 := &SharePub{
		ID:       id2,
		SharePub: pub2,
	}
	sharePubs = append(sharePubs, sharePub1)
	sharePubs = append(sharePubs, sharePub2)
	public, err := sharePubs.ReconstructKey(2)
	if err != nil {
		t.Fatalf("reconstructKey failed: %v", err)
	}
	if !bytes.Equal(public.X.Bytes(), x.Bytes()) {
		t.Fatalf("public x error")
	}
	if !bytes.Equal(public.Y.Bytes(), y.Bytes()) {
		t.Fatalf("public x error")
	}
}
