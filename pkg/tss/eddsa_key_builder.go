package tss

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type EDDSAKeyBuilder struct {
	curve elliptic.Curve
}

func NewEDDSAKeyBuilder(curve elliptic.Curve) *EDDSAKeyBuilder {
	return &EDDSAKeyBuilder{curve}
}

func (g *EDDSAKeyBuilder) VerifySharePublicKey(share []byte, sharePubKey string) error {
	d := new(big.Int).SetBytes(share)

	sharePubBytes, err := utils.Decode(sharePubKey)
	if err != nil {
		return fmt.Errorf("share public key decode error: %v", err)
	}

	sharePub, err := crypto.DecompressEDDSAPubKey(sharePubBytes)
	if err != nil {
		return fmt.Errorf("decompress public key error: %v", err)
	}
	prvKey, err := crypto.CreateEDDSAPrivateKey(d)
	if err != nil {
		return fmt.Errorf("create EDDSA private key error: %v", err)
	}
	log.Printf("Derived share public key: 0x%064x\n", prvKey.PubKey().Serialize())
	if !bytes.Equal(prvKey.PubKey().Serialize(), sharePub.Serialize()) {
		return fmt.Errorf("derived share public key differ, verify share info failed")
	}
	return nil
}

func (g *EDDSAKeyBuilder) ReconstructPublicKey(sharePubs SharePubs, threshold int, chainCode []byte) (crypto.CKDKey, error) {
	if threshold > len(sharePubs) {
		return nil, fmt.Errorf("number of SharePubs %v less than threshold %v", len(sharePubs), threshold)
	}
	pubKey, err := sharePubs.ReconstructKey(threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct root public key: %v", err)
	}
	extPubKey := crypto.CreateEDDSAExtendedPublicKey(crypto.ConvertECDSAPubkeyToEDDSA(pubKey), chainCode)
	return extPubKey, nil
}

func (g *EDDSAKeyBuilder) BuildSharePub(p Participant) (*SharePub, error) {
	var ok bool
	var sharePub *ecdsa.PublicKey

	sharePubBytes, err := utils.Decode(p.SharePubKey)
	if err != nil {
		return nil, fmt.Errorf("share public key decode error: %v", err)
	}

	pub, err := crypto.DecompressEDDSAPubKey(sharePubBytes)
	if err != nil {
		return nil, fmt.Errorf("decompress public key error: %v", err)
	}
	sharePub = pub.ToECDSA()

	shareID := new(big.Int)
	shareID, ok = shareID.SetString(p.ShareID, 10)
	if !ok {
		return nil, fmt.Errorf("share ID parse error")
	}
	public := &SharePub{
		ID:       shareID,
		SharePub: sharePub,
	}
	return public, nil
}

func (g *EDDSAKeyBuilder) ReconstructPrivateKey(shares Shares, threshold int, chainCode []byte) (crypto.CKDKey, error) {
	if threshold > len(shares) {
		return nil, fmt.Errorf("number of Shares %v less than threshold %v", len(shares), threshold)
	}
	secret, err := shares.reconstruct(g.curve)
	if err != nil {
		return nil, fmt.Errorf("TSS recovery group failed to reconstruct shares: %v", err)
	}
	privateKey, err := crypto.CreateEDDSAPrivateKey(secret)
	if err != nil {
		return nil, fmt.Errorf("TSS recovery group failed to reconstruct root private key: %v", err)
	}

	extPrivateKey := crypto.CreateEDDSAExtendedPrivateKey(privateKey, chainCode)
	return extPrivateKey, nil
}
