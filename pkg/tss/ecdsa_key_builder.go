package tss

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type ECDSAKeyBuilder struct {
	curve elliptic.Curve
}

func NewECDSAKeyBuilder(curve elliptic.Curve) *ECDSAKeyBuilder {
	return &ECDSAKeyBuilder{curve}
}

func (g *ECDSAKeyBuilder) VerifySharePublicKey(share []byte, sharePubKey string) error {
	d := new(big.Int).SetBytes(share)

	sharePubBytes, err := utils.Decode(sharePubKey)
	if err != nil {
		return fmt.Errorf("share public key decode error: %v", err)
	}

	sharePub, err := crypto.DecompressECDSAPubKey(sharePubBytes)
	if err != nil {
		return fmt.Errorf("decompress public key error: %v", err)
	}
	prvKey := crypto.CreateECDSAPrivateKey(g.curve, d)
	log.Printf("Derived share public key: 0x04%064x%064x\n", prvKey.PublicKey.X.Bytes(), prvKey.PublicKey.Y.Bytes())
	if !prvKey.PublicKey.Equal(sharePub) {
		return fmt.Errorf("derived share public key differ, verify share info failed")
	}
	return nil
}

func (g *ECDSAKeyBuilder) ReconstructPublicKey(sharePubs SharePubs, threshold int, chainCode []byte) (crypto.CKDKey, error) {
	if threshold > len(sharePubs) {
		return nil, fmt.Errorf("number of SharePubs %v less than threshold %v", len(sharePubs), threshold)
	}
	pubKey, err := sharePubs.ReconstructKey(threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct root public key: %v", err)
	}
	extPubKey := crypto.CreateECDSAExtendedPublicKey(pubKey, chainCode)
	return crypto.NewECDSAExtendedKey(extPubKey), nil
}

func (g *ECDSAKeyBuilder) BuildSharePub(p Participant) (*SharePub, error) {
	var ok bool
	var sharePub *ecdsa.PublicKey

	sharePubBytes, err := utils.Decode(p.SharePubKey)
	if err != nil {
		return nil, fmt.Errorf("share public key decode error: %v", err)
	}

	sharePub, err = crypto.DecompressECDSAPubKey(sharePubBytes)
	if err != nil {
		return nil, fmt.Errorf("decompress public key error: %v", err)
	}

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

func (g *ECDSAKeyBuilder) ReconstructPrivateKey(shares Shares, threshold int, chainCode []byte) (crypto.CKDKey, error) {
	if threshold > len(shares) {
		return nil, fmt.Errorf("number of Shares %v less than threshold %v", len(shares), threshold)
	}

	secret, err := shares.reconstruct(g.curve)
	if err != nil {
		return nil, fmt.Errorf("TSS recovery group failed to reconstruct shares: %v", err)
	}

	privateKey, err := crypto.CreateECDSAPrivateKey(g.curve, secret), nil
	if err != nil {
		return nil, fmt.Errorf("TSS recovery group failed to reconstruct root private key: %v", err)
	}
	extPrivateKey := crypto.CreateECDSAExtendedPrivateKey(privateKey, chainCode)
	return crypto.NewECDSAExtendedKey(extPrivateKey), nil
}
