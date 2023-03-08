package tss

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type Group struct {
	Version   int32      `json:"version"`
	GroupInfo *GroupInfo `json:"group_info"`
	ShareInfo *ShareInfo `json:"share_info"`
}

type GroupInfo struct {
	ID                 string           `json:"id"`
	CreatedTime        string           `json:"created_time"`
	Type               int32            `json:"type"`
	RootExtendedPubKey string           `json:"root_extended_public_key"`
	ChainCode          string           `json:"chaincode"`
	Curve              string           `json:"curve"`
	Threshold          int32            `json:"threshold"`
	Participants       ParticipantsInfo `json:"participants"`
}

type Participant struct {
	NodeID      string `json:"node_id"`
	ShareID     string `json:"share_id"`
	SharePubKey string `json:"share_public_key"`
}

type ParticipantsInfo []Participant

type ShareInfo struct {
	NodeID         string      `json:"node_id"`
	ShareID        string      `json:"share_id"`
	SharePubKey    string      `json:"share_public_key"`
	EncryptedShare []byte      `json:"encrypted_share"`
	KDF            *cipher.KDF `json:"kdf"`
}

func (s *ShareInfo) GenerateShare(key string) (*Share, error) {
	if s == nil || key == "" {
		return nil, fmt.Errorf("input error")
	}
	if s.KDF == nil {
		return nil, fmt.Errorf("encrypted share KDF nil")
	}

	aesGCM, err := cipher.NewAES256GCMWithPassPhrase(key, s.KDF)
	if err != nil {
		return nil, err
	}
	shareBytes, err := aesGCM.Decrypt(s.EncryptedShare)
	if err != nil {
		return nil, fmt.Errorf("AES GCM decrypt error: %v", err)
	}

	shareID := new(big.Int)
	shareID, ok := shareID.SetString(s.ShareID, 10)
	if !ok {
		return nil, fmt.Errorf("share ID parse error")
	}
	share := new(big.Int)
	share = share.SetBytes(shareBytes)

	secret := &Share{
		Xi: share,
		ID: shareID,
	}
	return secret, nil
}

func (p Participant) GenerateSharePub(curveType crypto.CurveType) (*SharePub, error) {
	var ok bool
	var sharePub *ecdsa.PublicKey

	sharePubBytes, err := utils.Decode(p.SharePubKey)
	if err != nil {
		return nil, fmt.Errorf("share public key decode error: %v", err)
	}

	switch curveType {
	case crypto.SECP256K1:
		sharePub, err = crypto.DecompressECDSAPubKey(sharePubBytes)
		if err != nil {
			return nil, fmt.Errorf("decompress public key error: %v", err)
		}

	case crypto.ED25519:
		pub, err := crypto.DecompressEDDSAPubKey(sharePubBytes)
		if err != nil {
			return nil, fmt.Errorf("decompress public key error: %v", err)
		}
		sharePub = pub.ToECDSA()
	default:
		return nil, fmt.Errorf("not supported curve type: %v", curveType)
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

func (parts ParticipantsInfo) ReconstructPublicKey(curveType crypto.CurveType, threshold int) (*ecdsa.PublicKey, error) {
	sharePubs := make(SharePubs, 0)
	for _, p := range parts {
		sharePub, err := p.GenerateSharePub(curveType)
		if err != nil {
			return nil, fmt.Errorf("generate share public error: %v", err)
		}
		sharePubs = append(sharePubs, sharePub)
	}
	if threshold > len(sharePubs) {
		return nil, fmt.Errorf("number of participants %v parse from files less than threshold %v", len(sharePubs), threshold)
	}
	pubKey, err := sharePubs.ReconstructKey(threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct root public key: %v", err)
	}
	return pubKey, nil
}

func (s *ShareInfo) VerifySharePublicKey(curveType crypto.CurveType, key string) error {
	if s == nil || key == "" {
		return fmt.Errorf("input error")
	}
	if s.KDF == nil {
		return fmt.Errorf("encrypted share KDF nil")
	}

	aesGCM, err := cipher.NewAES256GCMWithPassPhrase(key, s.KDF)
	if err != nil {
		return err
	}
	shareBytes, err := aesGCM.Decrypt(s.EncryptedShare)
	if err != nil {
		return fmt.Errorf("AES GCM decrypt error: %v", err)
	}
	d := new(big.Int).SetBytes(shareBytes)

	sharePubBytes, err := utils.Decode(s.SharePubKey)
	if err != nil {
		return fmt.Errorf("share public key decode error: %v", err)
	}

	switch curveType {
	case crypto.SECP256K1:
		sharePub, err := crypto.DecompressECDSAPubKey(sharePubBytes)
		if err != nil {
			return fmt.Errorf("decompress public key error: %v", err)
		}
		prvKey := crypto.CreateECDSAPrivateKey(crypto.S256(), d)
		log.Printf("Derived share public key: 0x04%064x%064x\n", prvKey.PublicKey.X.Bytes(), prvKey.PublicKey.Y.Bytes())
		if !prvKey.PublicKey.Equal(sharePub) {
			return fmt.Errorf("derived share public key differ, verify share info failed")
		}
	case crypto.ED25519:
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
	default:
		return fmt.Errorf("not supported curve type: %v", curveType)
	}
	return nil
}

func (g *GroupInfo) VerifyReconstructPublicKey() error {
	if g == nil {
		return fmt.Errorf("input error")
	}
	threshold := int(g.Threshold)
	parts := g.Participants
	if threshold < 1 || len(parts) == 0 {
		return fmt.Errorf("number of participants or threshold error")
	}
	if threshold > len(parts) {
		return fmt.Errorf("number of participants %v parse from files less than threshold %v", len(parts), threshold)
	}
	chainCode, err := utils.Decode(g.ChainCode)
	if err != nil {
		return fmt.Errorf("failed to parse chaincode: %v", err)
	}
	curveType := crypto.CurveNameType[g.Curve]
	fixedParts := make(ParticipantsInfo, 0)
	fixedIndexes := make([]int, 0)
	for i := 0; i < threshold-1; i++ {
		fixedParts = append(fixedParts, parts[i])
		fixedIndexes = append(fixedIndexes, i)
	}
	for i := threshold - 1; i < len(parts); i++ {
		selectParts := fixedParts
		selectParts = append(selectParts, parts[i])
		selectIndexes := fixedIndexes
		selectIndexes = append(selectIndexes, i)

		indexesStr := ""
		for _, index := range selectIndexes {
			indexesStr = indexesStr + fmt.Sprintf("(no.%v) ", index+1)
		}
		log.Printf("Use participants %v to reconstruct root extended public key ...", indexesStr)
		pub, err := selectParts.ReconstructPublicKey(curveType, threshold)
		if err != nil {
			return fmt.Errorf("reconstruct public key error: %v", err)
		}

		// create extended public key
		switch curveType {
		case crypto.SECP256K1:
			extPubKey := crypto.CreateECDSAExtendedPublicKey(pub, chainCode)
			log.Println("Reconstructed root extended public key:", extPubKey.String())
			if g.RootExtendedPubKey != extPubKey.String() {
				return fmt.Errorf("reconstructed root public key differ, verify root public key failed")
			}
		case crypto.ED25519:
			extPubKey := crypto.CreateEDDSAExtendedPublicKey(crypto.CreateEDDSAPubKey(pub), chainCode)
			log.Println("Reconstructed root extended public key:", extPubKey.String())
			if g.RootExtendedPubKey != extPubKey.String() {
				return fmt.Errorf("reconstructed root public key differ, verify root public key failed")
			}
		default:
			return fmt.Errorf("not support curve type: %v", curveType)
		}
		if err != nil {
			return fmt.Errorf("create extended public key error: %v", err)
		}
	}
	return nil
}

func (g *GroupInfo) VerifyReconstructPrivateKey(shares Shares, isShowPrivate bool) error {
	curveType := crypto.CurveNameType[g.Curve]
	threshold := int(g.Threshold)
	chainCode, err := utils.Decode(g.ChainCode)
	if err != nil {
		return fmt.Errorf("TSS group recovery failed to parse chaincode: %v", err)
	}

	switch curveType {
	case crypto.SECP256K1:
		privateKey, err := shares.ReconstructECDSAKey(threshold, crypto.S256())
		if err != nil {
			return fmt.Errorf("TSS group recovery failed to reconstruct root private key: %v", err)
		}
		extPrivateKey := crypto.CreateECDSAExtendedPrivateKey(privateKey, chainCode)
		if isShowPrivate {
			log.Println("Reconstructed root private key:", utils.Encode(privateKey.D.Bytes()))
			log.Println("Reconstructed root extended private key:", extPrivateKey.String())
		}
		log.Println("Reconstructed root extended public key:", extPrivateKey.PublicKey().String())
		if g.RootExtendedPubKey != extPrivateKey.PublicKey().String() {
			return fmt.Errorf("reconstructed root extended public key mismatch")
		}
	case crypto.ED25519:
		privateKey, err := shares.ReconstructEDDSAKey(threshold, crypto.Edwards())
		if err != nil {
			log.Fatalf("TSS group recovery failed to reconstruct root private key: %v", err)
		}
		extPrivateKey := crypto.CreateEDDSAExtendedPrivateKey(privateKey, chainCode)
		if isShowPrivate {
			log.Println("Reconstructed root private key:", utils.Encode(privateKey.GetD().Bytes()))
			log.Println("Reconstructed root extended private key:", extPrivateKey.String())
		}
		log.Println("Reconstructed root extended public key:", extPrivateKey.PublicKey().String())
		if g.RootExtendedPubKey != extPrivateKey.PublicKey().String() {
			return fmt.Errorf("reconstructed root extended public key mismatch")
		}
	default:
		return fmt.Errorf("not supported curve type: %v", curveType)
	}

	return nil
}
