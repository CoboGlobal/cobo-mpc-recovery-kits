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
	"github.com/tyler-smith/go-bip32"
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

func (p Participant) GenerateECDSASharePub() (*ECDSASharePub, error) {
	curve := crypto.S256()
	var ok bool
	x, y, err := crypto.ParseECDSAPublicKey(p.SharePubKey)
	if err != nil {
		return nil, fmt.Errorf("parse ecdsa public key error: %v", err)
	}
	sharePub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if !sharePub.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point not on the curve")
	}

	shareID := new(big.Int)
	shareID, ok = shareID.SetString(p.ShareID, 10)
	if !ok {
		return nil, fmt.Errorf("share ID parse error")
	}
	public := &ECDSASharePub{
		ID:       shareID,
		SharePub: sharePub,
	}
	return public, nil
}

func (s *ShareInfo) GenerateECDSAShare(key string) (*ECDSAShare, error) {
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

	secret := &ECDSAShare{
		Xi: share,
		ID: shareID,
	}
	return secret, nil
}

//nolint:cyclop
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

	if curveType == crypto.SECP256K1 {
		x, y, err := crypto.ParseECDSAPublicKey(s.SharePubKey)
		if err != nil {
			return fmt.Errorf("parse ecdsa public key error: %v", err)
		}
		d := new(big.Int).SetBytes(shareBytes)
		prvKey := crypto.CreateECDSAPrivateKey(crypto.S256(), d)

		log.Printf("Derived share public key: 0x04%x%x\n", prvKey.PublicKey.X.Bytes(), prvKey.PublicKey.Y.Bytes())
		if !bytes.Equal(prvKey.PublicKey.X.Bytes(), x.Bytes()) || !bytes.Equal(prvKey.PublicKey.Y.Bytes(), y.Bytes()) {
			return fmt.Errorf("share public key differ, verify share info failed")
		}
	} else if curveType == crypto.ED25519 {
		return fmt.Errorf("not support curve type ed25519 now")
	} else {
		return fmt.Errorf("not support curve type: %v", curveType)
	}
	return nil
}

func (parts ParticipantsInfo) ReconstructECDSAPubKey(threshold int) (*ecdsa.PublicKey, error) {
	sharePubs := make(ECDSASharePubs, 0)
	for _, p := range parts {
		sharePub, err := p.GenerateECDSASharePub()
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

func (g *GroupInfo) VerifyReconstructPubKey() error {
	if g == nil {
		return fmt.Errorf("input error")
	}
	threshold := int(g.Threshold)
	parts := g.Participants
	if threshold > len(parts) {
		return fmt.Errorf("number of participants %v parse from files less than threshold %v", len(parts), threshold)
	}
	chainCode, err := utils.Decode(g.ChainCode)
	if err != nil {
		return fmt.Errorf("failed to parse chaincode: %v", err)
	}
	// selectParts := make(ParticipantsInfo, 0)
	selectParts := parts // TODO

	curveType := crypto.CurveNameType[g.Curve]
	if curveType == crypto.SECP256K1 {
		pub, err := selectParts.ReconstructECDSAPubKey(threshold)
		if err != nil {
			return fmt.Errorf("reconstruct ECDSA public Key error: %v", err)
		}
		extPubKey := &bip32.Key{
			Version:     bip32.PublicWalletVersion,
			ChainCode:   chainCode,
			Key:         crypto.CompressPubKey(pub),
			Depth:       0x0,
			ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
			FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
			IsPrivate:   false,
		}
		log.Println("Reconstruct root extended public key:", extPubKey.PublicKey().String())

		if g.RootExtendedPubKey != extPubKey.PublicKey().String() {
			return fmt.Errorf("reconstruct root public key differ, verify root public key failed")
		}
	} else if curveType == crypto.ED25519 {
		return fmt.Errorf("not support curve type ed25519 now")
	} else {
		return fmt.Errorf("not support curve type: %v", curveType)
	}
	return nil
}
