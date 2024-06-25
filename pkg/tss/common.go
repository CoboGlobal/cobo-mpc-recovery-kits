package tss

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/utils"
	log "github.com/sirupsen/logrus"
)

func (s *ShareInfo) decryptShare(keys ...string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("share info is empty")
	}
	if len(keys) == 0 {
		if s.KDF != nil {
			return nil, fmt.Errorf("must need a decrypt key")
		}
		return s.EncryptedShare, nil
	}

	if s.KDF == nil {
		return nil, fmt.Errorf("encrypted share KDF nil")
	}
	key := keys[0]
	aesGCM, err := cipher.NewAES256GCMWithPassPhrase(key, s.KDF)
	if err != nil {
		return nil, err
	}
	return aesGCM.Decrypt(s.EncryptedShare)
}

func (s *ShareInfo) decryptShareV2(keys ...string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("share info is empty")
	}
	if len(keys) == 0 {
		if s.KDF != nil {
			return nil, fmt.Errorf("must need a decrypt key")
		}
		ePartyInfo := &EncryptedPartyInfo{}
		if err := json.Unmarshal(s.EncryptedShare, ePartyInfo); err != nil {
			return nil, err
		}
		return ePartyInfo.Share, nil
	}

	if s.KDF == nil {
		return nil, fmt.Errorf("encrypted share KDF nil")
	}
	key := keys[0]
	aesGCM, err := cipher.NewAES256GCMWithPassPhrase(key, s.KDF)
	if err != nil {
		return nil, err
	}
	shareBytes, err := aesGCM.Decrypt(s.EncryptedShare)
	if err != nil {
		return nil, fmt.Errorf("AES GCM decrypt error: %v", err)
	}
	ePartyInfo := &EncryptedPartyInfo{}
	if err := json.Unmarshal(shareBytes, ePartyInfo); err != nil {
		return nil, err
	}
	return ePartyInfo.Share, nil
}

func (g *GroupInfo) verifyRootPublicKey(builder GroupKeyBuilder) error {
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

		sharePubs := make(SharePubs, 0)
		for _, p := range selectParts {
			sharePub, err := builder.BuildSharePub(p)
			if err != nil {
				return fmt.Errorf("generate share public error: %v", err)
			}
			sharePubs = append(sharePubs, sharePub)
		}

		key, err := builder.ReconstructPublicKey(sharePubs, threshold, chainCode)
		if err != nil {
			return fmt.Errorf("reconstruct public key error: %v", err)
		}
		log.Println("Reconstructed root extended public key:", key.PublicKey().String())
		if g.RootExtendedPubKey != key.PublicKey().String() {
			return fmt.Errorf("reconstructed root public key differ, verify root public key failed")
		}
	}
	return nil
}

func (g *GroupInfo) reconstructRootPrivateKey(builder GroupKeyBuilder, shares Shares) (crypto.CKDKey, error) {
	threshold := int(g.Threshold)
	chainCode, err := utils.Decode(g.ChainCode)
	if err != nil {
		return nil, fmt.Errorf("TSS recovery group failed to parse chaincode: %v", err)
	}

	key, err := builder.ReconstructPrivateKey(shares, threshold, chainCode)
	if err != nil {
		return nil, fmt.Errorf("reconstruct private key error: %v", err)
	}
	if g.RootExtendedPubKey != key.PublicKey().String() {
		return nil, fmt.Errorf("reconstructed root extended public key mismatch")
	}
	return key, nil
}

func buildShare(share []byte, shareID string) (*Share, error) {
	id := new(big.Int)
	id, ok := id.SetString(shareID, 10)
	if !ok {
		return nil, fmt.Errorf("share ID parse error")
	}
	xi := new(big.Int)
	xi = xi.SetBytes(share)

	secret := &Share{
		Xi: xi,
		ID: id,
	}
	return secret, nil
}
