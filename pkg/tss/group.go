package tss

import (
	"fmt"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
)

const (
	GroupVersionV1 = 1
	GroupVersionV2 = 2
	GroupVersionV3 = 3
)

const (
	GroupTypeEcdsaTSS int32 = 1
	GroupTypeEddsaTSS int32 = 2
)

type GroupKeyBuilder interface {
	VerifySharePublicKey(share []byte, sharePubKey string) error
	ReconstructPublicKey(sharePubs SharePubs, threshold int, chainCode []byte) (crypto.CKDKey, error)
	BuildSharePub(p Participant) (*SharePub, error)
	ReconstructPrivateKey(shares Shares, threshold int, chainCode []byte) (crypto.CKDKey, error)
}

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

type EncryptedPartyInfo struct {
	Share []byte `json:"encrypted_share"`
}

func NewGroupKeyBuilder(curveType crypto.CurveType) (GroupKeyBuilder, error) {
	switch curveType {
	case crypto.SECP256K1:
		return NewECDSAKeyBuilder(crypto.S256()), nil
	case crypto.ED25519:
		return NewEDDSAKeyBuilder(crypto.Edwards()), nil

	default:
		return nil, fmt.Errorf("not supported curve type: %v", curveType)
	}
}

func (g *Group) CheckGroupParams() error {
	if g == nil || g.GroupInfo == nil || g.ShareInfo == nil {
		return fmt.Errorf("group param empty")
	}
	if g.GroupInfo.ID == "" {
		return fmt.Errorf("group id mismatch")
	}
	if g.GroupInfo.Type != GroupTypeEcdsaTSS && g.GroupInfo.Type != GroupTypeEddsaTSS {
		return fmt.Errorf("group param type not supported")
	}
	if g.GroupInfo.RootExtendedPubKey == "" {
		return fmt.Errorf("group param root extended public key empty")
	}
	if g.GroupInfo.ChainCode == "" {
		return fmt.Errorf("group param chaincode empty")
	}
	if crypto.CurveNameType[g.GroupInfo.Curve] != crypto.SECP256K1 &&
		crypto.CurveNameType[g.GroupInfo.Curve] != crypto.ED25519 {
		return fmt.Errorf("group param curve not supported")
	}
	if g.GroupInfo.Threshold < 1 {
		return fmt.Errorf("group param threshold not supported")
	}
	if g.GroupInfo.Threshold > int32(len(g.GroupInfo.Participants)) {
		return fmt.Errorf("group param participants less than threshold")
	}

	if g.ShareInfo.NodeID == "" {
		return fmt.Errorf("group param node id empty")
	}
	if g.ShareInfo.ShareID == "" {
		return fmt.Errorf("group param share ID empty")
	}
	if g.ShareInfo.SharePubKey == "" {
		return fmt.Errorf("group param share public key empty")
	}
	if g.ShareInfo.EncryptedShare == nil {
		return fmt.Errorf("group param encrypted share empty")
	}
	if g.ShareInfo.KDF == nil {
		return fmt.Errorf("group param encrypt KDF empty")
	}
	return g.checkGroupParticipants()
}

//nolint:gocognit
func (g *Group) checkGroupParticipants() error {
	parts := g.GroupInfo.Participants
	if int(g.GroupInfo.Threshold) > len(parts) {
		return fmt.Errorf("number of participants %v parse from files less than threshold %v",
			len(g.GroupInfo.Participants), int(g.GroupInfo.Threshold))
	}
	foundSharePart := false
	for i, part := range parts {
		if part.NodeID == "" {
			return fmt.Errorf("participant (no.%v) node id nil", i+1)
		}
		if part.ShareID == "" {
			return fmt.Errorf("participant (no.%v) share ID nil", i+1)
		}
		if part.SharePubKey == "" {
			return fmt.Errorf("participant (no.%v) share public key nil", i+1)
		}
		for j := 0; j < len(parts); j++ {
			if i == j {
				continue
			}
			if part.NodeID == parts[j].NodeID {
				return fmt.Errorf("participants (no.%v) and (no.%v) node ids should be different", i+1, j+1)
			}
			if part.ShareID == parts[j].ShareID {
				return fmt.Errorf("participants (no.%v) and (no.%v) share ids should be different", i+1, j+1)
			}
			if part.SharePubKey == parts[j].SharePubKey {
				return fmt.Errorf("participants (no.%v) and (no.%v) share public keys should be different", i+1, j+1)
			}
		}
		if part.NodeID == g.ShareInfo.NodeID {
			if part.ShareID != g.ShareInfo.ShareID {
				return fmt.Errorf("participant (no.%v) mismatch with share id in share info", i+1)
			}
			if part.SharePubKey != g.ShareInfo.SharePubKey {
				return fmt.Errorf("participant (no.%v) mismatch with share public key in share info", i+1)
			}
			foundSharePart = true
		}
	}
	if !foundSharePart {
		return fmt.Errorf("cannot found share info in participants")
	}
	return nil
}

func (g *Group) CheckWithGroup(group *Group) error {
	if g.GroupInfo.ID != group.GroupInfo.ID {
		return fmt.Errorf("group ids mismatch")
	}
	if g.GroupInfo.Type != group.GroupInfo.Type {
		return fmt.Errorf("group types mismatch")
	}
	if g.GroupInfo.RootExtendedPubKey != group.GroupInfo.RootExtendedPubKey {
		return fmt.Errorf("group root extended public keys mismatch")
	}
	if g.GroupInfo.ChainCode != group.GroupInfo.ChainCode {
		return fmt.Errorf("group chaincodes mismatch")
	}
	if g.GroupInfo.Curve != group.GroupInfo.Curve {
		return fmt.Errorf("group curves mismatch")
	}
	if g.GroupInfo.Threshold != group.GroupInfo.Threshold {
		return fmt.Errorf("group thresholds mismatch")
	}
	if g.ShareInfo.NodeID == group.ShareInfo.NodeID {
		return fmt.Errorf("node ids should be different")
	}
	if g.ShareInfo.ShareID == group.ShareInfo.ShareID {
		return fmt.Errorf("share ids should be different")
	}
	if g.ShareInfo.SharePubKey == group.ShareInfo.SharePubKey {
		return fmt.Errorf("share public keys should be different")
	}
	return g.checkWithGroupParticipants(group)
}

func (g *Group) checkWithGroupParticipants(group *Group) error {
	parts1 := g.GroupInfo.Participants
	parts2 := group.GroupInfo.Participants
	if len(parts1) != len(parts2) {
		return fmt.Errorf("participants length mismatch")
	}
	for _, part1 := range parts1 {
		foundSamePart := false
		for _, part2 := range parts2 {
			if part1 == part2 {
				foundSamePart = true
			}
		}
		if !foundSamePart {
			return fmt.Errorf("participant (node id: %v) cannot found in other participants", part1.NodeID)
		}
	}
	for _, part2 := range parts2 {
		foundSamePart := false
		for _, part1 := range parts1 {
			if part2 == part1 {
				foundSamePart = true
			}
		}
		if !foundSamePart {
			return fmt.Errorf("participant (node id: %v) cannot found in other participants", part2.NodeID)
		}
	}
	return nil
}

func (g *Group) VerifyRootPublicKey() error {
	if g.GroupInfo == nil {
		return fmt.Errorf("group info is empty")
	}
	builder, err := NewGroupKeyBuilder(crypto.CurveNameType[g.GroupInfo.Curve])
	if err != nil {
		return err
	}
	return g.GroupInfo.verifyRootPublicKey(builder)
}

func (g *Group) VerifySharePublicKey(keys ...string) error {
	if g.ShareInfo == nil {
		return fmt.Errorf("group share info is empty")
	}
	var share []byte
	var err error
	if g.Version >= GroupVersionV2 {
		share, err = g.ShareInfo.decryptShareV2(keys...)
	} else {
		share, err = g.ShareInfo.decryptShare(keys...)
	}
	if err != nil {
		return err
	}
	builder, err := NewGroupKeyBuilder(crypto.CurveNameType[g.GroupInfo.Curve])
	if err != nil {
		return err
	}

	return builder.VerifySharePublicKey(share, g.ShareInfo.SharePubKey)
}

func (g *Group) DecryptShare(keys ...string) (*Share, error) {
	if g.ShareInfo == nil {
		return nil, fmt.Errorf("group share info is empty")
	}
	var share []byte
	var err error
	if g.Version >= GroupVersionV2 {
		share, err = g.ShareInfo.decryptShareV2(keys...)
	} else {
		share, err = g.ShareInfo.decryptShare(keys...)
	}
	if err != nil {
		return nil, err
	}
	return buildShare(share, g.ShareInfo.ShareID)
}

func (g *Group) VerifyRootPrivateKey(shares Shares) error {
	if g.GroupInfo == nil {
		return fmt.Errorf("group info is empty")
	}
	builder, err := NewGroupKeyBuilder(crypto.CurveNameType[g.GroupInfo.Curve])
	if err != nil {
		return err
	}
	_, err = g.GroupInfo.reconstructRootPrivateKey(builder, shares)
	return err
}

func (g *Group) ReconstructRootPrivateKey(shares Shares) (crypto.CKDKey, error) {
	if g.GroupInfo == nil {
		return nil, fmt.Errorf("group info is empty")
	}
	builder, err := NewGroupKeyBuilder(crypto.CurveNameType[g.GroupInfo.Curve])
	if err != nil {
		return nil, err
	}
	return g.GroupInfo.reconstructRootPrivateKey(builder, shares)
}
