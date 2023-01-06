package cmd

import (
	"fmt"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/tss"
)

func checkFlags() error {
	if len(Paths) > 0 && Csv != "" {
		return fmt.Errorf("flags 'paths' and 'csv' at same time is not allowed")
	}

	return nil
}

//nolint:cyclop
func checkGroupParam(groupID string, group *tss.Group) error {
	if groupID == "" || group == nil || group.GroupInfo == nil || group.ShareInfo == nil {
		return fmt.Errorf("group param nil")
	}
	if groupID != group.GroupInfo.ID {
		return fmt.Errorf("group id mismatch")
	}
	if group.GroupInfo.Type != 1 {
		return fmt.Errorf("group param type not supported")
	}
	if group.GroupInfo.RootExtendedPubKey == "" {
		return fmt.Errorf("group param root extended public key nil")
	}
	if group.GroupInfo.ChainCode == "" {
		return fmt.Errorf("group param root extended public key nil")
	}
	if crypto.CurveNameType[group.GroupInfo.Curve] != crypto.SECP256K1 &&
		crypto.CurveNameType[group.GroupInfo.Curve] != crypto.ED25519 {
		return fmt.Errorf("group param curve not supported")
	}
	if group.GroupInfo.Threshold < 1 {
		return fmt.Errorf("group param threshold not supported")
	}
	if group.GroupInfo.Threshold > int32(len(group.GroupInfo.Participants)) {
		return fmt.Errorf("group param threshold participants less than threshold")
	}

	if group.ShareInfo.NodeID == "" {
		return fmt.Errorf("group param node id nil")
	}
	if group.ShareInfo.ShareID == "" {
		return fmt.Errorf("group param share ID nil")
	}
	if group.ShareInfo.SharePubKey == "" {
		return fmt.Errorf("group param share public key nil")
	}
	if group.ShareInfo.EncryptedShare == nil {
		return fmt.Errorf("group param encrypted share nil")
	}
	if group.ShareInfo.KDF == nil {
		return fmt.Errorf("group param encrypt KDF nil")
	}
	return nil
}

//nolint:gocognit,cyclop
func checkGroupParticipants(group *tss.Group) error {
	parts := group.GroupInfo.Participants
	if int(group.GroupInfo.Threshold) > len(parts) {
		return fmt.Errorf("number of participants %v parse from files less than threshold %v",
			len(group.GroupInfo.Participants), int(group.GroupInfo.Threshold))
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
				return fmt.Errorf("participants (no.%v and no.%v) node ids should be different", i+1, j+1)
			}
			if part.ShareID == parts[j].ShareID {
				return fmt.Errorf("participants (no.%v and no.%v) share ids should be different", i+1, j+1)
			}
			if part.SharePubKey == parts[j].SharePubKey {
				return fmt.Errorf("participants (no.%v and no.%v) share public keys should be different", i+1, j+1)
			}
		}
		if part.NodeID == group.ShareInfo.NodeID {
			if part.ShareID != group.ShareInfo.ShareID {
				return fmt.Errorf("participant (no.%v) mismatch with share id in share info", i+1)
			}
			if part.SharePubKey != group.ShareInfo.SharePubKey {
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

func checkMultiGroupsParam(group1 *tss.Group, group2 *tss.Group) error {
	if group1.GroupInfo.ID != group2.GroupInfo.ID {
		return fmt.Errorf("group ids mismatch")
	}
	if group1.GroupInfo.Type != group2.GroupInfo.Type {
		return fmt.Errorf("group types mismatch")
	}
	if group1.GroupInfo.RootExtendedPubKey != group2.GroupInfo.RootExtendedPubKey {
		return fmt.Errorf("group root extended public keys mismatch")
	}
	if group1.GroupInfo.ChainCode != group2.GroupInfo.ChainCode {
		return fmt.Errorf("group chaincodes mismatch")
	}
	if group1.GroupInfo.Curve != group2.GroupInfo.Curve {
		return fmt.Errorf("group curves mismatch")
	}
	if group1.GroupInfo.Threshold != group2.GroupInfo.Threshold {
		return fmt.Errorf("group thresholds mismatch")
	}
	if group1.ShareInfo.NodeID == group2.ShareInfo.NodeID {
		return fmt.Errorf("node ids should be different")
	}
	if group1.ShareInfo.ShareID == group2.ShareInfo.ShareID {
		return fmt.Errorf("share ids should be different")
	}
	if group1.ShareInfo.SharePubKey == group2.ShareInfo.SharePubKey {
		return fmt.Errorf("share public keys should be different")
	}
	return nil
}

func checkMultiGroupsParticipants(group1 *tss.Group, group2 *tss.Group) error {
	parts1 := group1.GroupInfo.Participants
	parts2 := group2.GroupInfo.Participants
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
