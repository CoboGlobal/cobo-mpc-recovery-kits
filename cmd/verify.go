package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/tss"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verify command to reconstruct root public key by share public keys and verify TSS group recovery files parameters",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		verifyShare()
	},
}

//nolint:cyclop
func verifyShare() {
	if len(GroupFiles) == 0 {
		log.Fatal("no group recovery files")
	}
	if GroupID == "" {
		log.Fatal("nil group ID")
	}

	verifyGroups := make([]*tss.Group, 0)
	for _, groupFile := range GroupFiles {
		_, err := os.Stat(groupFile)
		if err != nil {
			log.Fatalln("Group recovery file error:", err)
		}
		log.Printf("Start to verify group recovery file %v", groupFile)

		groupBytes, err := ioutil.ReadFile(groupFile)
		if err != nil {
			log.Fatalln("Read group recovery file failed:", err)
		}

		group := &tss.Group{}
		err = json.Unmarshal(groupBytes, group)
		if err != nil {
			log.Fatalln("Unmarshal group failed:", err)
		}

		if err := checkGroupParam(GroupID, group); err != nil {
			log.Fatalln("Group param check error:", err)
		}

		if err := checkGroupParticipants(group); err != nil {
			log.Fatalln("Group participants check error:", err)
		}
		log.Printf("Verify all group parameters passed!")

		for i, verifyGroup := range verifyGroups {
			if err := checkMultiGroupsParam(verifyGroup, group); err != nil {
				log.Fatalln("Multi groups param check  error:", err)
			}
			if err := checkMultiGroupsParticipants(verifyGroup, group); err != nil {
				log.Fatalln("Multi groups participants check error:", err)
			}
			log.Printf("Compare with no.%v group parameters passed!", i+1)
		}
		verifyGroups = append(verifyGroups, group)

		log.Printf("Start to reconstruct root public key ...")
		if err := group.GroupInfo.VerifyReconstructPubKey(); err != nil {
			log.Fatalln("Verify root public key error:", err)
		}
		log.Printf("Verify to reconstruct root public key passed!")

		log.Printf("Start to derive share public key from share secret ...")
		fmt.Printf("Enter password to decrypt share secret from %v\n", groupFile)
		key, err := cipher.Credentials("Password:")
		if err != nil {
			log.Fatalln("Credentials error:", err)
		}
		curveType := crypto.CurveNameType[group.GroupInfo.Curve]
		if err := group.ShareInfo.VerifySharePublicKey(curveType, key); err != nil {
			log.Fatalln("Verify share public key failed:", err)
		}
		log.Printf("Verify to derive share public key from share secret passed!")
		log.Printf("Verfiy group recovery file %v passed!", groupFile)
		log.Printf("=======================================")
	}
	log.Printf("Verfiy all group recovery files passed!")
}
