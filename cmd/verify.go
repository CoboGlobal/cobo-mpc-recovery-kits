package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/tss"
	"github.com/cobo/cobo-mpc-recovery-kits/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verify command to reconstruct root public key by share public keys and verify TSS group recovery files parameters",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Version: " + version.TextVersion() + "\n")
		verifyShare()
	},
}

//nolint:gocognit
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

		groupBytes, err := os.ReadFile(groupFile) //#nosec G304
		if err != nil {
			log.Fatalln("Read group recovery file failed:", err)
		}

		group := &tss.Group{}
		err = json.Unmarshal(groupBytes, group)
		if err != nil {
			groups := make([]tss.Group, 0)
			err = json.Unmarshal(groupBytes, &groups)
			if err != nil {
				log.Fatalf("Unmarshal group failed: %v", err)
			}
			for _, g := range groups {
				if GroupID == g.GroupInfo.ID {
					group = &g
					break
				}
			}
		}
		if group.GroupInfo == nil || GroupID != group.GroupInfo.ID {
			log.Fatalf("Not found group %v from group recovery file", GroupID)
		}

		if err := group.CheckGroupParams(); err != nil {
			log.Fatalln("Group param check error:", err)
		}
		log.Printf("Verify group parameters passed!")

		for i, verifyGroup := range verifyGroups {
			log.Printf("Start to compare with group (no.%v) parameters ...", i+1)
			if err := group.CheckWithGroup(verifyGroup); err != nil {
				log.Fatalln("Multi groups param check  error:", err)
			}
			log.Printf("Compare with group (no.%v) parameters passed!", i+1)
		}
		verifyGroups = append(verifyGroups, group)

		log.Printf("Start to reconstruct root public key ...")
		if err := group.VerifyRootPublicKey(); err != nil {
			log.Fatalln("Verify root public key error:", err)
		}
		log.Printf("Verify to reconstruct root public key passed!")

		log.Printf("Start to derive share public key from share secret ...")
		fmt.Printf("Enter password to decrypt share secret from %v\n", groupFile)
		key, err := cipher.Credentials("Password:")
		if err != nil {
			log.Fatalln("Credentials error:", err)
		}
		if err := group.VerifySharePublicKey(key); err != nil {
			log.Fatalln("Verify share public key failed:", err)
		}
		log.Printf("Verify to derive share public key from share secret passed!")
		log.Printf("Verify group recovery file %v passed!", groupFile)
		log.Printf("=======================================")
	}
	log.Printf("Verify all group recovery files passed!")
}
