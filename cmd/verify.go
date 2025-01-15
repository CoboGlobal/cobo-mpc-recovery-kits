package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CoboGlobal/cobo-mpc-recovery-kits/pkg/cipher"
	"github.com/CoboGlobal/cobo-mpc-recovery-kits/pkg/tss"
	"github.com/CoboGlobal/cobo-mpc-recovery-kits/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Reconstruct root public key by share public keys and verify TSS recovery group files parameters",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Version: " + version.TextVersion() + "\n")
		verifyShare()
	},
}

//nolint:gocognit
func verifyShare() {
	if len(GroupFiles) == 0 {
		log.Fatal("no recovery group files")
	}
	if GroupID == "" {
		log.Fatal("nil group ID")
	}

	verifyGroups := make([]*tss.Group, 0)
	for _, groupFile := range GroupFiles {
		_, err := os.Stat(groupFile)
		if err != nil {
			log.Fatalln("Recovery group file error:", err)
		}
		log.Printf("Start to verify recovery group file %v", groupFile)

		groupBytes, err := os.ReadFile(filepath.Clean(groupFile))
		if err != nil {
			log.Fatalln("Read recovery group file failed:", err)
		}

		var groups []*tss.Group
		rSecrets := tss.RecoverySecrets{RecoveryGroups: make([]*tss.Group, 0)}
		rGroups := make([]*tss.Group, 0)
		var rGroup tss.Group
		if err := json.Unmarshal(groupBytes, &rSecrets); err == nil && len(rSecrets.RecoveryGroups) > 0 {
			groups = rSecrets.RecoveryGroups
		} else if err := json.Unmarshal(groupBytes, &rGroups); err == nil && len(rGroups) > 0 {
			groups = rGroups
		} else if err := json.Unmarshal(groupBytes, &rGroup); err == nil {
			rGroups = append(rGroups, &rGroup)
			groups = rGroups
		} else {
			log.Fatalf("Cannot parse recovery group file: %v", groupFile)
		}

		var group *tss.Group
		for i := range groups {
			if GroupID == groups[i].GroupInfo.ID {
				group = groups[i]
				break
			}
		}

		if group == nil || group.GroupInfo == nil || GroupID != group.GroupInfo.ID {
			log.Fatalf("Not found group %v from recovery group file", GroupID)
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
		log.Printf("Verify recovery group file %v passed!", groupFile)
		log.Printf("=======================================")
	}
	log.Printf("Verify all recovery group files passed!")
}
