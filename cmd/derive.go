package cmd

import (
	"fmt"

	"github.com/cobo/cobo-mpc-recovery-kits/pkg/crypto"
	"github.com/cobo/cobo-mpc-recovery-kits/pkg/wallet"
	"github.com/cobo/cobo-mpc-recovery-kits/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var deriveCmd = &cobra.Command{
	Use:   "derive",
	Short: "Root key derives the corresponding child public key and addresses based on the paths and token",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Version: " + version.TextVersion() + "\n")
		derive()
	},
}

func derive() {
	if RootKey == "" {
		log.Fatal("no root key")
	}
	key, err := crypto.B58Deserialize(RootKey)
	if err != nil {
		log.Fatalf("failed to deserialize root key: %v", RootKey)
	}

	if len(Paths) > 0 {
		for _, hdPath := range Paths {
			dk, err := crypto.Derive(key, hdPath)
			if err != nil {
				log.Fatalf("Derive path %v error: %v", hdPath, err)
			}
			log.Printf("Path: %v derived child extended public key: %v", hdPath, dk.PublicKey().String())

			if Token != "" {
				token, err := wallet.GetToken(Token)
				if err != nil {
					log.Fatalf("Get token error: %v", err)
				}

				addresses, err := token.GenerateAddresses(dk)
				if err != nil {
					log.Fatalf("Generate address error: %v", err)
				}
				for _, address := range addresses {
					log.Printf("Token %v Address Type: %v, Address: %v", token, address.Type, address.Address)
				}
			}
		}
	}
}
