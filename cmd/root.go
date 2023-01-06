package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	GroupFiles      []string
	GroupID         string
	ShowRootPrivate bool
	Paths           []string
	Csv             string
	CsvOutputDir    string
)

func InitCmd() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func AddFlag() {
	rootCmd.PersistentFlags().StringSliceVar(&GroupFiles, "group-recovery-files", []string{},
		"TSS group recovery files, such as recovery/tss-group-id-node-1-time,recovery/tss-group-id-node-1-time")
	rootCmd.MarkPersistentFlagRequired("group-recovery-files")
	rootCmd.PersistentFlags().StringVar(&GroupID, "group-id", "", "recovery group id")
	rootCmd.MarkPersistentFlagRequired("group-id")

	rootCmd.Flags().BoolVar(&ShowRootPrivate, "show-root-private-key", false, "show TSS root private key")
	rootCmd.Flags().StringSliceVar(&Paths, "paths", []string{}, "key HD derivation paths")
	rootCmd.Flags().StringVar(&Csv, "csv-file", "",
		"address csv file, contains HD derivation paths")
	rootCmd.Flags().StringVar(&CsvOutputDir, "csv-output-dir", "recovery",
		"address csv output dir, derive keys file output in this directory")
}

var rootCmd = &cobra.Command{
	Use:   "cobo-mpc-recovery-tool",
	Short: "cobo-mpc-recovery-tool to reconstruct root private key by TSS group recovery files and derive child keys",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		err := checkFlags()
		if err != nil {
			log.Fatal("Check flags failed: ", err)
		}
		privateKey := recoveryPrivateKey()
		deriveKey(privateKey)
	},
}

func Execute() {
	InitCmd()
	AddFlag()

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
