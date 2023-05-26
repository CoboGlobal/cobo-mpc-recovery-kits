package cmd

import (
	"fmt"
	"os"

	"github.com/cobo/cobo-mpc-recovery-kits/version"
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
	rootCmd.AddCommand(versionCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func AddFlag() {
	rootCmd.Flags().StringSliceVar(&GroupFiles, "group-recovery-files", []string{},
		"TSS group recovery files, such as recovery/tss-group-id-node-1-time1,recovery/tss-group-id-node-2-time2")
	if err := rootCmd.MarkFlagRequired("group-recovery-files"); err != nil {
		log.Fatal(err)
	}
	rootCmd.Flags().StringVar(&GroupID, "group-id", "", "recovery group id")
	if err := rootCmd.MarkFlagRequired("group-id"); err != nil {
		log.Fatal(err)
	}
	rootCmd.Flags().BoolVar(&ShowRootPrivate, "show-root-private-key", false, "show TSS root private key")
	rootCmd.Flags().StringSliceVar(&Paths, "paths", []string{}, "key HD derivation paths")
	rootCmd.Flags().StringVar(&Csv, "csv-file", "",
		"address csv file, contains HD derivation paths")
	rootCmd.Flags().StringVar(&CsvOutputDir, "csv-output-dir", "recovery",
		"address csv output dir, derive keys file output in this directory")

	verifyCmd.Flags().StringSliceVar(&GroupFiles, "group-recovery-files", []string{},
		"TSS group recovery files, such as recovery/tss-group-id-node-1-time1,recovery/tss-group-id-node-2-time2")
	if err := verifyCmd.MarkFlagRequired("group-recovery-files"); err != nil {
		log.Fatal(err)
	}
	verifyCmd.Flags().StringVar(&GroupID, "group-id", "", "recovery group id")
	if err := verifyCmd.MarkFlagRequired("group-id"); err != nil {
		log.Fatal(err)
	}
}

var rootCmd = &cobra.Command{
	Use:   "cobo-mpc-recovery-tool",
	Short: "cobo-mpc-recovery-tool to reconstruct root private key by TSS group recovery files and derive child keys",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Version: " + version.TextVersion() + "\n")
		err := checkFlags()
		if err != nil {
			log.Fatal("Check flags failed: ", err)
		}
		recovery()
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

func checkFlags() error {
	if len(Paths) > 0 && Csv != "" {
		return fmt.Errorf("flags 'paths' and 'csv' at same time is not allowed")
	}

	return nil
}
