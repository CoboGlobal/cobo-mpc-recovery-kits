package cmd

import (
	"fmt"

	"github.com/cobo/cobo-mpc-recovery-kits/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show version information",
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.TextVersion())
	},
}
