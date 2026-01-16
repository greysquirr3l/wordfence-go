package cmd

import (
	"github.com/greysquirr3l/wordfence-go/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Long:  `Display the version of Wordfence CLI and build information.`,
	Run: func(_ *cobra.Command, _ []string) {
		version.PrintVersion()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
