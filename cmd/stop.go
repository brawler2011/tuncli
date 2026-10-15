package cmd

import (
	"github.com/brawler2011/tuncli/pkg/runner"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running VPN connection",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runner.Stop()
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
