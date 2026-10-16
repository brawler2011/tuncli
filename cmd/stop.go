package cmd

import (
	"github.com/brawler2011/tuncli/pkg/service"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running VPN connection",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := service.Call(cmd.Context(), service.Request{Operation: "stop"})
		return err
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
