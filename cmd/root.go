package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tuncli",
	Short: "A cool VPN CLI wrapper for sing-box",
	Long:  `tuncli is a CLI wrapper around sing-box that can fetch subscriptions and manage VPN connections via TUN or Proxy.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
