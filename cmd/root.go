package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "tuncli",
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "A cool VPN CLI wrapper for sing-box",
	Long:          `tuncli is a CLI wrapper around sing-box that can fetch subscriptions and manage VPN connections via TUN or Proxy.`,
}

func Execute() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
