package cmd

import (
	"fmt"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/runner"

	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the VPN connection",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		err = runner.Start(cfg)
		if err != nil {
			return fmt.Errorf("VPN failed: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
