package cmd

import (
	"fmt"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/runner"

	"github.com/spf13/cobra"
)

var startMode string
var startNode string

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the VPN connection",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		if startMode != "" {
			if startMode != "tun" && startMode != "proxy" {
				return fmt.Errorf("invalid mode %q: must be 'tun' or 'proxy'", startMode)
			}
			cfg.Mode = startMode
		}

		if startNode != "" {
			found := false
			if cfg.SelectedSubscription != "" {
				if nodes, err := config.LoadSubscriptionNodes(cfg.SelectedSubscription); err == nil {
					for _, n := range nodes {
						if n.Name == startNode {
							cfg.SelectedNode = n.Name
							found = true
							break
						}
					}
				}
			}
			if !found {
				for _, sub := range cfg.Subscriptions {
					if nodes, err := config.LoadSubscriptionNodes(sub.ID); err == nil {
						for _, n := range nodes {
							if n.Name == startNode {
								cfg.SelectedSubscription = sub.ID
								cfg.SelectedNode = n.Name
								found = true
								break
							}
						}
					}
					if found {
						break
					}
				}
			}
			if !found {
				return fmt.Errorf("node %q not found in any subscription", startNode)
			}
		}

		err = runner.Start(cfg)
		if err != nil {
			return fmt.Errorf("VPN failed: %w", err)
		}

		return nil
	},
}

func init() {
	startCmd.Flags().StringVarP(&startMode, "mode", "m", "", "Override operating mode (tun or proxy)")
	startCmd.Flags().StringVarP(&startNode, "node", "n", "", "Specify node name to start")
	rootCmd.AddCommand(startCmd)
}
