package cmd

import (
	"fmt"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/runner"
	"github.com/brawler2011/tuncli/pkg/service"

	"github.com/spf13/cobra"
)

var startMode string
var startNode string

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the VPN connection",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := service.Call(cmd.Context(), service.Request{Operation: "start", Mode: startMode, Node: startNode})
		return err
	},
}

func init() {
	startCmd.Flags().StringVarP(&startMode, "mode", "m", "", "Save operating mode (tun or proxy)")
	startCmd.Flags().StringVarP(&startNode, "node", "n", "", "Save node selection and connect in background")
	rootCmd.AddCommand(startCmd)
	run := &cobra.Command{Use: "run", Short: "Run VPN in foreground (without an installed service)", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if service.Installed() {
			return fmt.Errorf("service installed; use tuncli start")
		}
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}
		mode, _ := cmd.Flags().GetString("mode")
		node, _ := cmd.Flags().GetString("node")
		if err = applyStartOverrides(cfg, mode, node); err != nil {
			return err
		}
		return runner.Start(cfg)
	}}
	run.Flags().StringP("mode", "m", "", "Operating mode (tun or proxy)")
	run.Flags().StringP("node", "n", "", "Node name")
	rootCmd.AddCommand(run)
}

func applyStartOverrides(cfg *config.Config, mode, nodeName string) error {
	if mode != "" {
		if mode != "tun" && mode != "proxy" {
			return fmt.Errorf("invalid mode %q: must be 'tun' or 'proxy'", mode)
		}
		cfg.Mode = mode
	}

	if nodeName != "" {
		found := false
		if cfg.SelectedSubscription != "" {
			if nodes, err := config.LoadSubscriptionNodes(cfg.SelectedSubscription); err == nil {
				for _, n := range nodes {
					if n.Name == nodeName {
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
						if n.Name == nodeName {
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
			return fmt.Errorf("node %q not found in any subscription", nodeName)
		}
	}

	return nil
}
