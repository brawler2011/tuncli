package cmd

import (
	"fmt"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/sub"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update [url]",
	Short: "Update subscription nodes",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		subURL := cfg.SubscriptionURL
		if len(args) > 0 {
			subURL = args[0]
			cfg.SubscriptionURL = subURL // Update the URL in config
		}

		if subURL == "" {
			return fmt.Errorf("subscription URL is required. Provide it as an argument: tuncli update <url>")
		}

		fmt.Printf("Fetching subscription from %s...\n", subURL)

		nodes, err := sub.FetchAndParse(subURL)
		if err != nil {
			return fmt.Errorf("failed to fetch/parse: %w", err)
		}

		fmt.Printf("Successfully fetched %d nodes.\n", len(nodes))

		// Convert sub.Node to config.Node
		cfg.Nodes = make([]config.Node, len(nodes))
		for i, n := range nodes {
			cfg.Nodes[i] = config.Node{
				Name:      n.Name,
				Protocol:  n.Protocol,
				Server:    n.Server,
				Port:      n.Port,
				RawLink:   n.RawLink,
				RawConfig: n.RawConfig,
			}
		}

		// Reset selected node index if it's out of bounds
		if cfg.SelectedNodeIndex >= len(cfg.Nodes) {
			cfg.SelectedNodeIndex = -1
		}

		err = config.SaveConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Println("Configuration saved.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
