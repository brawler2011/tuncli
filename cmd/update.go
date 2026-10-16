package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/sub"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update [id/name]",
	Short: "Update subscription nodes",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		if len(args) == 0 {
			// Update all subscriptions
			hasSubs := false
			var failures []error
			for _, item := range cfg.Subscriptions {
				if item.Type == "subscription" {
					hasSubs = true
					err := updateSubscription(item)
					if err != nil {
						failures = append(failures, fmt.Errorf("%s: %w", item.Name, err))
					}
				}
			}
			if !hasSubs {
				fmt.Println("No subscriptions to update. Add one with 'tuncli add <link>'.")
			}
			return errors.Join(failures...)
		}

		target := args[0]
		var foundIdx = -1

		// 1. Check exact ID match
		for i, item := range cfg.Subscriptions {
			if item.ID == target {
				foundIdx = i
				break
			}
		}

		// 2. Check exact Name match (case-insensitive)
		if foundIdx == -1 {
			for i, item := range cfg.Subscriptions {
				if strings.EqualFold(item.Name, target) {
					foundIdx = i
					break
				}
			}
		}

		// 3. Check substring Name match (case-insensitive)
		if foundIdx == -1 {
			for i, item := range cfg.Subscriptions {
				if strings.Contains(strings.ToLower(item.Name), strings.ToLower(target)) {
					foundIdx = i
					break
				}
			}
		}

		if foundIdx == -1 {
			return fmt.Errorf("no subscription or server matching %q found", target)
		}

		item := cfg.Subscriptions[foundIdx]
		if item.Type == "server" {
			return fmt.Errorf("item %q is a direct server and does not need updating", item.Name)
		}

		return updateSubscription(item)
	},
}

func updateSubscription(item config.SubscriptionItem) error {
	fmt.Printf("Updating %s (%s)...\n", item.Name, item.ID)
	fetchedNodes, err := sub.FetchAndParse(item.URL)
	if err != nil {
		return fmt.Errorf("failed to fetch/parse: %w", err)
	}

	nodes := make([]config.Node, len(fetchedNodes))
	for i, n := range fetchedNodes {
		nodes[i] = config.Node{
			Name:      n.Name,
			Protocol:  n.Protocol,
			Server:    n.Server,
			Port:      n.Port,
			RawLink:   n.RawLink,
			RawConfig: n.RawConfig,
		}
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.SelectedSubscription == item.ID {
		found := false
		for _, n := range nodes {
			if n.Name == cfg.SelectedNode {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("selected node disappeared; retaining previous subscription")
		}
	}
	err = config.SaveSubscriptionNodes(item.ID, nodes)
	if err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	fmt.Printf("Successfully updated %s (%s): %d nodes cached.\n", item.Name, item.ID, len(nodes))
	return nil
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
