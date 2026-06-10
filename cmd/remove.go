package cmd

import (
	"fmt"
	"strings"

	"github.com/brawler2011/tuncli/pkg/config"

	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:   "remove <id/name>",
	Short: "Remove a subscription or server",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		var foundIdx int = -1

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
			return fmt.Errorf("no subscription or server matching %q found. Run 'tuncli list' to see active items.", target)
		}

		removedItem := cfg.Subscriptions[foundIdx]

		// Delete subscription nodes cache file
		err = config.DeleteSubscriptionNodes(removedItem.ID)
		if err != nil {
			fmt.Printf("Warning: failed to delete cache file: %v\n", err)
		}

		// Remove from slice
		cfg.Subscriptions = append(cfg.Subscriptions[:foundIdx], cfg.Subscriptions[foundIdx+1:]...)

		// Reset selected node if it belongs to the removed subscription
		if cfg.SelectedSubscription == removedItem.ID {
			cfg.SelectedSubscription = ""
			cfg.SelectedNode = ""
			fmt.Println("Reset selected node because its subscription was removed.")
		}

		err = config.SaveConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Successfully removed %s %q with ID %q.\n", removedItem.Type, removedItem.Name, removedItem.ID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(removeCmd)
}
