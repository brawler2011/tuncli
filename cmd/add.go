package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/sub"

	"github.com/spf13/cobra"
)

var (
	addName string
)

var addCmd = &cobra.Command{
	Use:   "add <link>",
	Short: "Add a new subscription or server",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		link := args[0]

		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		isSub := strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://")

		var itemType string
		var idPrefix string
		var name string

		if isSub {
			itemType = "subscription"
			idPrefix = "sub"
			if addName != "" {
				name = addName
			} else {
				u, err := url.Parse(link)
				if err == nil {
					name = u.Host
				} else {
					name = "Subscription"
				}
			}
		} else {
			itemType = "server"
			idPrefix = "srv"
			if addName != "" {
				name = addName
			} else {
				u, err := url.Parse(link)
				if err == nil && u.Fragment != "" {
					unescaped, err := url.QueryUnescape(u.Fragment)
					if err == nil {
						name = unescaped
					} else {
						name = u.Fragment
					}
				} else if err == nil {
					name = u.Hostname()
				} else {
					name = "Server"
				}
			}
		}

		// Generate unique short ID
		var id string
		for i := 1; ; i++ {
			candidate := fmt.Sprintf("%s%d", idPrefix, i)
			exists := false
			for _, item := range cfg.Subscriptions {
				if item.ID == candidate {
					exists = true
					break
				}
			}
			if !exists {
				id = candidate
				break
			}
		}

		fmt.Printf("Fetching/parsing node data from %s...\n", link)
		fetchedNodes, err := sub.FetchAndParse(link)
		if err != nil {
			return fmt.Errorf("failed to add: failed to fetch or parse link: %w", err)
		}

		// Convert sub.Node to config.Node
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

		err = config.SaveSubscriptionNodes(id, nodes)
		if err != nil {
			return fmt.Errorf("failed to save subscription nodes cache: %w", err)
		}

		item := config.SubscriptionItem{
			ID:   id,
			Name: name,
			URL:  link,
			Type: itemType,
		}

		cfg.Subscriptions = append(cfg.Subscriptions, item)

		err = config.SaveConfig(cfg)
		if err != nil {
			// clean up cached nodes if config save fails
			_ = config.DeleteSubscriptionNodes(id)
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Successfully added %s %q with ID %q. Fetched %d node(s).\n", itemType, name, id, len(nodes))
		return nil
	},
}

func init() {
	addCmd.Flags().StringVarP(&addName, "name", "n", "", "Custom name for the subscription/server")
	rootCmd.AddCommand(addCmd)
}
