package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/brawler2011/tuncli/pkg/config"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all subscriptions and servers",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		if len(cfg.Subscriptions) == 0 {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "No subscriptions or servers added yet. Run 'tuncli add <link>' to add one.")
			return err
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		if _, err := fmt.Fprintln(w, "ID\tNAME\tTYPE\tNODES\tURL/LINK"); err != nil {
			return err
		}

		for _, item := range cfg.Subscriptions {
			nodes, err := config.LoadSubscriptionNodes(item.ID)
			nodeCount := 0
			if err == nil {
				nodeCount = len(nodes)
			}

			urlStr := item.URL
			if len(urlStr) > 60 {
				urlStr = urlStr[:57] + "..."
			}

			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", item.ID, item.Name, item.Type, nodeCount, urlStr); err != nil {
				return err
			}
		}
		return w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
