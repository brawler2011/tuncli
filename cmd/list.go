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
			fmt.Fprintln(cmd.OutOrStdout(), "No subscriptions or servers added yet. Run 'tuncli add <link>' to add one.")
			return nil
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tTYPE\tNODES\tURL/LINK")

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

			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", item.ID, item.Name, item.Type, nodeCount, urlStr)
		}
		w.Flush()

		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
