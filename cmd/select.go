package cmd

import (
	"fmt"

	"github.com/brawler2011/tuncli/pkg/config"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
)

var selectCmd = &cobra.Command{
	Use:   "select",
	Short: "Interactively select a node and mode",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}

		if len(cfg.Subscriptions) == 0 {
			return fmt.Errorf("no subscriptions or servers added yet. Please run 'tuncli add <link>' first.")
		}

		// 1. Select Mode
		modePrompt := &survey.Select{
			Message: "Select operating mode:",
			Options: []string{"tun", "proxy"},
			Default: cfg.Mode,
		}
		var selectedMode string
		err = survey.AskOne(modePrompt, &selectedMode)
		if err != nil {
			return err
		}
		cfg.Mode = selectedMode

		// 2. Load all nodes across subscriptions
		type nodeOption struct {
			SubID    string
			NodeName string
			Display  string
		}

		var options []nodeOption
		var nodeNames []string
		for _, sub := range cfg.Subscriptions {
			nodes, err := config.LoadSubscriptionNodes(sub.ID)
			if err != nil {
				continue
			}
			for _, n := range nodes {
				display := fmt.Sprintf("[%s] %s", sub.Name, n.Name)
				options = append(options, nodeOption{
					SubID:    sub.ID,
					NodeName: n.Name,
					Display:  display,
				})
				nodeNames = append(nodeNames, display)
			}
		}

		if len(nodeNames) == 0 {
			return fmt.Errorf("no nodes available. Please run 'tuncli update' first.")
		}

		nodePrompt := &survey.Select{
			Message:  "Select a VPN node:",
			Options:  nodeNames,
			PageSize: 15,
		}

		// Set default if valid
		if cfg.SelectedSubscription != "" && cfg.SelectedNode != "" {
			for _, opt := range options {
				if opt.SubID == cfg.SelectedSubscription && opt.NodeName == cfg.SelectedNode {
					nodePrompt.Default = opt.Display
					break
				}
			}
		}

		var selectedDisplay string
		err = survey.AskOne(nodePrompt, &selectedDisplay)
		if err != nil {
			return err
		}

		// Find the selected option
		var selectedOpt nodeOption
		for _, opt := range options {
			if opt.Display == selectedDisplay {
				selectedOpt = opt
				break
			}
		}

		cfg.SelectedSubscription = selectedOpt.SubID
		cfg.SelectedNode = selectedOpt.NodeName

		err = config.SaveConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Successfully selected node: %s\nMode set to: %s\n", cfg.SelectedNode, cfg.Mode)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(selectCmd)
}
