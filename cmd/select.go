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

		if len(cfg.Nodes) == 0 {
			return fmt.Errorf("no nodes available. Please run 'tuncli update' first.")
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

		// 2. Select Node
		var nodeNames []string
		for _, n := range cfg.Nodes {
			nodeNames = append(nodeNames, n.Name)
		}

		nodePrompt := &survey.Select{
			Message:  "Select a VPN node:",
			Options:  nodeNames,
			PageSize: 15,
		}

		// Set default if valid
		if cfg.SelectedNodeIndex >= 0 && cfg.SelectedNodeIndex < len(nodeNames) {
			nodePrompt.Default = nodeNames[cfg.SelectedNodeIndex]
		}

		var selectedNodeIndex int
		err = survey.AskOne(nodePrompt, &selectedNodeIndex)
		if err != nil {
			return err
		}

		cfg.SelectedNodeIndex = selectedNodeIndex

		err = config.SaveConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		fmt.Printf("Successfully selected node: %s\nMode set to: %s\n", cfg.Nodes[selectedNodeIndex].Name, cfg.Mode)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(selectCmd)
}
