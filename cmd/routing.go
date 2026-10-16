package cmd

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/spf13/cobra"
)

func newRoutingCommand() *cobra.Command {
	root := &cobra.Command{Use: "routing", Short: "Manage persistent domain routing (applied on next VPN start)"}
	change := func(fn func(*routing.Policy, []string, *cobra.Command) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadConfig()
			if err != nil {
				return err
			}
			if cfg.Routing == nil {
				cfg.Routing = routing.New()
			}
			if cfg.Routing.Presets == nil {
				cfg.Routing.Presets = map[string]routing.Outbound{}
			}
			if err = fn(cfg.Routing, args, cmd); err != nil {
				return err
			}
			if err = config.SaveConfig(cfg); err != nil {
				return err
			}
			cmd.Println("Routing settings saved. Restart VPN to apply changes.")
			return nil
		}
	}
	preset := &cobra.Command{Use: "preset", Short: "Manage presets"}
	preset.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, Run: func(cmd *cobra.Command, _ []string) {
		for _, p := range routing.Presets {
			cmd.Printf("%s  recommended=%s  %s%s\n", p.ID, p.Recommended, routing.BaseURL, p.File)
		}
	}})
	enable := &cobra.Command{Use: "enable <preset>", Args: cobra.ExactArgs(1), RunE: change(func(p *routing.Policy, args []string, cmd *cobra.Command) error {
		preset, err := routing.Find(args[0])
		if err != nil {
			return err
		}
		value, _ := cmd.Flags().GetString("outbound")
		o := preset.Recommended
		if value != "" {
			o = routing.Outbound(value)
		}
		if err = o.Validate(); err != nil {
			return err
		}
		p.Presets[preset.ID] = o
		p.Enabled = true
		return nil
	})}
	enable.Flags().String("outbound", "", "Route: direct or vpn (default: preset recommendation)")
	preset.AddCommand(enable)
	preset.AddCommand(&cobra.Command{Use: "disable <preset>", Args: cobra.ExactArgs(1), RunE: change(func(p *routing.Policy, args []string, _ *cobra.Command) error {
		if _, err := routing.Find(args[0]); err != nil {
			return err
		}
		delete(p.Presets, args[0])
		return nil
	})})
	root.AddCommand(preset)
	rule := &cobra.Command{Use: "rule", Short: "Manage personal domain rules"}
	add := &cobra.Command{Use: "add <domain>", Args: cobra.ExactArgs(1), RunE: change(func(p *routing.Policy, args []string, cmd *cobra.Command) error {
		domain, err := routing.Normalize(args[0])
		if err != nil {
			return err
		}
		s, _ := cmd.Flags().GetBool("suffix")
		value, _ := cmd.Flags().GetString("outbound")
		o := routing.Outbound(value)
		if err = o.Validate(); err != nil {
			return err
		}
		r := routing.Rule{Domain: domain, Suffix: s, Outbound: o}
		for i, old := range p.Rules {
			if old.Domain == domain && old.Suffix == s {
				p.Rules[i] = r
				p.Enabled = true
				return nil
			}
		}
		p.Rules = append(p.Rules, r)
		p.Enabled = true
		return nil
	})}
	add.Flags().Bool("suffix", false, "Include the domain and all subdomains")
	add.Flags().String("outbound", "", "Route: direct or vpn")
	_ = add.MarkFlagRequired("outbound")
	rule.AddCommand(add)
	remove := &cobra.Command{Use: "remove <domain>", Short: "Remove exact rule (use --suffix for a suffix rule)", Args: cobra.ExactArgs(1), RunE: change(func(p *routing.Policy, args []string, cmd *cobra.Command) error {
		d, err := routing.Normalize(args[0])
		if err != nil {
			return err
		}
		suffix, _ := cmd.Flags().GetBool("suffix")
		for i, r := range p.Rules {
			if r.Domain == d && r.Suffix == suffix {
				p.Rules = append(p.Rules[:i], p.Rules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("domain rule %s (suffix=%t) not found", d, suffix)
	})}
	remove.Flags().Bool("suffix", false, "Remove the suffix rule")
	rule.AddCommand(remove)
	root.AddCommand(rule)
	root.AddCommand(&cobra.Command{Use: "default <direct|vpn>", Args: cobra.ExactArgs(1), RunE: change(func(p *routing.Policy, args []string, _ *cobra.Command) error {
		o := routing.Outbound(args[0])
		if err := o.Validate(); err != nil {
			return err
		}
		p.Default = o
		p.Enabled = true
		return nil
	})})
	for _, enabled := range []bool{false, true} {
		name := "disable"
		if enabled {
			name = "enable"
		}
		root.AddCommand(&cobra.Command{Use: name, Args: cobra.NoArgs, RunE: change(func(p *routing.Policy, _ []string, _ *cobra.Command) error { p.Enabled = enabled; return nil })})
	}
	root.AddCommand(&cobra.Command{Use: "show", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}
		p := cfg.Routing
		if p == nil {
			p = routing.New()
		}
		cmd.Printf("Enabled: %t\nDefault: %s\n", p.Enabled, p.Default)
		cmd.Println("Personal rules:")
		if len(p.Rules) == 0 {
			cmd.Println("  (none)")
		}
		for _, e := range (&routing.Prepared{Policy: p}).Entries() {
			if domains, ok := e.Match["domain"].([]string); ok {
				cmd.Printf("  %s (exact) -> %s\n", domains[0], e.Outbound)
			}
			if domains, ok := e.Match["domain_suffix"].([]string); ok {
				cmd.Printf("  %s (suffix) -> %s\n", domains[0], e.Outbound)
			}
		}
		dir, err := config.GetConfigDir()
		if err != nil {
			return err
		}
		cache := routing.NewCache(filepath.Join(dir, "routing"))
		for _, preset := range routing.Presets {
			o, ok := p.Presets[preset.ID]
			state := "disabled"
			if ok {
				state = string(o)
			}
			cmd.Printf("Preset %s: %s\nSource: %s%s\n", preset.ID, state, routing.BaseURL, preset.File)
			record, err := cache.Inspect(preset.ID)
			if err != nil {
				cmd.Printf("Cache: unavailable (%v)\n", err)
			} else {
				fresh := "fresh"
				if time.Since(record.Checked) >= routing.FreshFor {
					fresh = "stale"
				}
				cmd.Printf("Cache: %s, checked=%s, SHA-256=%s\n", fresh, record.Checked.Format(time.RFC3339), record.SHA256)
			}
		}
		cmd.Println("Changes apply on next VPN start.")
		return nil
	}})
	root.AddCommand(&cobra.Command{Use: "update", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadConfig()
		if err != nil {
			return err
		}
		if cfg.Routing == nil {
			cmd.Println("No enabled presets.")
			return nil
		}
		copyPolicy := *cfg.Routing
		copyPolicy.Enabled = true
		dir, err := config.GetConfigDir()
		if err != nil {
			return err
		}
		_, warnings, err := routing.NewCache(filepath.Join(dir, "routing")).Prepare(cmd.Context(), &copyPolicy, true)
		for _, w := range warnings {
			cmd.PrintErrln("Warning:", w)
		}
		if err != nil {
			return errors.Join(errors.New("routing update failed; previous verified copies retained where available"), err)
		}
		cmd.Println("Routing lists updated. Restart VPN to apply changes.")
		return nil
	}})
	return root
}
func init() { rootCmd.AddCommand(newRoutingCommand()) }
