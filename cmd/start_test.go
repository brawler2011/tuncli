package cmd

import (
	"os"
	"reflect"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
)

func TestStartOverrides(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	t.Setenv("DOAS_USER", "")
	for id, names := range map[string][]string{"first": {"Shared", "Only first"}, "selected": {"Shared", "Only selected"}} {
		var nodes []config.Node
		for _, name := range names {
			nodes = append(nodes, config.Node{Name: name})
		}
		if err := config.SaveSubscriptionNodes(id, nodes); err != nil {
			t.Fatal(err)
		}
	}
	initial := config.Config{Mode: "tun", SelectedSubscription: "selected", SelectedNode: "Only selected", Subscriptions: []config.SubscriptionItem{{ID: "first"}, {ID: "selected"}}}
	if err := config.SaveConfig(&initial); err != nil {
		t.Fatal(err)
	}
	path, err := config.GetConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode, node, wantSub, wantNode, wantMode string
		wantErr                                 bool
	}{
		{"", "", "selected", "Only selected", "tun", false},
		{"proxy", "Shared", "selected", "Shared", "proxy", false},
		{"tun", "Only first", "first", "Only first", "tun", false},
		{"invalid", "", "", "", "", true},
		{"", "Missing", "", "", "", true},
	} {
		t.Run(tc.mode+"/"+tc.node, func(t *testing.T) {
			cfg := initial
			err := applyStartOverrides(&cfg, tc.mode, tc.node)
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr && (cfg.Mode != tc.wantMode || cfg.SelectedSubscription != tc.wantSub || cfg.SelectedNode != tc.wantNode) {
				t.Fatalf("wrong overrides: %+v", cfg)
			}
		})
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("saved selection changed")
	}
}
