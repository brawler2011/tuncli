package cmd

import (
	"os"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		require.NoError(t, config.SaveSubscriptionNodes(id, nodes))
	}
	initial := config.Config{Mode: "tun", SelectedSubscription: "selected", SelectedNode: "Only selected", Subscriptions: []config.SubscriptionItem{{ID: "first"}, {ID: "selected"}}}
	require.NoError(t, config.SaveConfig(&initial))
	path, err := config.GetConfigPath()
	require.NoError(t, err)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
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
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantMode, cfg.Mode)
			assert.Equal(t, tc.wantSub, cfg.SelectedSubscription)
			assert.Equal(t, tc.wantNode, cfg.SelectedNode)
		})
	}
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
