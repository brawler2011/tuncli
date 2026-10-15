package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigMigrationAndOperations(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("SUDO_USER", "")
	t.Setenv("DOAS_USER", "")

	// 1. Create a legacy config file to test migration
	configDir := filepath.Join(tempHome, ".config", "tuncli")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	legacyConfigData := `{
  "subscription_url": "https://example.com/legacy-sub",
  "mode": "tun",
  "selected_node_index": 1,
  "nodes": [
    {
      "name": "Node1",
      "protocol": "vless",
      "server": "1.1.1.1",
      "port": 443
    },
    {
      "name": "Node2",
      "protocol": "vmess",
      "server": "2.2.2.2",
      "port": 443
    }
  ]
}`
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.json"), []byte(legacyConfigData), 0644))

	// 2. Load config and verify migration
	cfg, err := LoadConfig()
	require.NoError(t, err)

	assert.Equal(t, "tun", cfg.Mode)

	require.Len(t, cfg.Subscriptions, 1)

	sub := cfg.Subscriptions[0]
	assert.Equal(t, "sub1", sub.ID)
	assert.Equal(t, "Default", sub.Name)
	assert.Equal(t, "https://example.com/legacy-sub", sub.URL)
	assert.Equal(t, "subscription", sub.Type)

	assert.Equal(t, "sub1", cfg.SelectedSubscription)

	assert.Equal(t, "Node2", cfg.SelectedNode)

	// Legacy fields should be cleared after migration
	assert.Empty(t, cfg.SubscriptionURL)
	require.Empty(t, cfg.Nodes)

	// Check if migrated nodes were saved to subscriptions/sub1.json
	nodes, err := LoadSubscriptionNodes("sub1")
	require.NoError(t, err)

	require.Len(t, nodes, 2)

	assert.Equal(t, "Node1", nodes[0].Name)
	assert.Equal(t, "Node2", nodes[1].Name)

	// 3. Test Save/Delete nodes
	newNode := Node{
		Name:     "ManualServer",
		Protocol: "trojan",
		Server:   "3.3.3.3",
		Port:     1080,
	}
	require.NoError(t, SaveSubscriptionNodes("srv1", []Node{newNode}))

	srvNodes, err := LoadSubscriptionNodes("srv1")
	require.NoError(t, err)
	require.Len(t, srvNodes, 1)
	assert.Equal(t, "ManualServer", srvNodes[0].Name)

	require.NoError(t, DeleteSubscriptionNodes("srv1"))

	srvNodesAfterDel, err := LoadSubscriptionNodes("srv1")
	require.NoError(t, err)
	require.Empty(t, srvNodesAfterDel)
}
