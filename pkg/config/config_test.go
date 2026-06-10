package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigMigrationAndOperations(t *testing.T) {
	// Set up temporary HOME directory
	tempHome, err := os.MkdirTemp("", "tuncli-test-home-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	// Override HOME environment variable for the test
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	// 1. Create a legacy config file to test migration
	configDir := filepath.Join(tempHome, ".config", "tuncli")
	err = os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

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
	err = os.WriteFile(filepath.Join(configDir, "config.json"), []byte(legacyConfigData), 0644)
	if err != nil {
		t.Fatalf("failed to write legacy config: %v", err)
	}

	// 2. Load config and verify migration
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Mode != "tun" {
		t.Errorf("expected Mode 'tun', got %q", cfg.Mode)
	}

	if len(cfg.Subscriptions) != 1 {
		t.Fatalf("expected 1 subscription item, got %d", len(cfg.Subscriptions))
	}

	sub := cfg.Subscriptions[0]
	if sub.ID != "sub1" || sub.Name != "Default" || sub.URL != "https://example.com/legacy-sub" || sub.Type != "subscription" {
		t.Errorf("unexpected subscription details: %+v", sub)
	}

	if cfg.SelectedSubscription != "sub1" {
		t.Errorf("expected SelectedSubscription 'sub1', got %q", cfg.SelectedSubscription)
	}

	if cfg.SelectedNode != "Node2" {
		t.Errorf("expected SelectedNode 'Node2', got %q", cfg.SelectedNode)
	}

	// Legacy fields should be cleared after migration
	if cfg.SubscriptionURL != "" {
		t.Errorf("expected SubscriptionURL to be cleared, got %q", cfg.SubscriptionURL)
	}
	if len(cfg.Nodes) != 0 {
		t.Errorf("expected Nodes to be cleared, got %d items", len(cfg.Nodes))
	}

	// Check if migrated nodes were saved to subscriptions/sub1.json
	nodes, err := LoadSubscriptionNodes("sub1")
	if err != nil {
		t.Fatalf("failed to load sub1 nodes: %v", err)
	}

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	if nodes[0].Name != "Node1" || nodes[1].Name != "Node2" {
		t.Errorf("unexpected node names: %q, %q", nodes[0].Name, nodes[1].Name)
	}

	// 3. Test Save/Delete nodes
	newNode := Node{
		Name:     "ManualServer",
		Protocol: "trojan",
		Server:   "3.3.3.3",
		Port:     1080,
	}
	err = SaveSubscriptionNodes("srv1", []Node{newNode})
	if err != nil {
		t.Fatalf("failed to save srv1 nodes: %v", err)
	}

	srvNodes, err := LoadSubscriptionNodes("srv1")
	if err != nil {
		t.Fatalf("failed to load srv1 nodes: %v", err)
	}
	if len(srvNodes) != 1 || srvNodes[0].Name != "ManualServer" {
		t.Errorf("unexpected srv1 nodes: %+v", srvNodes)
	}

	err = DeleteSubscriptionNodes("srv1")
	if err != nil {
		t.Fatalf("failed to delete srv1 nodes: %v", err)
	}

	srvNodesAfterDel, err := LoadSubscriptionNodes("srv1")
	if err != nil {
		t.Fatalf("failed to load srv1 nodes after delete: %v", err)
	}
	if len(srvNodesAfterDel) != 0 {
		t.Errorf("expected 0 nodes after delete, got %d", len(srvNodesAfterDel))
	}
}
