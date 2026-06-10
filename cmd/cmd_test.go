package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
)

func TestCommands(t *testing.T) {
	// Setup temporary HOME for config isolation
	tempHome, err := os.MkdirTemp("", "tuncli-cmd-test-*")
	if err != nil {
		t.Fatalf("failed to create temp home: %v", err)
	}
	defer os.RemoveAll(tempHome)

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tempHome)
	defer os.Setenv("HOME", origHome)

	// Create sub directory
	configDir := filepath.Join(tempHome, ".config", "tuncli")
	err = os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	// 1. Test "add" command with a direct URI
	rootCmd.SetArgs([]string{"add", "vless://123456@1.1.1.1:443?encryption=none#TestVPS"})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("execute add command failed: %v", err)
	}

	// Verify it was added to config
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if len(cfg.Subscriptions) != 1 {
		t.Fatalf("expected 1 item, got %d", len(cfg.Subscriptions))
	}

	item := cfg.Subscriptions[0]
	if item.ID != "srv1" || item.Name != "TestVPS" || item.Type != "server" {
		t.Errorf("unexpected added item: %+v", item)
	}

	// Verify cached node was saved
	nodes, err := config.LoadSubscriptionNodes("srv1")
	if err != nil {
		t.Fatalf("failed to load srv1 nodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "TestVPS" {
		t.Errorf("unexpected cached node: %+v", nodes)
	}

	// 2. Test "list" command
	buf.Reset()
	rootCmd.SetArgs([]string{"list"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("execute list command failed: %v", err)
	}

	listOut := buf.String()
	t.Logf("list output:\n%s", listOut)

	// List output should contain ID srv1 and Name TestVPS
	if !bytes.Contains(buf.Bytes(), []byte("srv1")) || !bytes.Contains(buf.Bytes(), []byte("TestVPS")) {
		t.Errorf("expected list output to contain srv1 and TestVPS")
	}

	// 3. Test "remove" command
	buf.Reset()
	rootCmd.SetArgs([]string{"remove", "srv1"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("execute remove command failed: %v", err)
	}

	// Verify config and files after removal
	cfg, err = config.LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if len(cfg.Subscriptions) != 0 {
		t.Errorf("expected 0 items in config, got %d", len(cfg.Subscriptions))
	}

	nodes, err = config.LoadSubscriptionNodes("srv1")
	if err != nil {
		t.Fatalf("failed to load srv1 nodes after remove: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 cached nodes after remove, got %d", len(nodes))
	}
}
