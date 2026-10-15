package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommands(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("SUDO_USER", "")
	t.Setenv("DOAS_USER", "")

	// Create sub directory
	configDir := filepath.Join(tempHome, ".config", "tuncli")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	// 1. Test "add" command with a direct URI
	rootCmd.SetArgs([]string{"add", "vless://123456@1.1.1.1:443?encryption=none#TestVPS"})

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	require.NoError(t, rootCmd.Execute())

	// Verify it was added to config
	cfg, err := config.LoadConfig()
	require.NoError(t, err)

	require.Len(t, cfg.Subscriptions, 1)

	item := cfg.Subscriptions[0]
	assert.Equal(t, "srv1", item.ID)
	assert.Equal(t, "TestVPS", item.Name)
	assert.Equal(t, "server", item.Type)

	// Verify cached node was saved
	nodes, err := config.LoadSubscriptionNodes("srv1")
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "TestVPS", nodes[0].Name)

	// 2. Test "list" command
	buf.Reset()
	rootCmd.SetArgs([]string{"list"})
	require.NoError(t, rootCmd.Execute())

	listOut := buf.String()
	t.Logf("list output:\n%s", listOut)

	// List output should contain ID srv1 and Name TestVPS
	assert.Contains(t, buf.String(), "srv1")
	assert.Contains(t, buf.String(), "TestVPS")

	// 3. Test "remove" command
	buf.Reset()
	rootCmd.SetArgs([]string{"remove", "srv1"})
	require.NoError(t, rootCmd.Execute())

	// Verify config and files after removal
	cfg, err = config.LoadConfig()
	require.NoError(t, err)
	require.Empty(t, cfg.Subscriptions)

	nodes, err = config.LoadSubscriptionNodes("srv1")
	require.NoError(t, err)
	require.Empty(t, nodes)
}
