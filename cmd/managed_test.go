package cmd

import (
	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestServiceCommandWhitelistAndFreshFlags(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	t.Setenv("DOAS_USER", "")
	daemonProcess = true
	t.Cleanup(func() { daemonProcess = false })
	for _, args := range [][]string{{"run"}, {"daemon"}, {"service", "recover"}, {"routing", "unknown"}, {"add"}, {"routing", "rule", "add", "example.com"}} {
		_, err := serviceCommand(args)
		require.Error(t, err)
	}
	_, err := serviceCommand([]string{"routing", "rule", "add", "example.com", "--outbound=direct", "--suffix=true"})
	require.NoError(t, err)
	_, err = serviceCommand([]string{"routing", "rule", "add", "second.example", "--outbound=vpn"})
	require.NoError(t, err)
	cfg, err := config.LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.Routing.Rules, 2)
	require.True(t, cfg.Routing.Rules[0].Suffix)
	require.False(t, cfg.Routing.Rules[1].Suffix)
}
