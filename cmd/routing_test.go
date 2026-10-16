package cmd

import (
	"bytes"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutingCommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
	t.Setenv("DOAS_USER", "")
	run := func(args ...string) string {
		t.Helper()
		c := newRoutingCommand()
		buf := new(bytes.Buffer)
		c.SetOut(buf)
		c.SetErr(buf)
		c.SetArgs(args)
		require.NoError(t, c.Execute())
		return buf.String()
	}
	run("preset", "enable", "ru", "--outbound", "direct")
	run("preset", "enable", "ai", "--outbound", "vpn")
	run("rule", "add", "MY.ITMO.RU.", "--outbound", "direct")
	run("rule", "add", "my.itmo.ru", "--outbound", "vpn")
	run("rule", "add", "example.com", "--suffix", "--outbound", "direct")
	run("default", "direct")
	run("disable")
	cfg, err := config.LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg.Routing)
	assert.False(t, cfg.Routing.Enabled)
	assert.Len(t, cfg.Routing.Presets, 2)
	assert.Len(t, cfg.Routing.Rules, 2)
	assert.Equal(t, routing.VPN, cfg.Routing.Rules[0].Outbound)
	run("enable")
	run("preset", "disable", "ru")
	run("rule", "remove", "my.itmo.ru")
	run("rule", "remove", "example.com", "--suffix")
	output := run("show")
	assert.Contains(t, output, "Enabled: true")
	assert.Contains(t, output, "Default: direct")
	assert.Contains(t, output, routing.BaseURL)
	cfg, err = config.LoadConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.Routing.Rules)
	assert.Equal(t, map[string]routing.Outbound{"ai": routing.VPN}, cfg.Routing.Presets)
	for _, args := range [][]string{{"preset", "enable", "unknown"}, {"default", "invalid"}, {"rule", "add", "*.ru", "--outbound", "direct"}, {"rule", "add", "example.com"}} {
		c := newRoutingCommand()
		c.SetOut(new(bytes.Buffer))
		c.SetErr(new(bytes.Buffer))
		c.SetArgs(args)
		assert.Error(t, c.Execute())
	}
}
