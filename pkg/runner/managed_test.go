package runner

import (
	"context"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestManagedMarksAndBootstrap(t *testing.T) {
	for _, mode := range []string{"tun", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			node := &config.Node{Name: "test", Protocol: "shadowsocks", Server: "192.0.2.1", Port: 443, RawConfig: map[string]any{"type": "ss", "server": "192.0.2.1", "port": 443, "cipher": "aes-128-gcm", "password": "test"}}
			options, err := BuildSingboxConfigWithPolicy(singboxContext(context.Background()), node, mode, &routing.Prepared{Managed: true})
			require.NoError(t, err)
			marks := map[string]option.FwMark{}
			for _, out := range options.Outbounds {
				dialer, ok := out.Options.(option.DialerOptionsWrapper)
				require.True(t, ok)
				marks[out.Tag] = dialer.TakeDialerOptions().RoutingMark
			}
			require.Equal(t, option.FwMark(TransportMark), marks["proxy"])
			require.Equal(t, option.FwMark(DirectMark), marks["direct"])
			require.Equal(t, option.FwMark(BootstrapMark), marks["bootstrap"])
		})
	}
}
func TestManagedRejectsFileAndMarkOverrides(t *testing.T) {
	for _, key := range []string{"certificate_path", "key_path", "routing_mark", "detour", "bind_interface", "protect_path"} {
		require.Error(t, validateManagedFields(map[string]any{"tls": map[string]any{key: "unsafe"}}))
	}
	require.NoError(t, validateManagedFields(map[string]any{"transport": map[string]any{"path": "/websocket"}}))
	node := &config.Node{Server: "192.0.2.1", RawConfig: map[string]any{"type": "direct", "server_port": 443}}
	_, err := BuildSingboxConfigWithPolicy(singboxContext(context.Background()), node, "tun", &routing.Prepared{Managed: true})
	require.ErrorContains(t, err, "unsupported managed")
}
