package runner

import (
	"context"
	"encoding/json"
	"maps"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/sub"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSingboxConfig_VLESS_gRPC(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:     "🇳🇱 Netherlands 2",
		Protocol: "vless",
		Server:   "192.0.2.1",
		Port:     443,
		RawConfig: map[string]any{
			"client-fingerprint": "firefox",
			"grpc-opts": map[string]any{
				"grpc-service-name": "Gun",
			},
			"name":            "🇳🇱 Netherlands 2",
			"network":         "grpc",
			"packet-encoding": "xudp",
			"port":            443,
			"reality-opts": map[string]any{
				"public-key": "NIS9cHp63_t_mxw1-zAwMktcjMXWI5hidvoFgk9i7kM",
				"short-id":   "34029c11d7fd539e",
			},
			"server":     "192.0.2.1",
			"servername": "192.0.2.1",
			"tls":        true,
			"type":       "vless",
			"udp":        true,
			"uuid":       "00000000-0000-4000-8000-000000000001",
		},
	}

	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(opts.Outbounds), 2)

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	require.NotNil(t, proxyOutbound)

	assert.Equal(t, "vless", proxyOutbound.Type)

	vlessOpts, ok := proxyOutbound.Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)

	require.NotNil(t, vlessOpts.Transport)
	assert.Equal(t, "grpc", vlessOpts.Transport.Type)
	assert.Equal(t, "Gun", vlessOpts.Transport.GRPCOptions.ServiceName)
	require.NotNil(t, vlessOpts.TLS)
	assert.True(t, vlessOpts.TLS.Enabled)
	require.NotNil(t, vlessOpts.TLS.Reality)
	assert.True(t, vlessOpts.TLS.Reality.Enabled)

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, instance.Close()) })
}

func TestBuildSingboxConfig_Hysteria2(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:     "🇩🇪 Germany Hysteria⚡",
		Protocol: "hysteria2",
		Server:   "192.0.2.1",
		Port:     443,
		RawConfig: map[string]any{
			"alpn":               []any{"h3"},
			"client-fingerprint": "chrome",
			"name":               "🇩🇪 Germany Hysteria⚡",
			"password":           "00000000-0000-4000-8000-000000000001",
			"port":               443,
			"server":             "192.0.2.1",
			"sni":                "192.0.2.1",
			"type":               "hysteria2",
			"udp":                true,
		},
	}

	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	require.NoError(t, err)

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	require.NotNil(t, proxyOutbound)

	assert.Equal(t, "hysteria2", proxyOutbound.Type)

	hy2Opts, ok := proxyOutbound.Options.(*option.Hysteria2OutboundOptions)
	require.True(t, ok)

	assert.Equal(t, "00000000-0000-4000-8000-000000000001", hy2Opts.Password)
	require.NotNil(t, hy2Opts.TLS)
	assert.True(t, hy2Opts.TLS.Enabled)
	assert.Equal(t, "192.0.2.1", hy2Opts.TLS.ServerName)
	require.NotEmpty(t, hy2Opts.TLS.ALPN)
	assert.Equal(t, "h3", hy2Opts.TLS.ALPN[0])
}

func TestBuildSingboxConfig_VMess_WebSocket(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:     "VMess WS Node",
		Protocol: "vmess",
		Server:   "ws.example.com",
		Port:     443,
		RawConfig: map[string]any{
			"type":    "vmess",
			"server":  "ws.example.com",
			"port":    443,
			"uuid":    "00000000-0000-4000-8000-000000000001",
			"alterId": 0,
			"cipher":  "auto",
			"network": "ws",
			"ws-opts": map[string]any{
				"path": "/ws-path",
				"headers": map[string]any{
					"Host": "ws.example.com",
				},
			},
			"tls": true,
		},
	}

	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	require.NoError(t, err)

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	require.NotNil(t, proxyOutbound)

	assert.Equal(t, "vmess", proxyOutbound.Type)

	vmessOpts, ok := proxyOutbound.Options.(*option.VMessOutboundOptions)
	require.True(t, ok)

	require.NotNil(t, vmessOpts.Transport)
	assert.Equal(t, "ws", vmessOpts.Transport.Type)
	assert.Equal(t, "/ws-path", vmessOpts.Transport.WebsocketOptions.Path)
}

func TestBuildSingboxConfig_TrojanAndShadowsocks(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	// Trojan
	trojanNode := &config.Node{
		Name:     "Trojan Node",
		Protocol: "trojan",
		Server:   "trojan.example.com",
		Port:     443,
		RawConfig: map[string]any{
			"type":     "trojan",
			"server":   "trojan.example.com",
			"port":     443,
			"password": "secret-trojan-password",
			"sni":      "trojan.example.com",
		},
	}
	trojanOpts, err := BuildSingboxConfig(ctx, trojanNode, "proxy")
	require.NoError(t, err)
	assert.Equal(t, "trojan", trojanOpts.Outbounds[0].Type)

	// Shadowsocks
	ssNode := &config.Node{
		Name:     "SS Node",
		Protocol: "ss",
		Server:   "ss.example.com",
		Port:     8388,
		RawConfig: map[string]any{
			"type":     "ss",
			"server":   "ss.example.com",
			"port":     8388,
			"cipher":   "aes-128-gcm",
			"password": "secret-ss-password",
		},
	}
	ssOpts, err := BuildSingboxConfig(ctx, ssNode, "proxy")
	require.NoError(t, err)
	assert.Equal(t, "shadowsocks", ssOpts.Outbounds[0].Type)
}

func TestBuildSingboxConfig_RawLink_VLESS_XHTTP_Sidecar(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:      "Gaming → [🎮 Игровой / Gemini]",
		Protocol:  "vless",
		Server:    "192.0.2.1",
		Port:      8443,
		RawLink:   "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:8443?type=xhttp&security=reality&sni=example.com&pbk=g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg&sid=96ce5c5b&fp=chrome&mode=stream-one&path=/xhttp#Gaming",
		RawConfig: nil,
	}

	opts, err := BuildSingboxConfig(ctx, node, "tun", 10815)
	require.NoError(t, err)

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	require.NotNil(t, proxyOutbound)

	assert.Equal(t, "socks", proxyOutbound.Type)

	socksOpts, ok := proxyOutbound.Options.(*option.SOCKSOutboundOptions)
	require.True(t, ok)

	assert.Equal(t, "127.0.0.1", socksOpts.Server)
	assert.Equal(t, uint16(10815), socksOpts.ServerPort)
}

func TestBuildSingboxConfig_RawLink_VLESS_Reality_TCP(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:      "Gate Reality",
		Protocol:  "vless",
		Server:    "192.0.2.2",
		Port:      444,
		RawLink:   "vless://00000000-0000-4000-8000-000000000001@192.0.2.2:444?type=tcp&encryption=none&security=reality&pbk=i09nP24-BerLPqI8-fwdXOIUOsCjYu5hPAt8-4L-wFU&fp=chrome&sni=example.org&sid=cd&flow=xtls-rprx-vision#gate",
		RawConfig: nil,
	}

	opts, err := BuildSingboxConfig(ctx, node, "tun")
	require.NoError(t, err)

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	require.NotNil(t, proxyOutbound)

	assert.Equal(t, "vless", proxyOutbound.Type)

	vlessOpts, ok := proxyOutbound.Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)

	assert.Equal(t, "00000000-0000-4000-8000-000000000001", vlessOpts.UUID)
	assert.Equal(t, "xtls-rprx-vision", vlessOpts.Flow)
	require.NotNil(t, vlessOpts.TLS)
	assert.True(t, vlessOpts.TLS.Enabled)
	require.NotNil(t, vlessOpts.TLS.Reality)
	assert.True(t, vlessOpts.TLS.Reality.Enabled)
	assert.Equal(t, "i09nP24-BerLPqI8-fwdXOIUOsCjYu5hPAt8-4L-wFU", vlessOpts.TLS.Reality.PublicKey)
}

func TestBuildSingboxConfig_RawLink_VLESS_WS(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:      "Finland 42 🇫🇮",
		Protocol:  "vless",
		Server:    "192.0.2.1",
		Port:      443,
		RawLink:   "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?type=ws&security=tls&sni=192.0.2.1&host=192.0.2.1&path=%2Fstream%2Fupdates%2Fa72208a3&fp=chrome&alpn=http%2F1.1&encryption=none#Finland",
		RawConfig: nil,
	}

	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	require.NoError(t, err)

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	require.NotNil(t, proxyOutbound)

	vlessOpts, ok := proxyOutbound.Options.(*option.VLESSOutboundOptions)
	require.True(t, ok)

	require.NotNil(t, vlessOpts.Transport)
	assert.Equal(t, "ws", vlessOpts.Transport.Type)
	assert.Equal(t, "/stream/updates/a72208a3", vlessOpts.Transport.WebsocketOptions.Path)
	hostHeader, ok := vlessOpts.Transport.WebsocketOptions.Headers["Host"]
	assert.True(t, ok)
	require.NotEmpty(t, hostHeader)
	assert.Equal(t, "192.0.2.1", hostHeader[0])
}

func TestNativeSingboxOutboundOptionsSurvive(t *testing.T) {
	ctx := singboxContext(context.Background())
	tls := map[string]any{"enabled": true, "server_name": "example.com", "alpn": []any{"http/1.1"}}
	raw := map[string]any{"type": "vless", "server": "192.0.2.1", "server_port": 443, "uuid": "00000000-0000-4000-8000-000000000001", "packet_encoding": "packetaddr", "tls": tls, "transport": map[string]any{"type": "ws", "path": "/test"}}
	node := &config.Node{Protocol: "vless", Server: "192.0.2.1", Port: 443, RawConfig: raw}
	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	require.NoError(t, err)
	v := opts.Outbounds[0].Options.(*option.VLESSOutboundOptions)
	require.NotNil(t, v.TLS)
	require.Equal(t, "example.com", v.TLS.ServerName)
	require.NotNil(t, v.Transport)
	require.Equal(t, "/test", v.Transport.WebsocketOptions.Path)
	require.NotNil(t, v.PacketEncoding)
	require.Equal(t, "packetaddr", *v.PacketEncoding)
	require.Nil(t, raw["tag"])
}

func TestShadowsocksPluginAndPacketEncodingSurvive(t *testing.T) {
	ctx := singboxContext(context.Background())
	for _, plugin := range []map[string]any{
		{"plugin": "v2ray-plugin;tls;host=example.com"},
		{"plugin": "v2ray-plugin", "plugin-opts": map[string]any{"tls": true, "host": "example.com"}},
	} {
		raw := map[string]any{"type": "ss", "server": "192.0.2.1", "port": 8388, "cipher": "aes-128-gcm", "password": "test-password"}
		maps.Copy(raw, plugin)
		opts, err := BuildSingboxConfig(ctx, &config.Node{Protocol: "ss", Server: "192.0.2.1", RawConfig: raw}, "proxy")
		require.NoError(t, err)
		ss := opts.Outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
		require.Equal(t, "v2ray-plugin", ss.Plugin)
		require.Contains(t, ss.PluginOptions, "host=example.com")
		require.Contains(t, ss.PluginOptions, "tls")
	}
	opts, err := BuildSingboxConfig(ctx, &config.Node{Protocol: "vless", Server: "192.0.2.1", RawConfig: map[string]any{"type": "vless", "server": "192.0.2.1", "port": 443, "uuid": "00000000-0000-4000-8000-000000000001", "packet-encoding": "xudp"}}, "proxy")
	require.NoError(t, err)
	v := opts.Outbounds[0].Options.(*option.VLESSOutboundOptions)
	require.NotNil(t, v.PacketEncoding)
	require.Equal(t, "xudp", *v.PacketEncoding)
}

func TestHysteriaAuthenticationAndBandwidth(t *testing.T) {
	ctx := singboxContext(context.Background())
	node := &config.Node{Protocol: "hysteria", Server: "192.0.2.1", RawLink: "hysteria://test-password@192.0.2.1:443?up=10&down=20&obfs=test-obfs"}
	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	require.NoError(t, err)
	hy := opts.Outbounds[0].Options.(*option.HysteriaOutboundOptions)
	require.Equal(t, "test-password", hy.AuthString)
	require.Equal(t, 10, hy.UpMbps)
	require.Equal(t, 20, hy.DownMbps)
	require.Equal(t, "test-obfs", hy.Obfs)
}

func TestBuilderRejectsInvalidInput(t *testing.T) {
	ctx := singboxContext(context.Background())
	_, err := BuildSingboxConfig(ctx, nil, "proxy")
	require.Error(t, err)
	_, err = BuildSingboxConfig(ctx, &config.Node{}, "invalid")
	require.Error(t, err)
}

func TestTUNDoesNotBlockQUICAndIPv6BypassIsHostRoute(t *testing.T) {
	ctx := singboxContext(context.Background())
	node := &config.Node{Protocol: "vless", Server: "2001:db8::1", RawConfig: map[string]any{"type": "vless", "server": "2001:db8::1", "port": 443, "uuid": "00000000-0000-4000-8000-000000000001"}}
	opts, err := BuildSingboxConfig(ctx, node, "tun")
	require.NoError(t, err)
	data, err := json.Marshal(opts)
	require.NoError(t, err)
	require.NotContains(t, string(data), `"reject"`)
	require.Contains(t, string(data), "2001:db8::1/128")
}

func TestParsedSubscriptionsRetainOptions(t *testing.T) {
	ctx := singboxContext(context.Background())
	for _, tc := range []struct{ name, body string }{
		{"singbox", `{"outbounds":[{"type":"vless","tag":"test","server":"192.0.2.1","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"server_name":"example.com"},"transport":{"type":"ws","path":"/test","max_early_data":2048}}]}`},
		{"clash", "proxies:\n  - name: test\n    type: vless\n    server: 192.0.2.1\n    port: 443\n    uuid: 00000000-0000-4000-8000-000000000001\n    tls: true\n    servername: example.com\n    network: ws\n    ws-opts:\n      path: /test\n      max-early-data: 2048\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := sub.ParseBody(tc.body)
			require.NoError(t, err)
			require.Len(t, nodes, 1)
			n := nodes[0]
			opts, err := BuildSingboxConfig(ctx, &config.Node{Name: n.Name, Protocol: n.Protocol, Server: n.Server, Port: n.Port, RawConfig: n.RawConfig}, "proxy")
			require.NoError(t, err)
			v := opts.Outbounds[0].Options.(*option.VLESSOutboundOptions)
			require.NotNil(t, v.TLS)
			require.Equal(t, "example.com", v.TLS.ServerName)
			require.NotNil(t, v.Transport)
			require.Equal(t, "/test", v.Transport.WebsocketOptions.Path)
			require.Equal(t, uint32(2048), v.Transport.WebsocketOptions.MaxEarlyData)
		})
	}
}

func TestClashObfsPluginCanInitialize(t *testing.T) {
	ctx := singboxContext(context.Background())
	node := &config.Node{Protocol: "ss", Server: "192.0.2.1", RawConfig: map[string]any{"type": "ss", "server": "192.0.2.1", "port": 8388, "cipher": "aes-128-gcm", "password": "test-password", "plugin": "obfs", "plugin-opts": map[string]any{"mode": "tls", "host": "example.com"}}}
	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	require.NoError(t, err)
	ss := opts.Outbounds[0].Options.(*option.ShadowsocksOutboundOptions)
	require.Equal(t, "obfs-local", ss.Plugin)
	require.Equal(t, "obfs-host=example.com;obfs=tls", ss.PluginOptions)
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, instance.Close()) })
}
