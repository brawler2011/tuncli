package runner

import (
	"context"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

func TestBuildSingboxConfig_VLESS_gRPC(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:     "🇳🇱 Netherlands 2",
		Protocol: "vless",
		Server:   "192.0.2.1",
		Port:     443,
		RawConfig: map[string]interface{}{
			"client-fingerprint": "firefox",
			"grpc-opts": map[string]interface{}{
				"grpc-service-name": "Gun",
			},
			"name":            "🇳🇱 Netherlands 2",
			"network":         "grpc",
			"packet-encoding": "xudp",
			"port":            443,
			"reality-opts": map[string]interface{}{
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
	if err != nil {
		t.Fatalf("BuildSingboxConfig failed: %v", err)
	}

	if len(opts.Outbounds) < 2 {
		t.Fatalf("expected at least 2 outbounds, got %d", len(opts.Outbounds))
	}

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	if proxyOutbound == nil {
		t.Fatal("proxy outbound not found")
	}

	if proxyOutbound.Type != "vless" {
		t.Errorf("expected outbound type 'vless', got %q", proxyOutbound.Type)
	}

	vlessOpts, ok := proxyOutbound.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("expected VLESSOutboundOptions, got %T", proxyOutbound.Options)
	}

	if vlessOpts.Transport == nil || vlessOpts.Transport.Type != "grpc" {
		t.Errorf("expected transport type 'grpc', got %+v", vlessOpts.Transport)
	}
	if vlessOpts.Transport.GRPCOptions.ServiceName != "Gun" {
		t.Errorf("expected grpc service name 'Gun', got %q", vlessOpts.Transport.GRPCOptions.ServiceName)
	}
	if vlessOpts.TLS == nil || !vlessOpts.TLS.Enabled {
		t.Error("expected TLS to be enabled")
	} else if vlessOpts.TLS.Reality == nil || !vlessOpts.TLS.Reality.Enabled {
		t.Error("expected Reality to be enabled")
	}

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		t.Fatalf("box.New failed to initialize with gRPC node: %v", err)
	}
	defer instance.Close()
}

func TestBuildSingboxConfig_Hysteria2(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:     "🇩🇪 Germany Hysteria⚡",
		Protocol: "hysteria2",
		Server:   "192.0.2.1",
		Port:     443,
		RawConfig: map[string]interface{}{
			"alpn":               []interface{}{"h3"},
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
	if err != nil {
		t.Fatalf("BuildSingboxConfig failed: %v", err)
	}

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	if proxyOutbound == nil {
		t.Fatal("proxy outbound not found")
	}

	if proxyOutbound.Type != "hysteria2" {
		t.Errorf("expected outbound type 'hysteria2', got %q", proxyOutbound.Type)
	}

	hy2Opts, ok := proxyOutbound.Options.(*option.Hysteria2OutboundOptions)
	if !ok {
		t.Fatalf("expected Hysteria2OutboundOptions, got %T", proxyOutbound.Options)
	}

	if hy2Opts.Password != "00000000-0000-4000-8000-000000000001" {
		t.Errorf("unexpected password: %q", hy2Opts.Password)
	}
	if hy2Opts.TLS == nil || !hy2Opts.TLS.Enabled {
		t.Error("expected TLS to be enabled for hysteria2")
	} else {
		if hy2Opts.TLS.ServerName != "192.0.2.1" {
			t.Errorf("expected server name '192.0.2.1', got %q", hy2Opts.TLS.ServerName)
		}
		if len(hy2Opts.TLS.ALPN) == 0 || hy2Opts.TLS.ALPN[0] != "h3" {
			t.Errorf("expected ALPN ['h3'], got %v", hy2Opts.TLS.ALPN)
		}
	}
}

func TestBuildSingboxConfig_VMess_WebSocket(t *testing.T) {
	ctx := context.Background()
	ctx = singboxContext(ctx)

	node := &config.Node{
		Name:     "VMess WS Node",
		Protocol: "vmess",
		Server:   "ws.example.com",
		Port:     443,
		RawConfig: map[string]interface{}{
			"type":    "vmess",
			"server":  "ws.example.com",
			"port":    443,
			"uuid":    "00000000-0000-4000-8000-000000000001",
			"alterId": 0,
			"cipher":  "auto",
			"network": "ws",
			"ws-opts": map[string]interface{}{
				"path": "/ws-path",
				"headers": map[string]interface{}{
					"Host": "ws.example.com",
				},
			},
			"tls": true,
		},
	}

	opts, err := BuildSingboxConfig(ctx, node, "proxy")
	if err != nil {
		t.Fatalf("BuildSingboxConfig failed: %v", err)
	}

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	if proxyOutbound == nil {
		t.Fatal("proxy outbound not found")
	}

	if proxyOutbound.Type != "vmess" {
		t.Errorf("expected outbound type 'vmess', got %q", proxyOutbound.Type)
	}

	vmessOpts, ok := proxyOutbound.Options.(*option.VMessOutboundOptions)
	if !ok {
		t.Fatalf("expected VMessOutboundOptions, got %T", proxyOutbound.Options)
	}

	if vmessOpts.Transport == nil || vmessOpts.Transport.Type != "ws" {
		t.Errorf("expected transport 'ws', got %+v", vmessOpts.Transport)
	}
	if vmessOpts.Transport.WebsocketOptions.Path != "/ws-path" {
		t.Errorf("expected path '/ws-path', got %q", vmessOpts.Transport.WebsocketOptions.Path)
	}
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
		RawConfig: map[string]interface{}{
			"type":     "trojan",
			"server":   "trojan.example.com",
			"port":     443,
			"password": "secret-trojan-password",
			"sni":      "trojan.example.com",
		},
	}
	trojanOpts, err := BuildSingboxConfig(ctx, trojanNode, "proxy")
	if err != nil {
		t.Fatalf("BuildSingboxConfig for trojan failed: %v", err)
	}
	if trojanOpts.Outbounds[0].Type != "trojan" {
		t.Errorf("expected trojan, got %q", trojanOpts.Outbounds[0].Type)
	}

	// Shadowsocks
	ssNode := &config.Node{
		Name:     "SS Node",
		Protocol: "ss",
		Server:   "ss.example.com",
		Port:     8388,
		RawConfig: map[string]interface{}{
			"type":     "ss",
			"server":   "ss.example.com",
			"port":     8388,
			"cipher":   "aes-128-gcm",
			"password": "secret-ss-password",
		},
	}
	ssOpts, err := BuildSingboxConfig(ctx, ssNode, "proxy")
	if err != nil {
		t.Fatalf("BuildSingboxConfig for shadowsocks failed: %v", err)
	}
	if ssOpts.Outbounds[0].Type != "shadowsocks" {
		t.Errorf("expected shadowsocks, got %q", ssOpts.Outbounds[0].Type)
	}
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
	if err != nil {
		t.Fatalf("expected BuildSingboxConfig to succeed for xhttp transport, got: %v", err)
	}

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	if proxyOutbound == nil {
		t.Fatal("proxy outbound not found")
	}

	if proxyOutbound.Type != "socks" {
		t.Errorf("expected outbound type 'socks', got %q", proxyOutbound.Type)
	}

	socksOpts, ok := proxyOutbound.Options.(*option.SOCKSOutboundOptions)
	if !ok {
		t.Fatalf("expected SOCKSOutboundOptions, got %T", proxyOutbound.Options)
	}

	if socksOpts.Server != "127.0.0.1" {
		t.Errorf("expected server 127.0.0.1, got %q", socksOpts.Server)
	}
	if socksOpts.ServerPort != 10815 {
		t.Errorf("expected server port 10815, got %d", socksOpts.ServerPort)
	}
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
	if err != nil {
		t.Fatalf("BuildSingboxConfig failed for valid raw link: %v", err)
	}

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	if proxyOutbound == nil {
		t.Fatal("proxy outbound not found")
	}

	if proxyOutbound.Type != "vless" {
		t.Errorf("expected outbound type 'vless', got %q", proxyOutbound.Type)
	}

	vlessOpts, ok := proxyOutbound.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("expected VLESSOutboundOptions, got %T", proxyOutbound.Options)
	}

	if vlessOpts.UUID != "00000000-0000-4000-8000-000000000001" {
		t.Errorf("expected uuid, got %q", vlessOpts.UUID)
	}
	if vlessOpts.Flow != "xtls-rprx-vision" {
		t.Errorf("expected flow 'xtls-rprx-vision', got %q", vlessOpts.Flow)
	}
	if vlessOpts.TLS == nil || !vlessOpts.TLS.Enabled {
		t.Error("expected TLS enabled")
	}
	if vlessOpts.TLS.Reality == nil || !vlessOpts.TLS.Reality.Enabled {
		t.Error("expected Reality enabled")
	}
	if vlessOpts.TLS.Reality.PublicKey != "i09nP24-BerLPqI8-fwdXOIUOsCjYu5hPAt8-4L-wFU" {
		t.Errorf("expected reality public key, got %q", vlessOpts.TLS.Reality.PublicKey)
	}
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
	if err != nil {
		t.Fatalf("BuildSingboxConfig failed for raw ws link: %v", err)
	}

	var proxyOutbound *option.Outbound
	for i := range opts.Outbounds {
		if opts.Outbounds[i].Tag == "proxy" {
			proxyOutbound = &opts.Outbounds[i]
			break
		}
	}
	if proxyOutbound == nil {
		t.Fatal("proxy outbound not found")
	}

	vlessOpts, ok := proxyOutbound.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("expected VLESSOutboundOptions, got %T", proxyOutbound.Options)
	}

	if vlessOpts.Transport == nil || vlessOpts.Transport.Type != "ws" {
		t.Errorf("expected ws transport, got %+v", vlessOpts.Transport)
	}
	if vlessOpts.Transport.WebsocketOptions.Path != "/stream/updates/a72208a3" {
		t.Errorf("expected path '/stream/updates/a72208a3', got %q", vlessOpts.Transport.WebsocketOptions.Path)
	}
	if hostHeader, ok := vlessOpts.Transport.WebsocketOptions.Headers["Host"]; !ok || len(hostHeader) == 0 || hostHeader[0] != "192.0.2.1" {
		t.Errorf("expected Host header '192.0.2.1', got %v", vlessOpts.Transport.WebsocketOptions.Headers["Host"])
	}
}
