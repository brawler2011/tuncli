package runner

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsXHTTP(t *testing.T) {
	tests := []struct {
		name     string
		node     *config.Node
		expected bool
	}{
		{
			name: "VLESS Reality XHTTP raw link",
			node: &config.Node{
				RawLink: "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:8443?type=xhttp&security=reality#Gaming",
			},
			expected: true,
		},
		{
			name: "SplitHTTP raw config",
			node: &config.Node{
				RawConfig: map[string]any{
					"type":    "vless",
					"network": "splithttp",
				},
			},
			expected: true,
		},
		{
			name: "VLESS gRPC node",
			node: &config.Node{
				RawConfig: map[string]any{
					"type":    "vless",
					"network": "grpc",
				},
			},
			expected: false,
		},
		{
			name: "VLESS TCP Reality",
			node: &config.Node{
				RawLink: "vless://00000000-0000-4000-8000-000000000001@192.0.2.2:444?type=tcp&security=reality#Gate",
			},
			expected: false,
		},
		{
			name: "Hysteria2 node",
			node: &config.Node{
				Protocol: "hysteria2",
				RawConfig: map[string]any{
					"type": "hysteria2",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsXHTTP(tt.node)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestGenerateXrayConfig(t *testing.T) {
	node := &config.Node{
		Name:     "Gaming → [🎮 Игровой / Gemini]",
		Protocol: "vless",
		Server:   "192.0.2.1",
		Port:     8443,
		RawLink:  "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:8443?type=xhttp&security=reality&sni=example.com&pbk=g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg&sid=96ce5c5b&fp=chrome&mode=stream-one&path=/xhttp&concurrency=4&x-test-header=warp&x-test-priority=0#Gaming",
	}

	configBytes, err := GenerateXrayConfig(node, 10815)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(configBytes, &parsed))

	// 1. Verify Inbound
	inbounds, ok := parsed["inbounds"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, inbounds)
	inbound := inbounds[0].(map[string]any)
	assert.Equal(t, "socks", inbound["protocol"])
	assert.Equal(t, "127.0.0.1", inbound["listen"])
	assert.Equal(t, 10815, int(inbound["port"].(float64)))

	// 2. Verify Outbound
	outbounds, ok := parsed["outbounds"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, outbounds)
	outbound := outbounds[0].(map[string]any)
	assert.Equal(t, "vless", outbound["protocol"])

	streamSettings, ok := outbound["streamSettings"].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "xhttp", streamSettings["network"])
	assert.Equal(t, "reality", streamSettings["security"])

	// Check sockopt mark 354
	sockopt, ok := streamSettings["sockopt"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 354, int(sockopt["mark"].(float64)))

	// Check realitySettings
	reality, ok := streamSettings["realitySettings"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "example.com", reality["serverName"])
	assert.Equal(t, "g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg", reality["publicKey"])

	// Check xhttpSettings
	xhttp, ok := streamSettings["xhttpSettings"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "/xhttp", xhttp["path"])
	assert.Equal(t, "stream-one", xhttp["mode"])
	assert.Equal(t, "example.com", xhttp["host"])

	headers, ok := xhttp["headers"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "warp", headers["x-test-header"])
	assert.Equal(t, "0", headers["x-test-priority"])

	// If xray binary is installed, validate config with `xray run -test -c`
	if xrayPath, err := exec.LookPath("xray"); err == nil {
		path := filepath.Join(t.TempDir(), "xray.json")
		require.NoError(t, os.WriteFile(path, configBytes, 0600))
		cmd := exec.Command(xrayPath, "run", "-test", "-c", path)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "xray validation output: %s", out)
	}
}

func TestGetDefaultInterface(t *testing.T) {
	iface := GetDefaultInterface()
	// On machines with active network, iface should be detected
	if iface != "" {
		t.Logf("Detected default interface: %s", iface)
	}
}

func TestXrayProcessHelper(t *testing.T) {
	mode := os.Getenv("TUNCLI_XRAY_HELPER")
	if mode == "" {
		return
	}
	if mode == "exit" {
		_, _ = os.Stderr.WriteString("synthetic xray failure\n")
		os.Exit(7)
	}
	if mode == "timeout" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	var path string
	for i, arg := range os.Args {
		if arg == "-c" && i+1 < len(os.Args) {
			path = os.Args[i+1]
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		os.Exit(2)
	}
	var cfg struct {
		Inbounds []struct {
			Port int `json:"port"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(data, &cfg) != nil || len(cfg.Inbounds) != 1 {
		os.Exit(3)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.Inbounds[0].Port))
	if err != nil {
		os.Exit(4)
	}
	defer func() { _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			os.Exit(5)
		}
		require.NoError(t, conn.Close())
		_, err = os.Stdout.WriteString("test connection\n")
		require.NoError(t, err)
	}
}

func fakeXray(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv("TUNCLI_XRAY_HELPER", mode)
	t.Setenv("TUNCLI_TEST_BINARY", os.Args[0])
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	path := filepath.Join(dir, "xray")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexec \"$TUNCLI_TEST_BINARY\" -test.run=^TestXrayProcessHelper$ -- \"$@\"\n"), 0700))
	return path
}

func xrayTestNode() *config.Node {
	return &config.Node{Protocol: "vless", Server: "192.0.2.1", Port: 443, RawConfig: map[string]any{"type": "vless", "network": "xhttp", "uuid": "00000000-0000-4000-8000-000000000001"}}
}

func TestXrayLifecycleAndRepeatedStop(t *testing.T) {
	path := fakeXray(t, "serve")
	sidecar, err := startXraySidecar(xrayTestNode(), 0, path, false)
	require.NoError(t, err)
	cleaned := 0
	sidecar.cleanupRule = func() { cleaned++ }
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			assert.NoError(t, sidecar.Stop())
		})
	}
	wg.Wait()
	require.Equal(t, 1, cleaned)
	select {
	case <-sidecar.done:
	default:
		t.Fatal("child not reaped")
	}
	assert.NoFileExists(t, sidecar.ConfigFile)
}

func TestXrayStartupFailureCleansConfig(t *testing.T) {
	for _, mode := range []string{"exit", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			path := fakeXray(t, mode)
			_, err := startXraySidecar(xrayTestNode(), 0, path, false)
			require.Error(t, err)
			if mode == "exit" {
				require.ErrorContains(t, err, "synthetic xray failure")
			}
			matches, err := filepath.Glob(filepath.Join(os.Getenv("TMPDIR"), "tuncli-xray-*.json"))
			require.NoError(t, err)
			require.Empty(t, matches)
		})
	}
}

func TestGenerateXrayConfigTLSOptionsAndDefaultPath(t *testing.T) {
	for _, alpn := range []any{"h2,http/1.1", []any{"h2", "http/1.1"}, []string{"h2", "http/1.1"}} {
		node := xrayTestNode()
		node.RawConfig["security"] = "tls"
		node.RawConfig["alpn"] = alpn
		node.RawConfig["insecure"] = "1"
		data, err := GenerateXrayConfig(node, 10815, 0)
		require.NoError(t, err)
		var cfg map[string]any
		require.NoError(t, json.Unmarshal(data, &cfg))
		stream := cfg["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
		tls := stream["tlsSettings"].(map[string]any)
		require.Equal(t, true, tls["allowInsecure"])
		require.Len(t, tls["alpn"].([]any), 2)
		require.Equal(t, "/", stream["xhttpSettings"].(map[string]any)["path"])
		_, ok := stream["sockopt"]
		require.False(t, ok)
	}
}
