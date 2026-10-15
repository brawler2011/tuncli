package runner

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
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
				RawConfig: map[string]interface{}{
					"type":    "vless",
					"network": "splithttp",
				},
			},
			expected: true,
		},
		{
			name: "VLESS gRPC node",
			node: &config.Node{
				RawConfig: map[string]interface{}{
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
				RawConfig: map[string]interface{}{
					"type": "hysteria2",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsXHTTP(tt.node); got != tt.expected {
				t.Errorf("IsXHTTP() = %v, want %v", got, tt.expected)
			}
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
	if err != nil {
		t.Fatalf("GenerateXrayConfig failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(configBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated json: %v", err)
	}

	// 1. Verify Inbound
	inbounds, ok := parsed["inbounds"].([]interface{})
	if !ok || len(inbounds) == 0 {
		t.Fatal("inbounds missing or empty")
	}
	inbound := inbounds[0].(map[string]interface{})
	if inbound["protocol"] != "socks" {
		t.Errorf("expected inbound protocol 'socks', got %v", inbound["protocol"])
	}
	if inbound["listen"] != "127.0.0.1" {
		t.Errorf("expected inbound listen '127.0.0.1', got %v", inbound["listen"])
	}
	if int(inbound["port"].(float64)) != 10815 {
		t.Errorf("expected inbound port 10815, got %v", inbound["port"])
	}

	// 2. Verify Outbound
	outbounds, ok := parsed["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		t.Fatal("outbounds missing or empty")
	}
	outbound := outbounds[0].(map[string]interface{})
	if outbound["protocol"] != "vless" {
		t.Errorf("expected outbound protocol 'vless', got %v", outbound["protocol"])
	}

	streamSettings, ok := outbound["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatal("streamSettings missing")
	}

	if streamSettings["network"] != "xhttp" {
		t.Errorf("expected network 'xhttp', got %v", streamSettings["network"])
	}
	if streamSettings["security"] != "reality" {
		t.Errorf("expected security 'reality', got %v", streamSettings["security"])
	}

	// Check sockopt mark 354
	sockopt, ok := streamSettings["sockopt"].(map[string]interface{})
	if !ok {
		t.Fatal("sockopt missing")
	}
	if int(sockopt["mark"].(float64)) != 354 {
		t.Errorf("expected mark 354, got %v", sockopt["mark"])
	}

	// Check realitySettings
	reality, ok := streamSettings["realitySettings"].(map[string]interface{})
	if !ok {
		t.Fatal("realitySettings missing")
	}
	if reality["serverName"] != "example.com" {
		t.Errorf("expected serverName 'example.com', got %v", reality["serverName"])
	}
	if reality["publicKey"] != "g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg" {
		t.Errorf("expected publicKey, got %v", reality["publicKey"])
	}

	// Check xhttpSettings
	xhttp, ok := streamSettings["xhttpSettings"].(map[string]interface{})
	if !ok {
		t.Fatal("xhttpSettings missing")
	}
	if xhttp["path"] != "/xhttp" {
		t.Errorf("expected path '/xhttp', got %v", xhttp["path"])
	}
	if xhttp["mode"] != "stream-one" {
		t.Errorf("expected mode 'stream-one', got %v", xhttp["mode"])
	}
	if xhttp["host"] != "example.com" {
		t.Errorf("expected host 'example.com', got %v", xhttp["host"])
	}

	headers, ok := xhttp["headers"].(map[string]interface{})
	if !ok {
		t.Fatal("headers missing")
	}
	if headers["x-test-header"] != "warp" {
		t.Errorf("expected x-test-header 'warp', got %v", headers["x-test-header"])
	}
	if headers["x-test-priority"] != "0" {
		t.Errorf("expected x-test-priority '0', got %v", headers["x-test-priority"])
	}

	// If xray binary is installed, validate config with `xray run -test -c`
	if xrayPath, err := exec.LookPath("xray"); err == nil || xrayPath != "" {
		tmpFile, err := os.CreateTemp("", "xray-test-*.json")
		if err == nil {
			defer os.Remove(tmpFile.Name())
			tmpFile.Write(configBytes)
			tmpFile.Close()

			cmd := exec.Command(xrayPath, "run", "-test", "-c", tmpFile.Name())
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("xray validation failed: %v\nOutput:\n%s", err, string(out))
			}
		}
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
		os.Stderr.WriteString("synthetic xray failure\n")
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
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			os.Exit(5)
		}
		conn.Close()
		os.Stdout.WriteString("test connection\n")
	}
}

func fakeXray(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv("TUNCLI_XRAY_HELPER", mode)
	t.Setenv("TUNCLI_TEST_BINARY", os.Args[0])
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	path := filepath.Join(dir, "xray")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec \"$TUNCLI_TEST_BINARY\" -test.run=^TestXrayProcessHelper$ -- \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func xrayTestNode() *config.Node {
	return &config.Node{Protocol: "vless", Server: "192.0.2.1", Port: 443, RawConfig: map[string]interface{}{"type": "vless", "network": "xhttp", "uuid": "00000000-0000-4000-8000-000000000001"}}
}

func TestXrayLifecycleAndRepeatedStop(t *testing.T) {
	path := fakeXray(t, "serve")
	sidecar, err := startXraySidecar(xrayTestNode(), 0, path, false)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := 0
	sidecar.cleanupRule = func() { cleaned++ }
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			if err := sidecar.Stop(); err != nil {
				t.Errorf("Stop: %v", err)
			}
		})
	}
	wg.Wait()
	if cleaned != 1 {
		t.Fatalf("cleanup called %d times", cleaned)
	}
	select {
	case <-sidecar.done:
	default:
		t.Fatal("child not reaped")
	}
	if _, err := os.Stat(sidecar.ConfigFile); !os.IsNotExist(err) {
		t.Fatalf("temporary config remains: %v", err)
	}
}

func TestXrayStartupFailureCleansConfig(t *testing.T) {
	for _, mode := range []string{"exit", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			path := fakeXray(t, mode)
			_, err := startXraySidecar(xrayTestNode(), 0, path, false)
			if err == nil {
				t.Fatal("startup succeeded")
			}
			if mode == "exit" && !strings.Contains(err.Error(), "synthetic xray failure") {
				t.Fatalf("diagnostic lost: %v", err)
			}
			matches, err := filepath.Glob(filepath.Join(os.Getenv("TMPDIR"), "tuncli-xray-*.json"))
			if err != nil || len(matches) != 0 {
				t.Fatalf("config leak: %v, %v", matches, err)
			}
		})
	}
}

func TestGenerateXrayConfigTLSOptionsAndDefaultPath(t *testing.T) {
	for _, alpn := range []interface{}{"h2,http/1.1", []interface{}{"h2", "http/1.1"}, []string{"h2", "http/1.1"}} {
		node := xrayTestNode()
		node.RawConfig["security"] = "tls"
		node.RawConfig["alpn"] = alpn
		node.RawConfig["insecure"] = "1"
		data, err := GenerateXrayConfig(node, 10815, 0)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		stream := cfg["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
		tls := stream["tlsSettings"].(map[string]interface{})
		if tls["allowInsecure"] != true || len(tls["alpn"].([]interface{})) != 2 {
			t.Fatalf("TLS options lost: %v", tls)
		}
		if stream["xhttpSettings"].(map[string]interface{})["path"] != "/" {
			t.Fatal("wrong default path")
		}
		if _, ok := stream["sockopt"]; ok {
			t.Fatal("proxy mode needs no privileged socket options")
		}
	}
}
