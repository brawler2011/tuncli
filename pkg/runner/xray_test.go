package runner

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"

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
