package sub

import (
	"encoding/base64"
	"testing"
)

func TestParseSingleURI_VLESS(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:8443?type=xhttp&security=reality&sni=example.com&pbk=g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg&sid=96ce5c5b&fp=chrome&mode=stream-one&path=/xhttp&concurrency=4#Gaming%20Node"

	node, err := ParseSingleURI(link)
	if err != nil {
		t.Fatalf("ParseSingleURI failed: %v", err)
	}

	if node.Name != "Gaming Node" {
		t.Errorf("expected name 'Gaming Node', got %q", node.Name)
	}
	if node.Protocol != "vless" {
		t.Errorf("expected protocol 'vless', got %q", node.Protocol)
	}
	if node.Server != "192.0.2.1" {
		t.Errorf("expected server '192.0.2.1', got %q", node.Server)
	}
	if node.Port != 8443 {
		t.Errorf("expected port 8443, got %d", node.Port)
	}
	if node.RawConfig == nil {
		t.Fatal("expected RawConfig to not be nil")
	}
	if node.RawConfig["uuid"] != "00000000-0000-4000-8000-000000000001" {
		t.Errorf("expected uuid in RawConfig, got %v", node.RawConfig["uuid"])
	}
	if node.RawConfig["security"] != "reality" {
		t.Errorf("expected security 'reality', got %v", node.RawConfig["security"])
	}
	if node.RawConfig["pbk"] != "g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg" {
		t.Errorf("expected pbk in RawConfig, got %v", node.RawConfig["pbk"])
	}
}

func TestParseSingleURI_VMess(t *testing.T) {
	vmessJSON := `{"add":"vmess.example.com","port":443,"id":"12345678-1234-1234-1234-123456789abc","aid":0,"scy":"auto","net":"ws","type":"none","host":"vmess.example.com","path":"/ws","tls":"tls","sni":"vmess.example.com","ps":"VMess Test"}`
	b64 := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	link := "vmess://" + b64

	node, err := ParseSingleURI(link)
	if err != nil {
		t.Fatalf("ParseSingleURI failed: %v", err)
	}

	if node.Name != "VMess Test" {
		t.Errorf("expected name 'VMess Test', got %q", node.Name)
	}
	if node.Protocol != "vmess" {
		t.Errorf("expected protocol 'vmess', got %q", node.Protocol)
	}
	if node.Server != "vmess.example.com" {
		t.Errorf("expected server 'vmess.example.com', got %q", node.Server)
	}
	if node.Port != 443 {
		t.Errorf("expected port 443, got %d", node.Port)
	}
	if node.RawConfig["uuid"] != "12345678-1234-1234-1234-123456789abc" {
		t.Errorf("expected uuid in RawConfig, got %v", node.RawConfig["uuid"])
	}
	if node.RawConfig["network"] != "ws" {
		t.Errorf("expected network 'ws', got %v", node.RawConfig["network"])
	}
}

func TestParseSingleURI_Trojan(t *testing.T) {
	link := "trojan://my-password@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Ftrojan-ws#Trojan%20Test"

	node, err := ParseSingleURI(link)
	if err != nil {
		t.Fatalf("ParseSingleURI failed: %v", err)
	}

	if node.Name != "Trojan Test" {
		t.Errorf("expected name 'Trojan Test', got %q", node.Name)
	}
	if node.Protocol != "trojan" {
		t.Errorf("expected protocol 'trojan', got %q", node.Protocol)
	}
	if node.RawConfig["password"] != "my-password" {
		t.Errorf("expected password in RawConfig, got %v", node.RawConfig["password"])
	}
	if node.RawConfig["path"] != "/trojan-ws" {
		t.Errorf("expected path '/trojan-ws', got %v", node.RawConfig["path"])
	}
}

func TestParseSingleURI_Shadowsocks(t *testing.T) {
	userInfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:my-secret"))
	link := "ss://" + userInfo + "@ss.example.com:8388#SS%20Node"

	node, err := ParseSingleURI(link)
	if err != nil {
		t.Fatalf("ParseSingleURI failed: %v", err)
	}

	if node.Name != "SS Node" {
		t.Errorf("expected name 'SS Node', got %q", node.Name)
	}
	if node.Protocol != "shadowsocks" {
		t.Errorf("expected protocol 'shadowsocks', got %q", node.Protocol)
	}
	if node.RawConfig["cipher"] != "aes-256-gcm" {
		t.Errorf("expected cipher 'aes-256-gcm', got %v", node.RawConfig["cipher"])
	}
	if node.RawConfig["password"] != "my-secret" {
		t.Errorf("expected password 'my-secret', got %v", node.RawConfig["password"])
	}
}

func TestParseSingleURI_Hysteria2(t *testing.T) {
	link := "hysteria2://my-auth@hy2.example.com:443?sni=hy2.example.com&insecure=1#Hy2%20Node"

	node, err := ParseSingleURI(link)
	if err != nil {
		t.Fatalf("ParseSingleURI failed: %v", err)
	}

	if node.Name != "Hy2 Node" {
		t.Errorf("expected name 'Hy2 Node', got %q", node.Name)
	}
	if node.Protocol != "hysteria2" {
		t.Errorf("expected protocol 'hysteria2', got %q", node.Protocol)
	}
	if node.RawConfig["password"] != "my-auth" {
		t.Errorf("expected password 'my-auth', got %v", node.RawConfig["password"])
	}
	if node.RawConfig["skip-cert-verify"] != true {
		t.Errorf("expected skip-cert-verify true, got %v", node.RawConfig["skip-cert-verify"])
	}
}

func TestURIPathIsDecodedExactlyOnce(t *testing.T) {
	node, err := ParseSingleURI("vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?type=ws&path=%2Fone%252Ftwo%2Bthree")
	if err != nil {
		t.Fatal(err)
	}
	if got := node.RawConfig["path"]; got != "/one%2Ftwo+three" {
		t.Fatalf("path changed: %v", got)
	}
}

func TestShadowsocksSIP002PluginAndTrailingSlash(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:test-password"))
	node, err := ParseSingleURI("ss://" + userInfo + "@[2001:db8::1]:8388/?plugin=v2ray-plugin%3Btls%3Bhost%3Dexample.com#Test")
	if err != nil {
		t.Fatal(err)
	}
	if node.Server != "2001:db8::1" || node.Port != 8388 || node.RawConfig["plugin"] != "v2ray-plugin;tls;host=example.com" {
		t.Fatalf("unexpected node: %+v", node)
	}
}

func TestHysteria2PreservesColonInAuthentication(t *testing.T) {
	node, err := ParseSingleURI("hy2://test-user:test-password@192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if node.RawConfig["password"] != "test-user:test-password" {
		t.Fatalf("authentication changed: %v", node.RawConfig["password"])
	}
}
