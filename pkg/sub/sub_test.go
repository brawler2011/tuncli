package sub

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSingleURI_VLESS(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:8443?type=xhttp&security=reality&sni=example.com&pbk=g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg&sid=96ce5c5b&fp=chrome&mode=stream-one&path=/xhttp&concurrency=4#Gaming%20Node"

	node, err := ParseSingleURI(link)
	require.NoError(t, err)

	assert.Equal(t, "Gaming Node", node.Name)
	assert.Equal(t, "vless", node.Protocol)
	assert.Equal(t, "192.0.2.1", node.Server)
	assert.Equal(t, 8443, node.Port)
	require.NotNil(t, node.RawConfig)
	assert.Equal(t, "00000000-0000-4000-8000-000000000001", node.RawConfig["uuid"])
	assert.Equal(t, "reality", node.RawConfig["security"])
	assert.Equal(t, "g7Wb2K_GoNt6WmY9Z4H9-aILg92xBDrw36KwCezc5Sg", node.RawConfig["pbk"])
}

func TestParseSingleURI_VMess(t *testing.T) {
	vmessJSON := `{"add":"vmess.example.com","port":443,"id":"12345678-1234-1234-1234-123456789abc","aid":0,"scy":"auto","net":"ws","type":"none","host":"vmess.example.com","path":"/ws","tls":"tls","sni":"vmess.example.com","ps":"VMess Test"}`
	b64 := base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	link := "vmess://" + b64

	node, err := ParseSingleURI(link)
	require.NoError(t, err)

	assert.Equal(t, "VMess Test", node.Name)
	assert.Equal(t, "vmess", node.Protocol)
	assert.Equal(t, "vmess.example.com", node.Server)
	assert.Equal(t, 443, node.Port)
	assert.Equal(t, "12345678-1234-1234-1234-123456789abc", node.RawConfig["uuid"])
	assert.Equal(t, "ws", node.RawConfig["network"])
}

func TestParseSingleURI_Trojan(t *testing.T) {
	link := "trojan://my-password@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Ftrojan-ws#Trojan%20Test"

	node, err := ParseSingleURI(link)
	require.NoError(t, err)

	assert.Equal(t, "Trojan Test", node.Name)
	assert.Equal(t, "trojan", node.Protocol)
	assert.Equal(t, "my-password", node.RawConfig["password"])
	assert.Equal(t, "/trojan-ws", node.RawConfig["path"])
}

func TestParseSingleURI_Shadowsocks(t *testing.T) {
	userInfo := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:my-secret"))
	link := "ss://" + userInfo + "@ss.example.com:8388#SS%20Node"

	node, err := ParseSingleURI(link)
	require.NoError(t, err)

	assert.Equal(t, "SS Node", node.Name)
	assert.Equal(t, "shadowsocks", node.Protocol)
	assert.Equal(t, "aes-256-gcm", node.RawConfig["cipher"])
	assert.Equal(t, "my-secret", node.RawConfig["password"])
}

func TestParseSingleURI_Hysteria2(t *testing.T) {
	link := "hysteria2://my-auth@hy2.example.com:443?sni=hy2.example.com&insecure=1#Hy2%20Node"

	node, err := ParseSingleURI(link)
	require.NoError(t, err)

	assert.Equal(t, "Hy2 Node", node.Name)
	assert.Equal(t, "hysteria2", node.Protocol)
	assert.Equal(t, "my-auth", node.RawConfig["password"])
	assert.Equal(t, true, node.RawConfig["skip-cert-verify"])
}

func TestURIPathIsDecodedExactlyOnce(t *testing.T) {
	node, err := ParseSingleURI("vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?type=ws&path=%2Fone%252Ftwo%2Bthree")
	require.NoError(t, err)
	got := node.RawConfig["path"]
	require.Equal(t, "/one%2Ftwo+three", got)
}

func TestShadowsocksSIP002PluginAndTrailingSlash(t *testing.T) {
	userInfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:test-password"))
	node, err := ParseSingleURI("ss://" + userInfo + "@[2001:db8::1]:8388/?plugin=v2ray-plugin%3Btls%3Bhost%3Dexample.com#Test")
	require.NoError(t, err)
	require.Equal(t, "2001:db8::1", node.Server)
	require.Equal(t, 8388, node.Port)
	require.Equal(t, "v2ray-plugin;tls;host=example.com", node.RawConfig["plugin"])
}

func TestHysteria2PreservesColonInAuthentication(t *testing.T) {
	node, err := ParseSingleURI("hy2://test-user:test-password@192.0.2.1:443")
	require.NoError(t, err)
	require.Equal(t, "test-user:test-password", node.RawConfig["password"])
}
