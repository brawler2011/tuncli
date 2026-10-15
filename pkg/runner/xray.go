package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/sub"
)

const (
	DefaultXrayPort = 10815
	DefaultXrayMark = 354
)

// IsXHTTP returns true if the node uses the xhttp or splithttp transport.
func IsXHTTP(node *config.Node) bool {
	if node == nil {
		return false
	}
	rawConfig := getEffectiveRawConfig(node)
	if len(rawConfig) > 0 {
		netType := strings.ToLower(fmt.Sprint(rawConfig["network"]))
		typ := strings.ToLower(fmt.Sprint(rawConfig["type"]))
		if netType == "xhttp" || typ == "xhttp" || netType == "splithttp" || typ == "splithttp" {
			return true
		}
	}
	if node.RawLink != "" {
		if u, err := url.Parse(node.RawLink); err == nil {
			q := u.Query()
			t := strings.ToLower(q.Get("type"))
			n := strings.ToLower(q.Get("network"))
			if t == "xhttp" || n == "xhttp" || t == "splithttp" || n == "splithttp" {
				return true
			}
		}
	}
	return false
}

// GetDefaultInterface returns the default physical network interface name (e.g. "wlan0", "eth0").
func GetDefaultInterface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			iface := fields[0]
			if !strings.HasPrefix(iface, "tun") {
				return iface
			}
		}
	}
	return ""
}

func getEffectiveRawConfig(node *config.Node) map[string]interface{} {
	if node == nil {
		return nil
	}
	rawConfig := node.RawConfig
	if len(rawConfig) == 0 && node.RawLink != "" {
		if parsed, err := sub.ParseSingleURI(node.RawLink); err == nil && len(parsed.RawConfig) > 0 {
			rawConfig = parsed.RawConfig
			if node.Protocol == "" {
				node.Protocol = parsed.Protocol
			}
			if node.Server == "" {
				node.Server = parsed.Server
			}
			if node.Port == 0 {
				node.Port = parsed.Port
			}
		}
	}
	return rawConfig
}

// GenerateXrayConfig builds a minimal Xray configuration for an XHTTP outbound with SOCKS5 inbound.
func GenerateXrayConfig(node *config.Node, socksPort int, markOption ...int) ([]byte, error) {
	if node == nil {
		return nil, fmt.Errorf("node is nil")
	}

	mark := DefaultXrayMark
	if len(markOption) > 0 {
		mark = markOption[0]
	}

	rawConfig := getEffectiveRawConfig(node)
	server := node.Server
	if server == "" {
		if s, ok := rawConfig["server"].(string); ok {
			server = s
		}
	}
	port := node.Port
	if port == 0 {
		if p, ok := rawConfig["port"].(int); ok {
			port = p
		} else if p, ok := rawConfig["port"].(float64); ok {
			port = int(p)
		} else if pStr, ok := rawConfig["port"].(string); ok {
			fmt.Sscanf(pStr, "%d", &port)
		}
	}

	uuid, _ := rawConfig["uuid"].(string)

	// Stream settings
	streamSettings := map[string]interface{}{
		"network": "xhttp",
	}
	sockopt := make(map[string]interface{})
	if mark > 0 {
		sockopt["mark"] = mark
	}
	if iface := GetDefaultInterface(); iface != "" {
		sockopt["interface"] = iface
	}
	if len(sockopt) > 0 {
		streamSettings["sockopt"] = sockopt
	}

	// Security: Reality vs TLS vs None
	pbk, _ := rawConfig["pbk"].(string)
	sid, _ := rawConfig["sid"].(string)
	if realityOpts, ok := rawConfig["reality-opts"].(map[string]interface{}); ok {
		if pk, ok := realityOpts["public-key"].(string); ok && pk != "" {
			pbk = pk
		}
		if s, ok := realityOpts["short-id"].(string); ok && s != "" {
			sid = s
		}
	}

	sni, _ := rawConfig["sni"].(string)
	if sni == "" {
		sni, _ = rawConfig["servername"].(string)
	}
	if sni == "" {
		sni = server
	}

	fp, _ := rawConfig["fp"].(string)
	if fp == "" {
		fp, _ = rawConfig["client-fingerprint"].(string)
	}
	if fp == "" {
		fp = "chrome"
	}

	sec, _ := rawConfig["security"].(string)
	isTLS := false
	if tlsVal, ok := rawConfig["tls"].(bool); ok && tlsVal {
		isTLS = true
	} else if tlsStr, ok := rawConfig["tls"].(string); ok && (tlsStr == "1" || tlsStr == "true") {
		isTLS = true
	}

	if pbk != "" || sec == "reality" {
		realitySettings := map[string]interface{}{
			"show":        false,
			"fingerprint": fp,
			"serverName":  sni,
			"publicKey":   pbk,
			"shortId":     sid,
		}
		if spx, ok := rawConfig["spx"].(string); ok && spx != "" {
			realitySettings["spiderX"] = spx
		}
		streamSettings["security"] = "reality"
		streamSettings["realitySettings"] = realitySettings
	} else if isTLS || sec == "tls" {
		tlsSettings := map[string]interface{}{
			"serverName":  sni,
			"fingerprint": fp,
		}
		if scv, ok := rawConfig["skip-cert-verify"].(bool); ok && scv {
			tlsSettings["allowInsecure"] = true
		} else if insec, ok := rawConfig["insecure"].(bool); ok && insec {
			tlsSettings["allowInsecure"] = true
		}
		if alpn, ok := rawConfig["alpn"].([]string); ok && len(alpn) > 0 {
			tlsSettings["alpn"] = alpn
		}
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = tlsSettings
	} else {
		streamSettings["security"] = "none"
	}

	// XHTTP settings
	path, _ := rawConfig["path"].(string)
	if path == "" {
		path = "/xhttp"
	}

	mode, _ := rawConfig["mode"].(string)
	if mode == "" {
		mode = "auto"
	}

	host, _ := rawConfig["host"].(string)
	if host == "" {
		host = sni
	}

	xhttpSettings := map[string]interface{}{
		"path": path,
		"mode": mode,
	}
	if host != "" {
		xhttpSettings["host"] = host
	}

	headers := make(map[string]string)
	for k, v := range rawConfig {
		lowerK := strings.ToLower(k)
		if strings.HasPrefix(lowerK, "x-") && lowerK != "xhttp" {
			headers[k] = fmt.Sprint(v)
		}
	}
	if customHeaders, ok := rawConfig["headers"].(map[string]interface{}); ok {
		for k, v := range customHeaders {
			if !strings.EqualFold(k, "host") {
				headers[k] = fmt.Sprint(v)
			}
		}
	}
	if len(headers) > 0 {
		xhttpSettings["headers"] = headers
	}

	extra := make(map[string]string)
	if concurrency := rawConfig["concurrency"]; concurrency != nil {
		extra["concurrency"] = fmt.Sprint(concurrency)
	}
	if len(extra) > 0 {
		xhttpSettings["extra"] = extra
	}

	streamSettings["xhttpSettings"] = xhttpSettings

	// Outbound protocol settings
	proto := strings.ToLower(node.Protocol)
	if proto == "" || proto == "xhttp" || proto == "splithttp" {
		proto = "vless"
	}

	dialAddress := server
	if net.ParseIP(server) == nil && server != "" {
		if ips, err := net.LookupIP(server); err == nil {
			for _, ip := range ips {
				if ipv4 := ip.To4(); ipv4 != nil {
					dialAddress = ipv4.String()
					break
				}
			}
		}
	}

	var outboundSettings map[string]interface{}
	switch proto {
	case "vmess":
		alterID := 0
		if aid, ok := rawConfig["alterId"].(int); ok {
			alterID = aid
		} else if aid, ok := rawConfig["alterId"].(float64); ok {
			alterID = int(aid)
		}
		cipher, _ := rawConfig["cipher"].(string)
		if cipher == "" {
			cipher = "auto"
		}
		outboundSettings = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": dialAddress,
					"port":    port,
					"users": []map[string]interface{}{
						{
							"id":       uuid,
							"alterId":  alterID,
							"security": cipher,
						},
					},
				},
			},
		}
	default: // vless
		userObj := map[string]interface{}{
			"id":         uuid,
			"encryption": "none",
		}
		if flow, ok := rawConfig["flow"].(string); ok && flow != "" {
			userObj["flow"] = flow
		}
		outboundSettings = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": dialAddress,
					"port":    port,
					"users": []map[string]interface{}{
						userObj,
					},
				},
			},
		}
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"listen":   "127.0.0.1",
				"port":     socksPort,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol":       proto,
				"settings":       outboundSettings,
				"streamSettings": streamSettings,
			},
		},
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// XraySidecar manages the lifecycle of the background Xray process.
type XraySidecar struct {
	Port        int
	ConfigFile  string
	Cmd         *exec.Cmd
	cleanupRule func()
}

func setupXrayRoutingRule(mark int) func() {
	if os.Geteuid() != 0 || mark <= 0 {
		return func() {}
	}
	markStr := fmt.Sprintf("%d", mark)
	// Delete any existing rule first to prevent accumulation
	_ = exec.Command("ip", "rule", "del", "fwmark", markStr, "lookup", "main", "priority", "8990").Run()
	if err := exec.Command("ip", "rule", "add", "fwmark", markStr, "lookup", "main", "priority", "8990").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to add ip rule for Xray fwmark %d: %v\n", mark, err)
	}
	return func() {
		_ = exec.Command("ip", "rule", "del", "fwmark", markStr, "lookup", "main", "priority", "8990").Run()
	}
}

func findXrayBinary() string {
	if _, err := os.Stat("/usr/bin/xray"); err == nil {
		return "/usr/bin/xray"
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	return ""
}

func getFreePort(preferred int) (int, error) {
	if preferred > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferred))
		if err == nil {
			_ = ln.Close()
			return preferred, nil
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to find free port: %w", err)
	}
	defer ln.Close()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// StartXraySidecar starts an Xray process in the background with the generated config.
func StartXraySidecar(node *config.Node, preferredPort int) (*XraySidecar, error) {
	xrayPath := findXrayBinary()
	if xrayPath == "" {
		return nil, fmt.Errorf("xray binary not found (expected /usr/bin/xray): required for xhttp transport")
	}

	port, err := getFreePort(preferredPort)
	if err != nil {
		return nil, err
	}

	mark := DefaultXrayMark
	if os.Geteuid() != 0 {
		mark = 0
	}

	var cleanupRule func()
	if os.Geteuid() == 0 && mark > 0 {
		cleanupRule = setupXrayRoutingRule(mark)
	}

	cfgBytes, err := GenerateXrayConfig(node, port, mark)
	if err != nil {
		if cleanupRule != nil {
			cleanupRule()
		}
		return nil, fmt.Errorf("failed to generate xray config: %w", err)
	}

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("tuncli-xray-%d-*.json", port))
	if err != nil {
		if cleanupRule != nil {
			cleanupRule()
		}
		return nil, fmt.Errorf("failed to create temp xray config file: %w", err)
	}
	configPath := tmpFile.Name()

	if _, err := tmpFile.Write(cfgBytes); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(configPath)
		if cleanupRule != nil {
			cleanupRule()
		}
		return nil, fmt.Errorf("failed to write xray config: %w", err)
	}
	_ = tmpFile.Close()

	cmd := exec.Command(xrayPath, "run", "-c", configPath)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	cmd.Stdout = &errBuf

	if err := cmd.Start(); err != nil {
		_ = os.Remove(configPath)
		if cleanupRule != nil {
			cleanupRule()
		}
		return nil, fmt.Errorf("failed to start xray process: %w", err)
	}

	sidecar := &XraySidecar{
		Port:        port,
		ConfigFile:  configPath,
		Cmd:         cmd,
		cleanupRule: cleanupRule,
	}

	// Wait for Xray to be listening on socks port or exit with error
	ready := false
	for i := 0; i < 30; i++ {
		time.Sleep(50 * time.Millisecond)

		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			_ = sidecar.Stop()
			return nil, fmt.Errorf("xray process exited unexpectedly: %s", strings.TrimSpace(errBuf.String()))
		}

		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
	}

	if !ready {
		_ = sidecar.Stop()
		return nil, fmt.Errorf("timed out waiting for xray to listen on 127.0.0.1:%d: %s", port, strings.TrimSpace(errBuf.String()))
	}

	return sidecar, nil
}

// Stop terminates the Xray process and cleans up temporary config files.
func (s *XraySidecar) Stop() error {
	if s == nil {
		return nil
	}

	if s.cleanupRule != nil {
		s.cleanupRule()
		s.cleanupRule = nil
	}

	var stopErr error
	if s.Cmd != nil && s.Cmd.Process != nil {
		_ = s.Cmd.Process.Signal(syscall.SIGTERM)

		done := make(chan error, 1)
		go func() {
			done <- s.Cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(1500 * time.Millisecond):
			_ = s.Cmd.Process.Kill()
			<-done
		}
	}

	if s.ConfigFile != "" {
		if err := os.Remove(s.ConfigFile); err != nil && !os.IsNotExist(err) {
			stopErr = err
		}
	}

	return stopErr
}
