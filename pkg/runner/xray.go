package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
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

func getEffectiveRawConfig(node *config.Node) map[string]any {
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
			_, _ = fmt.Sscanf(pStr, "%d", &port) // Keep the default if the optional number is invalid.
		}
	}

	uuid, _ := rawConfig["uuid"].(string)

	// Stream settings
	streamSettings := map[string]any{
		"network": "xhttp",
	}
	sockopt := make(map[string]any)
	if mark > 0 {
		sockopt["mark"] = mark
	}
	if iface := GetDefaultInterface(); mark > 0 && iface != "" {
		sockopt["interface"] = iface
	}
	if len(sockopt) > 0 {
		streamSettings["sockopt"] = sockopt
	}

	// Security: Reality vs TLS vs None
	pbk, _ := rawConfig["pbk"].(string)
	sid, _ := rawConfig["sid"].(string)
	if realityOpts, ok := rawConfig["reality-opts"].(map[string]any); ok {
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
		realitySettings := map[string]any{
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
		tlsSettings := map[string]any{
			"serverName":  sni,
			"fingerprint": fp,
		}
		if alpn := stringList(rawConfig["alpn"]); len(alpn) > 0 {
			tlsSettings["alpn"] = alpn
		}
		if truthy(rawConfig["skip-cert-verify"]) || truthy(rawConfig["insecure"]) {
			tlsSettings["allowInsecure"] = true
		}
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = tlsSettings
	} else {
		streamSettings["security"] = "none"
	}

	// XHTTP settings
	path, _ := rawConfig["path"].(string)
	if path == "" {
		path = "/"
	}

	mode, _ := rawConfig["mode"].(string)
	if mode == "" {
		mode = "auto"
	}

	host, _ := rawConfig["host"].(string)
	if host == "" {
		host = sni
	}

	xhttpSettings := map[string]any{
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
	if customHeaders, ok := rawConfig["headers"].(map[string]any); ok {
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

	if proto != "vless" && proto != "vmess" {
		return nil, fmt.Errorf("unsupported XHTTP protocol %q", proto)
	}
	if server == "" || port <= 0 || port > 65535 || uuid == "" {
		return nil, fmt.Errorf("XHTTP node requires server, valid port and UUID")
	}
	var outboundSettings map[string]any
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
		outboundSettings = map[string]any{
			"vnext": []map[string]any{
				{
					"address": dialAddress,
					"port":    port,
					"users": []map[string]any{
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
		userObj := map[string]any{
			"id":         uuid,
			"encryption": "none",
		}
		if flow, ok := rawConfig["flow"].(string); ok && flow != "" {
			userObj["flow"] = flow
		}
		outboundSettings = map[string]any{
			"vnext": []map[string]any{
				{
					"address": dialAddress,
					"port":    port,
					"users": []map[string]any{
						userObj,
					},
				},
			},
		}
	}

	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
		},
		"inbounds": []map[string]any{
			{
				"listen":   "127.0.0.1",
				"port":     socksPort,
				"protocol": "socks",
				"settings": map[string]any{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []map[string]any{
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
	done        chan struct{}
	waitErr     error
	stopOnce    sync.Once
	stopErr     error
}

func setupXrayRoutingRule(mark int) (func(), error) {
	markStr := fmt.Sprintf("%d", mark)
	// Only remove a rule successfully created by this instance.
	if err := exec.Command("ip", "rule", "add", "fwmark", markStr, "lookup", "main", "priority", "8990").Run(); err != nil {
		return nil, fmt.Errorf("add Xray routing rule: %w", err)
	}
	return func() {
		_ = exec.Command("ip", "rule", "del", "fwmark", markStr, "lookup", "main", "priority", "8990").Run()
	}, nil
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
	defer func() { _ = ln.Close() }()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

// StartXraySidecar starts an Xray process in the background with the generated config.
func StartXraySidecar(node *config.Node, preferredPort int, operatingMode ...string) (*XraySidecar, error) {
	return startXraySidecar(node, preferredPort, findXrayBinary(), len(operatingMode) == 0 || operatingMode[0] == "tun")
}

func startXraySidecar(node *config.Node, preferredPort int, xrayPath string, tunMode bool) (*XraySidecar, error) {
	if xrayPath == "" {
		return nil, fmt.Errorf("xray binary not found (expected /usr/bin/xray): required for xhttp transport")
	}

	port, err := getFreePort(preferredPort)
	if err != nil {
		return nil, err
	}

	mark := DefaultXrayMark
	if os.Geteuid() != 0 || !tunMode {
		mark = 0
	}

	var cleanupRule func()
	if os.Geteuid() == 0 && mark > 0 {
		cleanupRule, err = setupXrayRoutingRule(mark)
		if err != nil {
			return nil, err
		}
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	var errBuf synchronizedBuffer
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

	sidecar.watchProcess()

	// Wait for Xray to be listening on socks port or exit with error
	ready := false
	for range 30 {
		time.Sleep(50 * time.Millisecond)

		select {
		case <-sidecar.done:
			_ = sidecar.Stop()
			return nil, fmt.Errorf("xray process exited unexpectedly: %w: %s", sidecar.waitErr, strings.TrimSpace(errBuf.String()))
		default:
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

// watchProcess must be called once immediately after Cmd.Start.
func (s *XraySidecar) watchProcess() {
	s.done = make(chan struct{})
	go func() { s.waitErr = s.Cmd.Wait(); close(s.done) }()
}

// Stop terminates and reaps Xray before removing its network rule and config.
func (s *XraySidecar) Stop() error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		if s.Cmd != nil && s.Cmd.Process != nil {
			select {
			case <-s.done:
			default:
				if err := s.Cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
					s.stopErr = err
				}
				select {
				case <-s.done:
				case <-time.After(1500 * time.Millisecond):
					if err := s.Cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
						s.stopErr = errors.Join(s.stopErr, err)
					}
					<-s.done
				}
			}
		}
		if s.cleanupRule != nil {
			s.cleanupRule()
		}
		if s.ConfigFile != "" {
			if err := os.Remove(s.ConfigFile); err != nil && !os.IsNotExist(err) {
				s.stopErr = errors.Join(s.stopErr, err)
			}
		}
	})
	return s.stopErr
}

// Xray may emit output while readiness is checked. Bound and synchronize it.
type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if remaining := 64*1024 - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buf.Write(p)
	}
	return n, nil
}
func (b *synchronizedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
