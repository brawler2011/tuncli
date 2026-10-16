package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/storage"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type Node struct {
	Name      string         `json:"name"`
	Protocol  string         `json:"protocol"`
	Server    string         `json:"server"`
	Port      int            `json:"port"`
	RawLink   string         `json:"raw_link"`
	RawConfig map[string]any `json:"raw_config"`
}

func LoadOrCreateHWID() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	err = storage.Mkdir(dir)
	if err != nil {
		return "", err
	}
	hwidPath := filepath.Join(dir, "hwid")

	// Use existing HWID
	if data, err := os.ReadFile(hwidPath); err == nil {
		hwid := strings.TrimSpace(string(data))
		if hwid != "" {
			return hwid, nil
		}
	}

	// Prefer v2raytun-port HWID if available (device already registered)
	v2rayHwidPath := filepath.Join(home, ".config", "v2raytun-port", "hwid")
	if data, err := os.ReadFile(v2rayHwidPath); err == nil && !storage.Private {
		hwid := strings.TrimSpace(string(data))
		if hwid != "" {
			return hwid, storage.Write(hwidPath, []byte(hwid))
		}
	}

	// Generate UUID v4 format (matching subscription server expectations)
	hwid := generateUUID()

	return hwid, storage.Write(hwidPath, []byte(hwid))
}

func generateUUID() string {
	return uuid.NewString()
}

func FetchAndParse(subURL string) ([]Node, error) {
	if isDirectURI(subURL) {
		node, err := parseSingleURI(subURL)
		if err != nil {
			return nil, err
		}
		return []Node{node}, nil
	}

	req, err := http.NewRequest("GET", subURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request failed: %w", err)
	}

	req.Header.Set("User-Agent", "clash-verge/v2.2.3")

	hwid, err := LoadOrCreateHWID()
	if err == nil && hwid != "" {
		req.Header.Set("X-HWID", hwid)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status: %d %s", resp.StatusCode, resp.Status)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if len(bodyBytes) > 16<<20 {
		return nil, fmt.Errorf("subscription exceeds 16 MiB")
	}
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	nodes, err := ParseBody(string(bodyBytes))
	if err != nil {
		return nil, err
	}

	// Check if nodes are fake (server 0.0.0.0) — if so, try v2raytun-port cache
	if areNodesFake(nodes) {
		if cached, err := ImportFromV2RayTun(); err == nil && len(cached) > 0 {
			fmt.Fprintf(os.Stderr, "Warning: Server returned blocked nodes. Imported %d nodes from v2raytun-port cache.\n", len(cached))
			return cached, nil
		}
		return nil, fmt.Errorf("server returned blocked nodes (device limit reached or app not supported)")
	}

	return nodes, nil
}

func areNodesFake(nodes []Node) bool {
	if len(nodes) == 0 {
		return true
	}
	for _, n := range nodes {
		if n.Server == "0.0.0.0" || n.Server == "" {
			return true
		}
	}
	return false
}

func ImportFromV2RayTun() ([]Node, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".config", "v2raytun-port", "subscriptions.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var subs []struct {
		Nodes []struct {
			Name      string         `json:"name"`
			Protocol  string         `json:"protocol"`
			Address   string         `json:"address"`
			Port      int            `json:"port"`
			RawConfig map[string]any `json:"raw_config"`
		} `json:"nodes"`
	}
	err = json.Unmarshal(data, &subs)
	if err != nil {
		return nil, err
	}

	var nodes []Node
	for _, sub := range subs {
		for _, n := range sub.Nodes {
			nodes = append(nodes, Node{
				Name:      n.Name,
				Protocol:  n.Protocol,
				Server:    n.Address,
				Port:      n.Port,
				RawConfig: n.RawConfig,
			})
		}
	}
	return nodes, nil
}

func ParseBody(body string) ([]Node, error) {
	trimmed := strings.TrimSpace(body)

	if strings.Contains(trimmed, "proxies:") {
		nodes, err := parseClashYAML(trimmed)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}

	if strings.HasPrefix(trimmed, "{") {
		nodes, err := parseSingboxJSON(trimmed)
		if err == nil && len(nodes) > 0 {
			return nodes, nil
		}
	}

	decodedBytes, err := decodeBase64Flexible(trimmed)
	if err != nil {
		decodedBytes = []byte(trimmed)
	}

	return parseURIList(string(decodedBytes))
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")

	pad := len(s) % 4
	if pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}

	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return base64.URLEncoding.DecodeString(s)
	}
	return dec, nil
}

func parseClashYAML(body string) ([]Node, error) {
	var yamlData struct {
		Proxies []map[string]any `yaml:"proxies"`
	}

	err := yaml.Unmarshal([]byte(body), &yamlData)
	if err != nil {
		return nil, err
	}

	var nodes []Node
	for _, proxy := range yamlData.Proxies {
		name, _ := proxy["name"].(string)
		if name == "" {
			name = "unknown"
		}
		typ, _ := proxy["type"].(string)
		server, _ := proxy["server"].(string)

		port := 443
		if p, ok := proxy["port"].(int); ok {
			port = p
		} else if pFloat, ok := proxy["port"].(float64); ok {
			port = int(pFloat)
		}

		nodes = append(nodes, Node{
			Name:      name,
			Protocol:  strings.ToLower(typ),
			Server:    server,
			Port:      port,
			RawConfig: proxy,
		})
	}
	return nodes, nil
}

func parseSingboxJSON(body string) ([]Node, error) {
	var jsonData struct {
		Outbounds []map[string]any `json:"outbounds"`
	}

	err := json.Unmarshal([]byte(body), &jsonData)
	if err != nil {
		return nil, err
	}

	var nodes []Node
	for _, out := range jsonData.Outbounds {
		typ, _ := out["type"].(string)
		if typ == "selector" || typ == "urltest" || typ == "direct" || typ == "block" || typ == "dns" {
			continue
		}

		tag, _ := out["tag"].(string)
		server, _ := out["server"].(string)

		port := 443
		if pFloat, ok := out["server_port"].(float64); ok {
			port = int(pFloat)
		}

		nodes = append(nodes, Node{
			Name:      tag,
			Protocol:  typ,
			Server:    server,
			Port:      port,
			RawConfig: out,
		})
	}
	return nodes, nil
}

func parseURIList(body string) ([]Node, error) {
	lines := strings.Split(body, "\n")
	var nodes []Node

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		node, err := parseSingleURI(line)
		if err == nil {
			nodes = append(nodes, node)
		}
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no valid proxy nodes found in subscription")
	}

	return nodes, nil
}

func isDirectURI(uri string) bool {
	uri = strings.TrimSpace(uri)
	return strings.HasPrefix(uri, "vmess://") ||
		strings.HasPrefix(uri, "vless://") ||
		strings.HasPrefix(uri, "trojan://") ||
		strings.HasPrefix(uri, "ss://") ||
		strings.HasPrefix(uri, "hysteria2://") ||
		strings.HasPrefix(uri, "hy2://") ||
		strings.HasPrefix(uri, "hysteria://")
}

func ParseSingleURI(link string) (Node, error) {
	return parseSingleURI(link)
}

func parseSingleURI(link string) (Node, error) {
	link = strings.TrimSpace(link)
	if !isDirectURI(link) {
		return Node{}, fmt.Errorf("invalid URI scheme")
	}

	if strings.HasPrefix(link, "vmess://") {
		return parseVMessURI(link)
	} else if strings.HasPrefix(link, "ss://") {
		return parseShadowsocksURI(link)
	}

	u, err := url.Parse(link)
	if err != nil {
		return Node{}, err
	}

	name := u.Fragment
	if name == "" {
		name = "Unnamed Node"
	} else {
		if unescaped, err := url.QueryUnescape(name); err == nil {
			name = unescaped
		}
	}

	protocol := strings.TrimSuffix(u.Scheme, "://")
	if protocol == "hy2" {
		protocol = "hysteria2"
	}

	server := u.Hostname()
	port := 443
	if p := u.Port(); p != "" {
		_, _ = fmt.Sscanf(p, "%d", &port) // Keep the default if the optional number is invalid.
	}

	rawConfig := make(map[string]any)
	rawConfig["name"] = name
	rawConfig["type"] = protocol
	rawConfig["server"] = server
	rawConfig["port"] = port

	if u.User != nil {
		user := u.User.Username()
		switch protocol {
		case "vless":
			rawConfig["uuid"] = user
		case "trojan", "hysteria2", "hysteria":
			rawConfig["password"] = user
			if pass, ok := u.User.Password(); ok && pass != "" {
				rawConfig["password"] = user + ":" + pass
			}
		}
	}

	q := u.Query()
	for k, v := range q {
		if len(v) > 0 {
			rawConfig[k] = v[0]
		}
	}

	// Normalizations
	if sni := q.Get("sni"); sni != "" {
		rawConfig["servername"] = sni
		rawConfig["sni"] = sni
	} else if peer := q.Get("peer"); peer != "" {
		rawConfig["servername"] = peer
		rawConfig["sni"] = peer
	}

	if typ := q.Get("type"); typ != "" {
		rawConfig["network"] = typ
	}

	if sec := q.Get("security"); sec != "" {
		rawConfig["security"] = sec
		if sec == "tls" || sec == "reality" {
			rawConfig["tls"] = true
		}
	}
	if protocol == "trojan" || protocol == "hysteria2" || protocol == "hysteria" {
		rawConfig["tls"] = true
	}

	if pbk := q.Get("pbk"); pbk != "" {
		rawConfig["reality-opts"] = map[string]any{
			"public-key": pbk,
			"short-id":   q.Get("sid"),
		}
		rawConfig["pbk"] = pbk
		rawConfig["sid"] = q.Get("sid")
		rawConfig["tls"] = true
	}

	if fp := q.Get("fp"); fp != "" {
		rawConfig["client-fingerprint"] = fp
		rawConfig["fp"] = fp
	}

	if flow := q.Get("flow"); flow != "" {
		rawConfig["flow"] = flow
	}

	if insecure := q.Get("insecure"); insecure == "1" || insecure == "true" {
		rawConfig["skip-cert-verify"] = true
	}

	if path := q.Get("path"); path != "" {
		rawConfig["path"] = path
	}

	if host := q.Get("host"); host != "" {
		rawConfig["host"] = host
	}

	if serviceName := q.Get("serviceName"); serviceName != "" {
		rawConfig["serviceName"] = serviceName
	}

	if alpn := q.Get("alpn"); alpn != "" {
		rawConfig["alpn"] = alpn
	}

	return Node{
		Name:      name,
		Protocol:  protocol,
		Server:    server,
		Port:      port,
		RawLink:   link,
		RawConfig: rawConfig,
	}, nil
}

func parseVMessURI(link string) (Node, error) {
	encoded := strings.TrimPrefix(link, "vmess://")
	dec, err := decodeBase64Flexible(encoded)
	if err != nil {
		return Node{}, fmt.Errorf("failed to decode vmess base64: %w", err)
	}

	var vmessData map[string]any
	if err := json.Unmarshal(dec, &vmessData); err != nil {
		return Node{}, fmt.Errorf("failed to parse vmess json: %w", err)
	}

	name := "Unnamed VMess"
	if ps, ok := vmessData["ps"].(string); ok && ps != "" {
		name = ps
	}

	server, _ := vmessData["add"].(string)
	port := 443
	if p, ok := vmessData["port"].(float64); ok {
		port = int(p)
	} else if pStr, ok := vmessData["port"].(string); ok {
		_, _ = fmt.Sscanf(pStr, "%d", &port) // Keep the default if the optional number is invalid.
	}

	rawConfig := make(map[string]any)
	rawConfig["name"] = name
	rawConfig["type"] = "vmess"
	rawConfig["server"] = server
	rawConfig["port"] = port

	if id, ok := vmessData["id"].(string); ok {
		rawConfig["uuid"] = id
	}
	if aid, ok := vmessData["aid"].(float64); ok {
		rawConfig["alterId"] = int(aid)
	} else if aidStr, ok := vmessData["aid"].(string); ok {
		var aid int
		_, _ = fmt.Sscanf(aidStr, "%d", &aid) // Keep the default if the optional number is invalid.
		rawConfig["alterId"] = aid
	}
	if scy, ok := vmessData["scy"].(string); ok && scy != "" {
		rawConfig["cipher"] = scy
	} else {
		rawConfig["cipher"] = "auto"
	}
	if netType, ok := vmessData["net"].(string); ok && netType != "" {
		rawConfig["network"] = netType
	}
	if path, ok := vmessData["path"].(string); ok && path != "" {
		rawConfig["path"] = path
	}
	if host, ok := vmessData["host"].(string); ok && host != "" {
		rawConfig["host"] = host
	}
	if tlsVal, ok := vmessData["tls"].(string); ok && (tlsVal == "tls" || tlsVal == "reality") {
		rawConfig["tls"] = true
		rawConfig["security"] = tlsVal
	}
	if sni, ok := vmessData["sni"].(string); ok && sni != "" {
		rawConfig["sni"] = sni
		rawConfig["servername"] = sni
	} else if host, ok := vmessData["host"].(string); ok && host != "" {
		rawConfig["servername"] = host
	}
	if alpn, ok := vmessData["alpn"].(string); ok && alpn != "" {
		rawConfig["alpn"] = alpn
	}
	if fp, ok := vmessData["fp"].(string); ok && fp != "" {
		rawConfig["fp"] = fp
		rawConfig["client-fingerprint"] = fp
	}

	return Node{
		Name:      name,
		Protocol:  "vmess",
		Server:    server,
		Port:      port,
		RawLink:   link,
		RawConfig: rawConfig,
	}, nil
}

func parseShadowsocksURI(link string) (Node, error) {
	link = strings.TrimSpace(link)
	withoutScheme := strings.TrimPrefix(link, "ss://")

	var name string
	if idx := strings.Index(withoutScheme, "#"); idx != -1 {
		namePart := withoutScheme[idx+1:]
		withoutScheme = withoutScheme[:idx]
		if unescaped, err := url.QueryUnescape(namePart); err == nil {
			name = unescaped
		} else {
			name = namePart
		}
	}
	if name == "" {
		name = "Shadowsocks Node"
	}

	var queryPart string
	if idx := strings.Index(withoutScheme, "?"); idx != -1 {
		queryPart = withoutScheme[idx+1:]
		withoutScheme = withoutScheme[:idx]
	}

	var method, password, server string
	var port = 8388

	if strings.Contains(withoutScheme, "@") {
		at := strings.LastIndex(withoutScheme, "@")
		parts := []string{withoutScheme[:at], withoutScheme[at+1:]}
		userInfo := parts[0]
		hostPort := strings.TrimSuffix(parts[1], "/")

		if dec, err := decodeBase64Flexible(userInfo); err == nil && strings.Contains(string(dec), ":") {
			userInfo = string(dec)
		} else if decoded, err := url.PathUnescape(userInfo); err == nil {
			userInfo = decoded
		}
		if colon := strings.Index(userInfo, ":"); colon != -1 {
			method = userInfo[:colon]
			password = userInfo[colon+1:]
		}

		if hp, p, err := net.SplitHostPort(hostPort); err == nil {
			server = hp
			_, _ = fmt.Sscanf(p, "%d", &port) // Keep the default if the optional number is invalid.
		} else {
			server = hostPort
		}
	} else {
		if dec, err := decodeBase64Flexible(withoutScheme); err == nil {
			decodedStr := string(dec)
			if before, after, ok := strings.Cut(decodedStr, "@"); ok {
				userPart := before
				hostPart := after
				if before, after, ok := strings.Cut(userPart, ":"); ok {
					method = before
					password = after
				}
				if hp, p, err := net.SplitHostPort(hostPart); err == nil {
					server = hp
					_, _ = fmt.Sscanf(p, "%d", &port) // Keep the default if the optional number is invalid.
				} else {
					server = hostPart
				}
			}
		}
	}

	if server == "" {
		return Node{}, fmt.Errorf("failed to parse shadowsocks URI: server not found")
	}

	rawConfig := map[string]any{
		"name":     name,
		"type":     "shadowsocks",
		"server":   server,
		"port":     port,
		"cipher":   method,
		"password": password,
	}

	if queryPart != "" {
		if q, err := url.ParseQuery(queryPart); err == nil {
			if plugin := q.Get("plugin"); plugin != "" {
				rawConfig["plugin"] = plugin
			}
		}
	}

	return Node{
		Name:      name,
		Protocol:  "shadowsocks",
		Server:    server,
		Port:      port,
		RawLink:   link,
		RawConfig: rawConfig,
	}, nil
}
