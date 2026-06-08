package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type Node struct {
	Name      string                 `json:"name"`
	Protocol  string                 `json:"protocol"`
	Server    string                 `json:"server"`
	Port      int                    `json:"port"`
	RawLink   string                 `json:"raw_link"`
	RawConfig map[string]interface{} `json:"raw_config"`
}

func LoadOrCreateHWID() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".config", "tuncli")
	err = os.MkdirAll(dir, 0755)
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
	if data, err := os.ReadFile(v2rayHwidPath); err == nil {
		hwid := strings.TrimSpace(string(data))
		if hwid != "" {
			os.WriteFile(hwidPath, []byte(hwid), 0644)
			return hwid, nil
		}
	}

	// Generate UUID v4 format (matching subscription server expectations)
	hwid := generateUUID()

	os.WriteFile(hwidPath, []byte(hwid), 0644)
	return hwid, nil
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

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status: %d %s", resp.StatusCode, resp.Status)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
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
			Name      string                 `json:"name"`
			Protocol  string                 `json:"protocol"`
			Address   string                 `json:"address"`
			Port      int                    `json:"port"`
			RawConfig map[string]interface{} `json:"raw_config"`
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
		Proxies []map[string]interface{} `yaml:"proxies"`
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
		Outbounds []map[string]interface{} `json:"outbounds"`
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
		strings.HasPrefix(uri, "hy2://")
}

func parseSingleURI(link string) (Node, error) {
	if !isDirectURI(link) {
		return Node{}, fmt.Errorf("invalid URI scheme")
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

	server := u.Hostname()
	port := 443
	if p := u.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}

	if strings.HasPrefix(link, "vmess://") {
		encoded := strings.TrimPrefix(link, "vmess://")
		if dec, err := decodeBase64Flexible(encoded); err == nil {
			var vmessData map[string]interface{}
			if json.Unmarshal(dec, &vmessData) == nil {
				if add, ok := vmessData["add"].(string); ok {
					server = add
				}
				if ps, ok := vmessData["ps"].(string); ok {
					name = ps
				}
				if pt, ok := vmessData["port"].(float64); ok {
					port = int(pt)
				} else if ptStr, ok := vmessData["port"].(string); ok {
					fmt.Sscanf(ptStr, "%d", &port)
				}
			}
		}
	}

	return Node{
		Name:     name,
		Protocol: protocol,
		Server:   server,
		Port:     port,
		RawLink:  link,
	}, nil
}
