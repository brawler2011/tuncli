package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"sort"
	"strings"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/brawler2011/tuncli/pkg/sub"

	"github.com/sagernet/sing-box/option"
	singJson "github.com/sagernet/sing/common/json"
)

func BuildSingboxConfig(ctx context.Context, node *config.Node, mode string, xrayPort ...int) (option.Options, error) {
	return BuildSingboxConfigWithPolicy(ctx, node, mode, nil, xrayPort...)
}

// BuildSingboxConfigWithPolicy is pure: callers prepare rule files and bootstrap IPs.
func BuildSingboxConfigWithPolicy(ctx context.Context, node *config.Node, mode string, prepared *routing.Prepared, xrayPort ...int) (option.Options, error) {
	var opts option.Options
	if node == nil {
		return opts, fmt.Errorf("node is nil")
	}
	if mode != "tun" && mode != "proxy" {
		return opts, fmt.Errorf("invalid mode %q", mode)
	}

	if (len(node.RawConfig) == 0 || node.Server == "") && node.RawLink != "" {
		if parsed, err := sub.ParseSingleURI(node.RawLink); err == nil {
			if len(node.RawConfig) == 0 && len(parsed.RawConfig) > 0 {
				node.RawConfig = parsed.RawConfig
			}
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
	// Determine the proxy server address for bypass rules
	proxyServer := ""
	if node != nil {
		proxyServer = node.Server
	}

	var routeRules []map[string]any

	if mode == "tun" {
		routeRules = append(routeRules, map[string]any{
			"port":   []int{53},
			"action": "hijack-dns",
		})
	}

	proxyIP := ""
	if net.ParseIP(proxyServer) != nil {
		proxyIP = proxyServer
		prefix := "/32"
		if net.ParseIP(proxyServer).To4() == nil {
			prefix = "/128"
		}
		routeRules = append(routeRules, map[string]any{
			"ip_cidr":  []string{proxyServer + prefix},
			"outbound": "direct",
		})
	} else if proxyServer != "" {
		if prepared != nil {
			for _, address := range prepared.ServerIPs {
				ip := net.ParseIP(address)
				if ip == nil {
					return opts, fmt.Errorf("invalid bootstrap IP %q", address)
				}
				prefix := "/128"
				if ip.To4() != nil {
					prefix = "/32"
					proxyIP = ip.String()
				}
				routeRules = append(routeRules, map[string]any{"ip_cidr": []string{ip.String() + prefix}, "outbound": "direct"})
			}
		}
		routeRules = append(routeRules, map[string]any{
			"domain":   []string{proxyServer},
			"outbound": "direct",
		})
	}

	dnsRules := []map[string]any{}
	if proxyServer != "" && net.ParseIP(proxyServer) == nil {
		dnsRules = append(dnsRules, map[string]any{
			"domain": []string{proxyServer},
			"server": "dns-local",
		})
	}

	baseConfig := map[string]any{
		"dns": map[string]any{
			"servers": []map[string]any{
				{"tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
				{"tag": "dns-local", "address": "local", "detour": "direct"},
			},
			"rules":    dnsRules,
			"final":    "dns-remote",
			"strategy": "prefer_ipv4",
		},
		"route": map[string]any{
			"auto_detect_interface": true,
			"final":                 "proxy",
			"rules":                 routeRules,
		},
	}

	// Keep TUN first: routing setup adjusts its stack and addresses.
	var inbounds []map[string]any
	if mode == "tun" {
		inbounds = append(inbounds,
			map[string]any{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": "tuncli-tun0",
				"address":        "172.19.0.1/24",
				"auto_route":     true,
				"strict_route":   true,
				"stack":          "system",
			},
		)
	}
	inbounds = append(inbounds, map[string]any{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      "127.0.0.1",
		"listen_port": 2080,
	})
	baseConfig["inbounds"] = inbounds

	// Build outbounds
	var outbounds []map[string]any

	rawConfig := node.RawConfig
	if len(rawConfig) == 0 && node.RawLink != "" {
		if parsed, err := sub.ParseSingleURI(node.RawLink); err == nil && len(parsed.RawConfig) > 0 {
			rawConfig = parsed.RawConfig
			if node.Protocol == "" {
				node.Protocol = parsed.Protocol
			}
		}
	}

	if len(rawConfig) > 0 {
		if IsXHTTP(node) {
			socksPort := DefaultXrayPort
			if len(xrayPort) > 0 && xrayPort[0] > 0 {
				socksPort = xrayPort[0]
			}
			outbound := map[string]any{
				"type":        "socks",
				"tag":         "proxy",
				"server":      "127.0.0.1",
				"server_port": socksPort,
				"version":     "5",
				"network":     []string{"tcp", "udp"},
			}
			outbounds = append(outbounds, outbound)
		} else {
			rawCopy := make(map[string]any)
			maps.Copy(rawCopy, rawConfig)
			if proxyIP != "" {
				rawCopy["server"] = proxyIP
			}
			outbound := convertToSingboxOutbound(rawCopy, node.Protocol, proxyServer)
			outbound["tag"] = "proxy"
			outbounds = append(outbounds, outbound)
		}
	} else {
		return opts, fmt.Errorf("node lacks raw_config and raw_link could not be parsed")
	}

	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	baseConfig["outbounds"] = outbounds

	if prepared != nil && prepared.Policy != nil && prepared.Policy.Enabled {
		if err := applyRouting(baseConfig, prepared, mode, proxyServer); err != nil {
			return opts, err
		}
	}
	if prepared != nil && prepared.Managed {
		for _, outbound := range outbounds {
			if outbound["tag"] == "proxy" {
				switch outbound["type"] {
				case "socks", "http", "shadowsocks", "vmess", "vless", "trojan", "hysteria", "hysteria2":
				default:
					return opts, fmt.Errorf("unsupported managed VPN protocol %v", outbound["type"])
				}
			}
			if outbound["tag"] == "proxy" {
				outbound["routing_mark"] = TransportMark
			} else {
				outbound["routing_mark"] = DirectMark
			}
		}
		// Dedicated bootstrap resolver cannot be selected by user routing rules.
		outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "bootstrap", "routing_mark": BootstrapMark})
		baseConfig["outbounds"] = outbounds
		dns := baseConfig["dns"].(map[string]any)
		servers := dns["servers"].([]map[string]any)
		servers = append(servers, map[string]any{"type": "udp", "tag": "dns-bootstrap", "server": "1.1.1.1", "detour": "bootstrap"})
		dns["servers"] = servers
		for _, outbound := range outbounds {
			outbound["domain_resolver"] = "dns-bootstrap"
		}
		if rules, ok := dns["rules"].([]map[string]any); ok {
			for _, rule := range rules {
				if domains, ok := rule["domain"].([]string); ok && len(domains) == 1 && domains[0] == proxyServer {
					rule["server"] = "dns-bootstrap"
				}
			}
		}
		if mode == "tun" {
			baseConfig["inbounds"].([]map[string]any)[0]["address"] = []string{"172.19.0.1/24", "fdfe:dcba:9876::1/126"}
		}
	}
	jsonBytes, err := json.MarshalIndent(baseConfig, "", "  ")
	if err != nil {
		return opts, err
	}

	// Use context-aware unmarshaling (needed for DNS transport registry)
	opts, err = singJson.UnmarshalExtendedContext[option.Options](ctx, jsonBytes)
	if err != nil {
		return opts, fmt.Errorf("failed to parse generated sing-box JSON: %w", err)
	}

	return opts, nil
}

// convertToSingboxOutbound converts from Clash/subscription format to sing-box format
func convertToSingboxOutbound(raw map[string]any, protocolHint string, defaultServerName string) map[string]any {
	out := make(map[string]any)
	// Native sing-box outbounds already have the correct schema. Rebuilding them
	// as Clash nodes loses nested TLS/transport and protocol-specific options.
	if _, native := raw["server_port"]; native {
		maps.Copy(out, raw)
		if tls, ok := raw["tls"].(map[string]any); ok && tls["server_name"] == nil && net.ParseIP(defaultServerName) == nil && defaultServerName != "" {
			copyTLS := make(map[string]any, len(tls)+1)
			maps.Copy(copyTLS, tls)
			copyTLS["server_name"] = defaultServerName
			out["tls"] = copyTLS
		}
		return out
	}

	// Determine protocol type
	typ, _ := raw["type"].(string)
	typ = strings.ToLower(typ)
	protocolHint = strings.ToLower(protocolHint)

	var proto string
	switch typ {
	case "tcp", "ws", "grpc", "quic", "h2", "http", "httpupgrade", "xhttp", "splithttp":
		proto = protocolHint
	case "ss":
		proto = "shadowsocks"
	case "hy2", "hysteria2":
		proto = "hysteria2"
	case "hy", "hysteria":
		proto = "hysteria"
	default:
		if typ != "" {
			proto = typ
		} else {
			proto = protocolHint
		}
	}
	out["type"] = proto

	// Server address
	if server, ok := raw["server"].(string); ok && server != "" {
		out["server"] = server
	} else if address, ok := raw["address"].(string); ok && address != "" {
		out["server"] = address
	}

	// Server port
	if port, ok := raw["port"].(float64); ok {
		out["server_port"] = int(port)
	} else if port, ok := raw["port"].(int); ok {
		out["server_port"] = port
	} else if pStr, ok := raw["port"].(string); ok && pStr != "" {
		var p int
		if _, err := fmt.Sscanf(pStr, "%d", &p); err == nil {
			out["server_port"] = p
		}
	} else if port, ok := raw["server_port"].(float64); ok {
		out["server_port"] = int(port)
	} else if port, ok := raw["server_port"].(int); ok {
		out["server_port"] = port
	} else if pStr, ok := raw["server_port"].(string); ok && pStr != "" {
		var p int
		if _, err := fmt.Sscanf(pStr, "%d", &p); err == nil {
			out["server_port"] = p
		}
	}

	// UUID (for vless, vmess)
	if uuid, ok := raw["uuid"].(string); ok && uuid != "" {
		out["uuid"] = uuid
	}

	// Flow (for vless)
	if flow, ok := raw["flow"].(string); ok && flow != "" {
		out["flow"] = flow
	}

	// Password / Auth (for hysteria2, hysteria, trojan, shadowsocks)
	if password, ok := raw["password"].(string); ok && password != "" {
		out["password"] = password
	} else if auth, ok := raw["auth"].(string); ok && auth != "" {
		out["password"] = auth
	}

	if proto == "hysteria" {
		if password, ok := out["password"]; ok {
			out["auth_str"] = password
			delete(out, "password")
		}
		if auth, ok := raw["auth-str"]; ok {
			out["auth_str"] = auth
		}
		if obfs, ok := raw["obfs"].(string); ok {
			out["obfs"] = obfs
		}
	}
	if packetEncoding, ok := raw["packet-encoding"].(string); ok && (proto == "vless" || proto == "vmess") {
		out["packet_encoding"] = packetEncoding
	}

	// Encryption / Cipher / Method
	switch proto {
	case "shadowsocks":
		if plugin, ok := raw["plugin"].(string); ok && plugin != "" {
			name, options, _ := strings.Cut(plugin, ";")
			if name == "obfs" {
				name = "obfs-local"
			}
			out["plugin"] = name
			if opts, ok := raw["plugin-opts"].(map[string]any); ok {
				var parts []string
				for k, v := range opts {
					if name == "obfs-local" {
						switch k {
						case "mode":
							k = "obfs"
						case "host":
							k = "obfs-host"
						}
					}
					if enabled, ok := v.(bool); ok {
						if enabled {
							parts = append(parts, k)
						}
					} else {
						parts = append(parts, k+"="+fmt.Sprint(v))
					}
				}
				sort.Strings(parts)
				options = strings.Join(parts, ";")
			}
			if options != "" {
				out["plugin_opts"] = options
			}
		}
		if cipher, ok := raw["cipher"].(string); ok && cipher != "" {
			out["method"] = cipher
		}
	case "vmess":
		if cipher, ok := raw["cipher"].(string); ok && cipher != "" {
			out["security"] = cipher
		} else {
			out["security"] = "auto"
		}
		if alterID, ok := raw["alterId"].(float64); ok {
			out["alter_id"] = int(alterID)
		} else if alterID, ok := raw["alterId"].(int); ok {
			out["alter_id"] = alterID
		} else if aidStr, ok := raw["alterId"].(string); ok && aidStr != "" {
			var aid int
			if _, err := fmt.Sscanf(aidStr, "%d", &aid); err == nil {
				out["alter_id"] = aid
			}
		}
	case "vless":
		if encryption, ok := raw["encryption"].(string); ok && encryption != "none" && encryption != "" {
			out["encryption"] = encryption
		}
	}

	// Network: sing-box L4 (tcp/udp)
	hasUDP, _ := raw["udp"].(bool)
	hasFlow := raw["flow"] != nil && raw["flow"] != ""
	if hasUDP && !hasFlow && proto != "hysteria2" && proto != "hysteria" {
		out["network"] = []string{"tcp", "udp"}
	}

	// Transport (grpc, ws, http/h2, httpupgrade, xhttp)
	networkType, _ := raw["network"].(string)
	networkType = strings.ToLower(networkType)

	if networkType == "grpc" || typ == "grpc" || raw["grpc-opts"] != nil {
		grpcMap := map[string]any{
			"type": "grpc",
		}
		if sn, ok := raw["serviceName"].(string); ok && sn != "" {
			grpcMap["service_name"] = sn
		} else if sn, ok := raw["service_name"].(string); ok && sn != "" {
			grpcMap["service_name"] = sn
		}
		if gOpts, ok := raw["grpc-opts"].(map[string]any); ok {
			if sn, ok := gOpts["grpc-service-name"].(string); ok && sn != "" {
				grpcMap["service_name"] = sn
			} else if sn, ok := gOpts["serviceName"].(string); ok && sn != "" {
				grpcMap["service_name"] = sn
			} else if sn, ok := gOpts["service_name"].(string); ok && sn != "" {
				grpcMap["service_name"] = sn
			}
		}
		out["transport"] = grpcMap
	} else if networkType == "ws" || typ == "ws" || raw["ws-opts"] != nil {
		wsMap := map[string]any{
			"type": "ws",
		}
		if p, ok := raw["path"].(string); ok && p != "" {
			wsMap["path"] = p
		}
		if h, ok := raw["host"].(string); ok && h != "" {
			wsMap["headers"] = map[string]string{"Host": h}
		}
		if wsOpts, ok := raw["ws-opts"].(map[string]any); ok {
			if p, ok := wsOpts["path"].(string); ok && p != "" {
				wsMap["path"] = p
			}
			if h, ok := wsOpts["headers"].(map[string]any); ok && len(h) > 0 {
				headersMap := make(map[string]string)
				for hk, hv := range h {
					if s, ok := hv.(string); ok {
						headersMap[hk] = s
					}
				}
				if len(headersMap) > 0 {
					wsMap["headers"] = headersMap
				}
			}
			if maxEarlyData, ok := wsOpts["max-early-data"].(float64); ok {
				wsMap["max_early_data"] = uint32(maxEarlyData)
			} else if maxEarlyData, ok := wsOpts["max-early-data"].(int); ok {
				wsMap["max_early_data"] = uint32(maxEarlyData)
			}
			if earlyDataHeaderName, ok := wsOpts["early-data-header-name"].(string); ok {
				wsMap["early_data_header_name"] = earlyDataHeaderName
			}
		}
		out["transport"] = wsMap
	} else if networkType == "h2" || typ == "h2" || networkType == "http" || typ == "http" || raw["h2-opts"] != nil {
		h2Map := map[string]any{
			"type": "http",
		}
		if p, ok := raw["path"].(string); ok && p != "" {
			h2Map["path"] = p
		}
		if h, ok := raw["host"].(string); ok && h != "" {
			h2Map["host"] = []string{h}
		}
		if h2Opts, ok := raw["h2-opts"].(map[string]any); ok {
			if p, ok := h2Opts["path"].(string); ok && p != "" {
				h2Map["path"] = p
			}
			if host, ok := h2Opts["host"].([]any); ok && len(host) > 0 {
				var hosts []string
				for _, item := range host {
					if s, ok := item.(string); ok {
						hosts = append(hosts, s)
					}
				}
				h2Map["host"] = hosts
			}
		}
		out["transport"] = h2Map
	} else if networkType == "httpupgrade" || typ == "httpupgrade" {
		httpUpgradeMap := map[string]any{
			"type": "httpupgrade",
		}
		if p, ok := raw["path"].(string); ok && p != "" {
			httpUpgradeMap["path"] = p
		}
		if h, ok := raw["host"].(string); ok && h != "" {
			httpUpgradeMap["host"] = h
		}
		out["transport"] = httpUpgradeMap
	} else if networkType == "xhttp" || typ == "xhttp" || networkType == "splithttp" || typ == "splithttp" {
		httpMap := map[string]any{
			"type": "http",
		}
		if p, ok := raw["path"].(string); ok && p != "" {
			httpMap["path"] = p
		}
		if h, ok := raw["host"].(string); ok && h != "" {
			httpMap["host"] = []string{h}
		} else if sni, ok := raw["sni"].(string); ok && sni != "" {
			httpMap["host"] = []string{sni}
		}
		out["transport"] = httpMap
	}

	// Hysteria 2 specific options
	if proto == "hysteria2" || proto == "hysteria" {
		if up, ok := raw["up"].(float64); ok {
			out["up_mbps"] = int(up)
		} else if up, ok := raw["up"].(int); ok {
			out["up_mbps"] = up
		} else if upStr, ok := raw["up"].(string); ok {
			var mbps int
			if _, err := fmt.Sscanf(upStr, "%d", &mbps); err == nil {
				out["up_mbps"] = mbps
			}
		}
		if down, ok := raw["down"].(float64); ok {
			out["down_mbps"] = int(down)
		} else if down, ok := raw["down"].(int); ok {
			out["down_mbps"] = down
		} else if downStr, ok := raw["down"].(string); ok {
			var mbps int
			if _, err := fmt.Sscanf(downStr, "%d", &mbps); err == nil {
				out["down_mbps"] = mbps
			}
		}
		if obfsType, ok := raw["obfs"].(string); ok && obfsType != "" && proto == "hysteria2" {
			obfsPassword, _ := raw["obfs-password"].(string)
			out["obfs"] = map[string]any{
				"type":     obfsType,
				"password": obfsPassword,
			}
		}
	}

	// TLS block
	tlsEnabled := false
	if tls, ok := raw["tls"].(bool); ok && tls {
		tlsEnabled = true
	} else if tlsStr, ok := raw["tls"].(string); ok && (tlsStr == "1" || tlsStr == "true") {
		tlsEnabled = true
	}
	if security, ok := raw["security"].(string); ok && security != "none" && security != "" {
		tlsEnabled = true
	}
	if proto == "hysteria2" || proto == "hysteria" || proto == "trojan" {
		tlsEnabled = true
	}

	servername := ""
	if sn, ok := raw["servername"].(string); ok && sn != "" {
		servername = sn
	} else if sn, ok := raw["sni"].(string); ok && sn != "" {
		servername = sn
	} else if peer, ok := raw["peer"].(string); ok && peer != "" {
		servername = peer
	}
	if servername == "" && defaultServerName != "" && net.ParseIP(defaultServerName) == nil {
		servername = defaultServerName
	}

	fingerprint := "chrome"
	if fp, ok := raw["client-fingerprint"].(string); ok && fp != "" {
		fingerprint = fp
	} else if fp, ok := raw["fp"].(string); ok && fp != "" {
		fingerprint = fp
	}

	var realityPublicKey string
	var realityShortID string
	if realityOpts, ok := raw["reality-opts"].(map[string]any); ok {
		if pk, ok := realityOpts["public-key"].(string); ok {
			realityPublicKey = pk
		}
		if sid, ok := realityOpts["short-id"].(string); ok {
			realityShortID = sid
		}
	}
	if pk, ok := raw["pbk"].(string); ok && realityPublicKey == "" {
		realityPublicKey = pk
	}
	if sid, ok := raw["sid"].(string); ok && realityShortID == "" {
		realityShortID = sid
	}

	var alpnList []string
	if alpn, ok := raw["alpn"].([]any); ok {
		for _, a := range alpn {
			if s, ok := a.(string); ok && s != "" {
				alpnList = append(alpnList, s)
			}
		}
	} else if alpn, ok := raw["alpn"].([]string); ok {
		alpnList = alpn
	} else if alpnStr, ok := raw["alpn"].(string); ok && alpnStr != "" {
		for a := range strings.SplitSeq(alpnStr, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				alpnList = append(alpnList, a)
			}
		}
	}
	if proto == "hysteria2" && len(alpnList) == 0 {
		alpnList = []string{"h3"}
	} else if (networkType == "xhttp" || typ == "xhttp" || networkType == "splithttp" || typ == "splithttp") && len(alpnList) == 0 {
		alpnList = []string{"h2"}
	}

	skipCertVerify := false
	if scv, ok := raw["skip-cert-verify"].(bool); ok && scv {
		skipCertVerify = true
	} else if insecure, ok := raw["insecure"].(bool); ok && insecure {
		skipCertVerify = true
	} else if scv, ok := raw["skip-cert-verify"].(string); ok && (scv == "1" || scv == "true") {
		skipCertVerify = true
	} else if insecure, ok := raw["insecure"].(string); ok && (insecure == "1" || insecure == "true") {
		skipCertVerify = true
	}

	if tlsEnabled || realityPublicKey != "" {
		tlsBlock := map[string]any{
			"enabled": true,
		}
		if servername != "" {
			tlsBlock["server_name"] = servername
		}
		if len(alpnList) > 0 {
			tlsBlock["alpn"] = alpnList
		}
		if skipCertVerify {
			tlsBlock["insecure"] = true
		}
		if fingerprint != "" && proto != "hysteria2" && proto != "hysteria" {
			tlsBlock["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": fingerprint,
			}
		}
		if realityPublicKey != "" {
			tlsBlock["reality"] = map[string]any{
				"enabled":    true,
				"public_key": realityPublicKey,
				"short_id":   realityShortID,
			}
		}
		out["tls"] = tlsBlock
	}

	return out
}

func truthy(v any) bool {
	switch v := v.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}
func stringList(v any) []string {
	var result []string
	switch v := v.(type) {
	case []string:
		return v
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				result = append(result, s)
			}
		}
	case string:
		for item := range strings.SplitSeq(v, ",") {
			if s := strings.TrimSpace(item); s != "" {
				result = append(result, s)
			}
		}
	}
	return result
}
