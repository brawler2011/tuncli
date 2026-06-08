package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/brawler2011/tuncli/pkg/config"

	"github.com/sagernet/sing-box/option"
	singJson "github.com/sagernet/sing/common/json"
)

func BuildSingboxConfig(ctx context.Context, node *config.Node, mode string) (option.Options, error) {
	var opts option.Options

	// Determine the proxy server address for bypass rules
	proxyServer := ""
	if node != nil {
		proxyServer = node.Server
	}

	var routeRules []map[string]interface{}

	if mode == "tun" {
		routeRules = append(routeRules, map[string]interface{}{
			"port":   []int{53},
			"action": "hijack-dns",
		})
	}

	proxyIP := ""
	if net.ParseIP(proxyServer) != nil {
		proxyIP = proxyServer
		routeRules = append(routeRules, map[string]interface{}{
			"ip_cidr":  []string{proxyServer + "/32"},
			"outbound": "direct",
		})
	} else if proxyServer != "" {
		if ips, err := net.LookupIP(proxyServer); err == nil {
			for _, ip := range ips {
				if ipv4 := ip.To4(); ipv4 != nil {
					proxyIP = ipv4.String()
					routeRules = append(routeRules, map[string]interface{}{
						"ip_cidr":  []string{ipv4.String() + "/32"},
						"outbound": "direct",
					})
				}
			}
		}
		routeRules = append(routeRules, map[string]interface{}{
			"domain":   []string{proxyServer},
			"outbound": "direct",
		})
	}

	dnsRules := []map[string]interface{}{}
	if proxyServer != "" && net.ParseIP(proxyServer) == nil {
		dnsRules = append(dnsRules, map[string]interface{}{
			"domain": []string{proxyServer},
			"server": "dns-local",
		})
	}
	if mode == "tun" {
		dnsRules = append(dnsRules, map[string]interface{}{
			"port":   []int{53},
			"server": "dns-remote",
		})
	}

	baseConfig := map[string]interface{}{
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{"tag": "dns-remote", "address": "tls://8.8.8.8", "detour": "proxy"},
				{"tag": "dns-local", "address": "local", "detour": "direct"},
			},
			"rules":    dnsRules,
			"final":    "dns-remote",
			"strategy": "prefer_ipv4",
		},
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"final":                 "proxy",
			"rules":                 routeRules,
		},
	}

	// Inbounds
	if mode == "tun" {
		baseConfig["inbounds"] = []map[string]interface{}{
			{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": "tuncli-tun0",
				"address":        "172.19.0.1/24",
				"auto_route":     true,
				"strict_route":   true,
				"stack":          "system",
			},
		}
	} else {
		baseConfig["inbounds"] = []map[string]interface{}{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 2080,
			},
		}
	}

	// Build outbounds
	var outbounds []map[string]interface{}

	if len(node.RawConfig) > 0 {
		rawCopy := make(map[string]interface{})
		for k, v := range node.RawConfig {
			rawCopy[k] = v
		}
		if proxyIP != "" {
			rawCopy["server"] = proxyIP
		}
		outbound := convertToSingboxOutbound(rawCopy, node.Protocol)
		outbound["tag"] = "proxy"
		outbounds = append(outbounds, outbound)
	} else {
		return opts, fmt.Errorf("node lacks raw_config, raw links not yet supported")
	}

	outbounds = append(outbounds, map[string]interface{}{"type": "direct", "tag": "direct"})
	baseConfig["outbounds"] = outbounds

	jsonBytes, err := json.MarshalIndent(baseConfig, "", "  ")
	if err != nil {
		return opts, err
	}

	fmt.Println(string(jsonBytes))

	// Use context-aware unmarshaling (needed for DNS transport registry)
	opts, err = singJson.UnmarshalExtendedContext[option.Options](ctx, jsonBytes)
	if err != nil {
		return opts, fmt.Errorf("failed to parse generated sing-box JSON: %w", err)
	}

	return opts, nil
}

// convertToSingboxOutbound converts from Clash/subscription format to sing-box format
func convertToSingboxOutbound(raw map[string]interface{}, protocolHint string) map[string]interface{} {
	out := make(map[string]interface{})

	// Use protocol hint (from node.Protocol) if raw type is a transport like "tcp"
	typ, _ := raw["type"].(string)
	switch typ {
	case "tcp", "ws", "grpc", "quic", "h2":
		out["type"] = protocolHint
		if typ != "tcp" {
			out["transport"] = typ
		}
	default:
		out["type"] = typ
	}

	// Handle both "server" and "address" (Clash meta format)
	if server, ok := raw["server"].(string); ok {
		out["server"] = server
	} else if address, ok := raw["address"].(string); ok {
		out["server"] = address
	}

	// Map port -> server_port
	if port, ok := raw["port"].(float64); ok {
		out["server_port"] = int(port)
	} else if port, ok := raw["server_port"].(float64); ok {
		out["server_port"] = int(port)
	}

	if uuid, ok := raw["uuid"].(string); ok {
		out["uuid"] = uuid
	}

	if encryption, ok := raw["encryption"].(string); ok && encryption != "none" {
		out["encryption"] = encryption
	}

	if flow, ok := raw["flow"].(string); ok {
		out["flow"] = flow
	}

	// Skip packet_encoding — it requires server-side xudp support
	// which causes empty replies or TLS errors when unsupported
	_ = raw["packet-encoding"]

	// Clash "network" = transport (tcp/ws/grpc), sing-box "network" = L4 (tcp/udp)
	// Only add network if UDP is enabled and we're not using XTLS Vision
	hasUDP, _ := raw["udp"].(bool)
	hasFlow := raw["flow"] != nil
	if hasUDP && !hasFlow {
		out["network"] = []string{"tcp", "udp"}
	}

	// TLS block: convert from Clash flat format to sing-box nested format
	tlsEnabled := false
	servername := ""
	fingerprint := "chrome"
	var realityPublicKey string
	var realityShortID string

	if tls, ok := raw["tls"].(bool); ok && tls {
		tlsEnabled = true
	}
	if security, ok := raw["security"].(string); ok && security != "none" {
		tlsEnabled = true
	}
	// Handle both "servername" (standard) and "sni" (Clash meta format)
	if sn, ok := raw["servername"].(string); ok {
		servername = sn
	} else if sn, ok := raw["sni"].(string); ok {
		servername = sn
	}
	// Handle both "client-fingerprint" and "fp" (Clash meta format)
	if fp, ok := raw["client-fingerprint"].(string); ok {
		fingerprint = fp
	} else if fp, ok := raw["fp"].(string); ok {
		fingerprint = fp
	}

	// Reality opts: handle both "reality-opts" object and flat fields (Clash meta format)
	if realityOpts, ok := raw["reality-opts"].(map[string]interface{}); ok {
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

	if tlsEnabled || realityPublicKey != "" {
		tlsBlock := map[string]interface{}{
			"enabled": tlsEnabled || realityPublicKey != "",
		}
		if servername != "" {
			tlsBlock["server_name"] = servername
		}
		if fingerprint != "" {
			tlsBlock["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": fingerprint,
			}
		}
		if realityPublicKey != "" {
			tlsBlock["reality"] = map[string]interface{}{
				"enabled":    true,
				"public_key": realityPublicKey,
				"short_id":   realityShortID,
			}
		}
		out["tls"] = tlsBlock
	}

	// Copy any remaining fields we might have missed
	for k, v := range raw {
		switch k {
		case "type", "server", "address", "port", "server_port", "uuid", "encryption",
			"flow", "network", "tls", "security", "servername", "sni",
			"client-fingerprint", "fp", "reality-opts", "pbk", "sid",
			"name", "packet-encoding", "host", "path", "udp", "spx":
			// Already handled or Clash-specific
		default:
			out[k] = v
		}
	}

	return out
}
