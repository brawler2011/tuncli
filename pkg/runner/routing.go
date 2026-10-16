package runner

import (
	"fmt"
	"maps"
	"net"

	"github.com/brawler2011/tuncli/pkg/routing"
)

func applyRouting(base map[string]any, p *routing.Prepared, mode, server string) error {
	if err := p.Policy.Validate(); err != nil {
		return err
	}
	route := base["route"].(map[string]any)
	rules := route["rules"].([]map[string]any)
	// Lookup skips FakeIP transports. Resolving here uses the ordered real-DNS
	// policy before a route is selected, including after FakeIP domain recovery.
	rules = append(rules, map[string]any{"action": "resolve", "strategy": "prefer_ipv4"})
	dnsRules := []map[string]any{}
	if server != "" && net.ParseIP(server) == nil {
		dnsRules = append(dnsRules, map[string]any{"domain": []string{server}, "server": "dns-local"})
	}
	if mode == "tun" {
		dnsRules = append(dnsRules, map[string]any{"inbound": []string{"tun-in"}, "query_type": []string{"A", "AAAA"}, "server": "dns-fakeip"})
	}
	for _, e := range p.Entries() {
		r := maps.Clone(e.Match)
		r["outbound"] = e.Outbound.Tag()
		rules = append(rules, r)
		d := maps.Clone(e.Match)
		d["server"] = e.Outbound.DNS()
		dnsRules = append(dnsRules, d)
	}
	var sets []map[string]any
	for _, preset := range routing.Presets {
		if _, enabled := p.Policy.Presets[preset.ID]; !enabled {
			continue
		}
		path := p.Paths[preset.ID]
		if path == "" {
			return fmt.Errorf("preset %s has no verified rule file", preset.ID)
		}
		sets = append(sets, map[string]any{"type": "local", "tag": "preset-" + preset.ID, "format": "binary", "path": path})
	}
	route["rules"] = rules
	route["rule_set"] = sets
	route["final"] = p.Policy.Default.Tag()
	servers := []map[string]any{
		{"type": "https", "tag": "dns-remote", "server": "1.1.1.1", "path": "/dns-query", "detour": "proxy"},
		{"type": "udp", "tag": "dns-local", "server": "1.1.1.1", "detour": "direct"},
	}
	if mode == "tun" {
		if p.FakeIPPath == "" {
			return fmt.Errorf("missing persistent FakeIP cache path")
		}
		servers = append(servers, map[string]any{"type": "fakeip", "tag": "dns-fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"})
		base["inbounds"].([]map[string]any)[0]["address"] = []string{"172.19.0.1/24", "fdfe:dcba:9876::1/126"}
		base["experimental"] = map[string]any{"cache_file": map[string]any{"enabled": true, "path": p.FakeIPPath, "store_fakeip": true}}
	}
	base["dns"] = map[string]any{"servers": servers, "rules": dnsRules, "final": p.Policy.Default.DNS(), "strategy": "prefer_ipv4", "independent_cache": true}
	// Bootstrap and direct DNS dials never consult the policy or FakeIP.
	for _, o := range base["outbounds"].([]map[string]any) {
		o["domain_resolver"] = "dns-local"
	}
	return nil
}
