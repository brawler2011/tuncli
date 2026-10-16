package runner

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func routingNode() *config.Node {
	return &config.Node{Protocol: "ss", Server: "192.0.2.1", RawConfig: map[string]any{"type": "ss", "server": "192.0.2.1", "port": 8388, "cipher": "aes-128-gcm", "password": "test"}}
}
func preparedFixture(t *testing.T, def routing.Outbound) *routing.Prepared {
	t.Helper()
	dir := t.TempDir()
	p := routing.New()
	p.Enabled = true
	p.Default = def
	p.Presets = map[string]routing.Outbound{"ru": routing.Direct, "ai": routing.VPN}
	p.Rules = []routing.Rule{{Domain: "my.itmo.ru", Outbound: routing.Direct}, {Domain: "google.com", Suffix: true, Outbound: routing.Direct}, {Domain: "gemini.google.com", Outbound: routing.VPN}, {Domain: "itmo.ru", Suffix: true, Outbound: routing.VPN}}
	prepared := &routing.Prepared{Policy: p, Paths: map[string]string{}, FakeIPPath: filepath.Join(dir, "fakeip.db")}
	for id, domains := range map[string][]string{"ru": {"ru", "ozon.ru", "gosuslugi.ru", "gemini.google.com"}, "ai": {"gemini.google.com", "deepmind.google", "overlap.ru"}} {
		var b bytes.Buffer
		require.NoError(t, srs.Write(&b, option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: "default", DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: domains}}}}, 3))
		path := filepath.Join(dir, id+".srs")
		require.NoError(t, os.WriteFile(path, b.Bytes(), 0644))
		prepared.Paths[id] = path
	}
	return prepared
}
func TestRoutingLegacyAndModes(t *testing.T) {
	ctx := singboxContext(context.Background())
	for _, mode := range []string{"tun", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			legacy, err := BuildSingboxConfig(ctx, routingNode(), mode)
			require.NoError(t, err)
			p := preparedFixture(t, routing.VPN)
			p.Policy.Enabled = false
			disabled, err := BuildSingboxConfigWithPolicy(ctx, routingNode(), mode, p)
			require.NoError(t, err)
			assert.Equal(t, legacy, disabled)
			p.Policy.Enabled = true
			opts, err := BuildSingboxConfigWithPolicy(ctx, routingNode(), mode, p)
			require.NoError(t, err)
			assert.True(t, opts.DNS.IndependentCache)
			assert.Equal(t, "proxy", opts.Route.Final)
			assert.Len(t, opts.Route.RuleSet, 2)
			if mode == "tun" {
				assert.Equal(t, "gvisor", opts.Inbounds[0].Options.(*option.TunInboundOptions).Stack)
				assert.Len(t, opts.Inbounds[0].Options.(*option.TunInboundOptions).Address, 2)
				require.NotNil(t, opts.Experimental)
				assert.True(t, opts.Experimental.CacheFile.StoreFakeIP)
			} else {
				assert.Nil(t, opts.Experimental)
				assert.Len(t, opts.DNS.Servers, 2)
			}
			node := &config.Node{Protocol: "vless", Server: "192.0.2.1", RawConfig: map[string]any{"type": "vless", "server": "192.0.2.1", "port": 443, "uuid": "00000000-0000-4000-8000-000000000001", "network": "xhttp"}}
			opts, err = BuildSingboxConfigWithPolicy(ctx, node, mode, p, 12345)
			require.NoError(t, err)
			assert.Equal(t, "socks", opts.Outbounds[0].Type)
			assert.Equal(t, "proxy", opts.Route.Final)
		})
	}
}

// Run the actual embedded engine without TUN or listening inbounds. Only real
// resolver transports are replaced by deterministic, distinct hosts fixtures.
func TestRoutingDNSFakeIPPersistence(t *testing.T) {
	for _, def := range []routing.Outbound{routing.VPN, routing.Direct} {
		t.Run(string(def), func(t *testing.T) {
			p := preparedFixture(t, def)
			cases := map[string]routing.Outbound{"ozon.ru": routing.Direct, "sub.ozon.ru": routing.Direct, "overlap.ru": routing.VPN, "gosuslugi.ru": routing.Direct, "gemini.google.com": routing.VPN, "deepmind.google": routing.VPN, "my.itmo.ru": routing.Direct, "sub.itmo.ru": routing.VPN, "itmo.ru": routing.VPN, "other.google.com": routing.Direct, "unknown.example": def}
			expected := map[routing.Outbound]string{routing.Direct: "203.0.113.10", routing.VPN: "203.0.113.20"}
			saved := map[string]netip.Addr{}
			for restart := range 2 {
				ctx := service.ContextWithDefaultRegistry(singboxContext(context.Background()))
				opts, err := BuildSingboxConfigWithPolicy(ctx, routingNode(), "tun", p)
				require.NoError(t, err)
				opts.Inbounds = nil
				opts.Route.AutoDetectInterface = false
				for i, o := range []routing.Outbound{routing.VPN, routing.Direct} {
					hosts := map[string][]string{}
					for name := range cases {
						hosts[name] = []string{expected[o], "2001:db8::1"}
					}
					raw, err := singJSON.Marshal(map[string]any{"type": "hosts", "tag": o.DNS(), "predefined": hosts})
					require.NoError(t, err)
					server, err := singJSON.UnmarshalExtendedContext[option.DNSServerOptions](ctx, raw)
					require.NoError(t, err)
					opts.DNS.Servers[i] = server
				}
				instance, err := box.New(box.Options{Context: ctx, Options: opts})
				require.NoError(t, err)
				require.NoError(t, instance.Start())
				router := service.FromContext[adapter.DNSRouter](ctx)
				require.NotNil(t, router)
				manager := service.FromContext[adapter.DNSTransportManager](ctx)
				require.NotNil(t, manager)
				if restart == 1 {
					for key, address := range saved {
						recovered, ok := manager.FakeIP().Store().Lookup(address)
						require.True(t, ok, key)
						assert.Contains(t, key, recovered)
					}
				}
				for domain, outbound := range cases {
					for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
						request := new(dns.Msg)
						request.SetQuestion(dns.Fqdn(domain), qtype)
						qctx := adapter.WithContext(ctx, &adapter.InboundContext{Inbound: "tun-in"})
						response, err := router.Exchange(qctx, request, adapter.DNSQueryOptions{})
						require.NoError(t, err)
						require.Len(t, response.Answer, 1)
						var address netip.Addr
						if qtype == dns.TypeA {
							address = netip.MustParseAddr(response.Answer[0].(*dns.A).A.String())
							assert.True(t, netip.MustParsePrefix("198.18.0.0/15").Contains(address))
						} else {
							address = netip.MustParseAddr(response.Answer[0].(*dns.AAAA).AAAA.String())
							assert.True(t, netip.MustParsePrefix("fc00::/18").Contains(address))
						}
						key := domain + dns.TypeToString[qtype]
						if restart == 0 {
							saved[key] = address
						} else {
							assert.Equal(t, saved[key], address)
						}
						recovered, ok := manager.FakeIP().Store().Lookup(address)
						require.True(t, ok)
						assert.Equal(t, domain, recovered)
						chosen := ""
						for _, rule := range instance.Router().Rules() {
							if rule.Action().Type() != "route" {
								continue
							}
							metadata := &adapter.InboundContext{Domain: recovered}
							if rule.Match(metadata) {
								chosen = rule.Action().String()
								break
							}
						}
						if chosen == "" {
							chosen = opts.Route.Final
						}
						assert.Contains(t, chosen, outbound.Tag(), domain)
					}
					// Internal resolution retains inbound metadata but must skip FakeIP and
					// select the same policy. Independent caches must not return a fake answer.
					qctx := adapter.WithContext(ctx, &adapter.InboundContext{Inbound: "tun-in"})
					addresses, err := router.Lookup(qctx, domain, adapter.DNSQueryOptions{})
					require.NoError(t, err)
					assert.Contains(t, addresses, netip.MustParseAddr(expected[outbound]), domain)
					for _, a := range addresses {
						assert.False(t, manager.FakeIP().Store().Contains(a))
					}
				}
				require.NoError(t, instance.Close())
			}
		})
	}
}
