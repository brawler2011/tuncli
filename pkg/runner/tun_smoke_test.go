//go:build linux && tun_smoke

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	singJSON "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const smokePassword = "tuncli-isolated-fixture"

type smokeDNSEvent struct{ Domain, Resolver, Source string }

func smokeDirectory(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TUN_SMOKE_DIR")
	require.NotEmpty(t, dir, "run make test-tun; this test requires isolated namespaces")
	host := os.Getenv("TUN_SMOKE_HOST_NETNS")
	require.NotEmpty(t, host)
	current, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	require.NotEqual(t, host, current, "refusing to run in the host network namespace")
	return dir
}
func smokeMarker(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, nil, 0600))
}

// Fixture runs across the virtual WAN from the client. The proxy is a real
// Shadowsocks TCP/UDP inbound. Source addresses distinguish forwarded traffic
// from direct client connections without inspecting sing-box's rule objects.
func TestTUNSmokeFixture(t *testing.T) {
	dir := smokeDirectory(t)
	events, err := os.OpenFile(filepath.Join(dir, "dns.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, events.Close()) })
	var mu sync.Mutex
	answer := func(request *dns.Msg, resolver, source string) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		for _, q := range request.Question {
			mu.Lock()
			err := json.NewEncoder(events).Encode(smokeDNSEvent{strings.TrimSuffix(q.Name, "."), resolver, source})
			mu.Unlock()
			if err != nil {
				t.Errorf("record DNS: %v", err)
			}
			header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
			switch q.Qtype {
			case dns.TypeA:
				response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.ParseIP("203.0.113.10")})
			case dns.TypeAAAA:
				response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::10")})
			}
		}
		return response
	}
	packet, err := net.ListenPacket("udp4", "192.0.2.2:5353")
	require.NoError(t, err)
	udp := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if err := w.WriteMsg(answer(r, "direct", w.RemoteAddr().String())); err != nil {
			t.Errorf("DNS response: %v", err)
		}
	})}
	go func() {
		if err := udp.ActivateAndServe(); err != nil {
			t.Errorf("DNS serve: %v", err)
		}
	}()
	t.Cleanup(func() { assert.NoError(t, udp.Shutdown()) })
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close() //nolint:errcheck
		payload, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		message := new(dns.Msg)
		if err = message.Unpack(payload); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		body, err := answer(message, "vpn", r.RemoteAddr).Pack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(body)
	}))
	require.NoError(t, doh.Listener.Close())
	doh.Listener, err = net.Listen("tcp4", "192.0.2.2:8443")
	require.NoError(t, err)
	doh.StartTLS()
	t.Cleanup(doh.Close)
	marker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		route := "unexpected:" + host
		if host == "192.0.2.1" || host == "fd00:2026::1" {
			route = "direct"
		}
		if host == "192.0.2.2" || host == "fd00:2026::2" {
			route = "vpn"
		}
		_, _ = io.WriteString(w, route)
	})
	for _, address := range []string{"203.0.113.10:8080", "[2001:db8::10]:8080"} {
		listener, err := net.Listen("tcp", address)
		require.NoError(t, err)
		server := &http.Server{Handler: marker, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = server.Serve(listener) }()
		t.Cleanup(func() { assert.NoError(t, server.Close()) })
	}
	// UDP echo records the source just like the HTTP marker.
	for _, address := range []string{"203.0.113.10:8081", "[2001:db8::10]:8081"} {
		conn, err := net.ListenPacket("udp", address)
		require.NoError(t, err)
		go func() {
			buffer := make([]byte, 2048)
			for {
				_, peer, err := conn.ReadFrom(buffer)
				if err != nil {
					return
				}
				host, _, _ := net.SplitHostPort(peer.String())
				route := "direct"
				if host == "192.0.2.2" || host == "fd00:2026::2" {
					route = "vpn"
				}
				_, _ = conn.WriteTo([]byte(route), peer)
			}
		}()
		t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	registry := inboundRegistry()
	shadowsocks.RegisterInbound(registry)
	ctx = box.Context(ctx, registry, outboundRegistry(), endpointRegistry(), dnsTransportRegistry(), serviceRegistry())
	raw := fmt.Sprintf(`{"inbounds":[{"type":"shadowsocks","listen":"192.0.2.2","listen_port":8388,"method":"aes-128-gcm","password":%q}],"outbounds":[{"type":"direct","tag":"direct","inet4_bind_address":"192.0.2.2","inet6_bind_address":"fd00:2026::2"}],"route":{"final":"direct"}}`, smokePassword)
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(raw))
	require.NoError(t, err)
	opts.Log = &option.LogOptions{Level: "error", DisableColor: true}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { assert.NoError(t, instance.Close()) })
	smokeMarker(t, filepath.Join(dir, "fixture-ready"))
	deadline := time.Now().Add(75 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "done")); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("client did not finish")
}

func TestTUNSmoke(t *testing.T) {
	dir := smokeDirectory(t)
	for _, def := range []routing.Outbound{routing.VPN, routing.Direct} {
		t.Run(string(def), func(t *testing.T) {
			prepared := preparedFixture(t, def)
			cases := []struct {
				domain string
				route  routing.Outbound
			}{{"ozon.ru", routing.Direct}, {"gosuslugi.ru", routing.Direct}, {"gemini.google.com", routing.VPN}, {"my.itmo.ru", routing.Direct}, {"sub.itmo.ru", routing.VPN}, {"overlap.ru", routing.VPN}, {"unknown.example", def}}
			saved := map[string]string{}
			for restart := range 2 {
				ctx, cancelTUN := context.WithCancel(service.ContextWithDefaultRegistry(singboxContext(context.Background())))
				t.Cleanup(cancelTUN)
				node := routingNode()
				node.Server = "192.0.2.2"
				node.RawConfig["server"] = node.Server
				node.RawConfig["password"] = smokePassword
				opts, err := BuildSingboxConfigWithPolicy(ctx, node, "tun", prepared)
				require.NoError(t, err)
				opts.Log = &option.LogOptions{Level: "debug", DisableColor: true, Output: filepath.Join(dir, fmt.Sprintf("engine-%s-%d.log", def, restart))}
				// Only fixture addresses and its test TLS certificate differ from production.
				opts.DNS.Servers[0].Options.(*option.RemoteHTTPSDNSServerOptions).Server = "192.0.2.2"
				opts.DNS.Servers[0].Options.(*option.RemoteHTTPSDNSServerOptions).ServerPort = 8443
				opts.DNS.Servers[0].Options.(*option.RemoteHTTPSDNSServerOptions).TLS = &option.OutboundTLSOptions{Enabled: true, Insecure: true}
				opts.DNS.Servers[1].Options.(*option.RemoteDNSServerOptions).Server = "192.0.2.2"
				opts.DNS.Servers[1].Options.(*option.RemoteDNSServerOptions).ServerPort = 5353
				stopEngine := startSmokeEngine(t, dir, ctx, opts, fmt.Sprintf("%s-%d", def, restart))
				// Close even after a failed assertion so later namespace cleanup cannot hang.
				func() {
					defer func() { cancelTUN(); stopEngine() }()
					iface, err := net.InterfaceByName("tuncli-tun0")
					require.NoError(t, err)
					addresses, err := iface.Addrs()
					require.NoError(t, err)
					prefixes := make([]netip.Prefix, 0, len(addresses))
					for _, address := range addresses {
						prefix, err := netip.ParsePrefix(address.String())
						require.NoError(t, err)
						prefixes = append(prefixes, prefix)
					}
					assert.Contains(t, prefixes, netip.MustParsePrefix("172.19.0.1/24"))
					assert.Contains(t, prefixes, netip.MustParsePrefix("fdfe:dcba:9876::1/126"))
					if restart == 1 {
						for _, tc := range cases {
							for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
								key := fmt.Sprintf("%s/%d", tc.domain, qtype)
								smokeTransfer(t, saved[key], tc.route)
							}
						}
					}

					for _, tc := range cases {
						for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
							var fake string
							var previous string
							for _, network := range []string{"udp", "tcp"} {
								request := new(dns.Msg)
								request.SetQuestion(dns.Fqdn(tc.domain), qtype)
								response, _, err := (&dns.Client{Net: network, Timeout: 3 * time.Second}).Exchange(request, "203.0.113.53:53")
								require.NoError(t, err, "%s %s", tc.domain, network)
								require.Len(t, response.Answer, 1)
								switch rr := response.Answer[0].(type) {
								case *dns.A:
									fake = rr.A.String()
									assert.True(t, strings.HasPrefix(fake, "198.18.") || strings.HasPrefix(fake, "198.19."))
								case *dns.AAAA:
									fake = rr.AAAA.String()
									assert.True(t, strings.HasPrefix(fake, "fc00:"))
								default:
									t.Fatalf("unexpected DNS answer %T", rr)
								}
								if previous != "" {
									assert.Equal(t, previous, fake, "TCP/UDP DNS mapping %s", tc.domain)
								}
								previous = fake
							}
							key := fmt.Sprintf("%s/%d", tc.domain, qtype)
							if restart == 0 {
								saved[key] = fake
							} else {
								assert.Equal(t, saved[key], fake, key)
							}
							smokeTransfer(t, fake, tc.route)
						}
					}
					for _, domain := range []string{"ozon.ru", "gemini.google.com"} {
						want := routing.Direct
						if domain == "gemini.google.com" {
							want = routing.VPN
						}
						smokePinnedTCP(t, saved[fmt.Sprintf("%s/%d", domain, dns.TypeA)], want, 22000+restart+10*int(def[0]))
					}
					smokeReusedUDP(t, saved[fmt.Sprintf("ozon.ru/%d", dns.TypeA)], saved[fmt.Sprintf("gemini.google.com/%d", dns.TypeA)])
					data, err := os.ReadFile(filepath.Join(dir, "dns.jsonl"))
					require.NoError(t, err)
					events := map[string][]smokeDNSEvent{}
					for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
						var e smokeDNSEvent
						require.NoError(t, json.Unmarshal([]byte(line), &e))
						events[e.Domain] = append(events[e.Domain], e)
					}
					for _, tc := range cases {
						require.NotEmpty(t, events[tc.domain], tc.domain)
						for _, event := range events[tc.domain] {
							assert.Equal(t, string(tc.route), event.Resolver, tc.domain)
							source, _, err := net.SplitHostPort(event.Source)
							require.NoError(t, err)
							want := "192.0.2.1"
							if tc.route == routing.VPN {
								want = "192.0.2.2"
							}
							assert.Equal(t, want, source, "DNS path %s", tc.domain)
						}
					}
				}()
				// Each scenario has a different default; isolate its DNS evidence.
				require.NoError(t, os.WriteFile(filepath.Join(dir, "dns.jsonl"), nil, 0600))
			}
		})
	}
}

// Actual kernel sockets receive only an IP; TUN must recover its saved domain.
func smokeTransfer(t *testing.T, fake string, want routing.Outbound) {
	t.Helper()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(fake, "8080") + "/")
	require.NoError(t, err, fake)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	transport.CloseIdleConnections()
	assert.Equal(t, string(want), string(body), "TCP %s", fake)
	conn, err := net.DialTimeout("udp", net.JoinHostPort(fake, "8081"), 3*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = conn.Write([]byte("route?"))
	require.NoError(t, err)
	buffer := make([]byte, 100)
	n, err := conn.Read(buffer)
	require.NoError(t, err, "UDP %s", fake)
	require.NoError(t, conn.Close())
	assert.Equal(t, string(want), string(buffer[:n]), "UDP %s", fake)
}

func smokePinnedTCP(t *testing.T, fake string, want routing.Outbound, port int) {
	t.Helper()
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("172.19.0.1"), Port: port}, Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) { sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) })
		if err != nil {
			return err
		}
		return sockErr
	}}
	transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get("http://" + net.JoinHostPort(fake, "8080") + "/")
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	assert.Equal(t, string(want), string(body), "reused source port %d", port)
}

// Run each engine lifetime in a separate process, as tuncli start does. This
// also releases duplicated TUN file descriptors and kernel sockets on restart.
func startSmokeEngine(t *testing.T, dir string, ctx context.Context, opts option.Options, label string) func() {
	t.Helper()
	path := filepath.Join(dir, "options-"+label+".json")
	payload, err := singJSON.MarshalContext(ctx, opts)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, payload, 0600))
	executable, err := os.Executable()
	require.NoError(t, err)
	child := exec.Command(executable, "-test.run=^TestTUNSmokeEngine$", "-test.timeout=60s")
	child.Env = append(os.Environ(), "TUN_SMOKE_OPTIONS="+path)
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	require.NoError(t, child.Start())
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = child.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			select {
			case <-done:
			default:
				if err := child.Process.Signal(syscall.SIGTERM); err != nil {
					t.Errorf("signal engine: %v", err)
				}
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = child.Process.Kill()
				<-done
				t.Error("engine did not stop within 5 seconds")
			}
			assert.NoError(t, waitErr, "engine subprocess")
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path + ".ready"); err == nil {
			return stop
		}
		select {
		case <-done:
			require.NoError(t, waitErr)
			t.Fatal("engine exited before readiness")
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("engine subprocess did not become ready")
	return stop
}
func TestTUNSmokeEngine(t *testing.T) {
	smokeDirectory(t)
	path := os.Getenv("TUN_SMOKE_OPTIONS")
	require.NotEmpty(t, path, "engine helper must be launched by the smoke test")
	payload, err := os.ReadFile(path)
	require.NoError(t, err)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx = service.ContextWithDefaultRegistry(singboxContext(ctx))
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, payload)
	require.NoError(t, err)
	opts.Log.DisableColor = true
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	defer func() { cancel(); assert.NoError(t, instance.Close()) }()
	require.NoError(t, instance.Start())
	smokeMarker(t, path+".ready")
	<-ctx.Done()
}

// One UDP socket sends to different domains. The destination must participate
// in NAT lookup so DNS interception and per-domain routing remain independent.
func smokeReusedUDP(t *testing.T, direct, vpn string) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("172.19.0.1")})
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	for _, tc := range []struct{ address, want string }{{direct, "direct"}, {vpn, "vpn"}, {direct, "direct"}} {
		require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
		peer := &net.UDPAddr{IP: net.ParseIP(tc.address), Port: 8081}
		_, err := conn.WriteToUDP([]byte("same-source"), peer)
		require.NoError(t, err)
		payload := make([]byte, 128)
		n, from, err := conn.ReadFromUDP(payload)
		require.NoError(t, err)
		assert.Equal(t, tc.want, string(payload[:n]), "UDP source %s destination %s", conn.LocalAddr(), peer)
		assert.Equal(t, peer.String(), from.String())
	}
}
