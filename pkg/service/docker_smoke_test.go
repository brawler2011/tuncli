//go:build linux && tun_smoke

package service

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/brawler2011/tuncli/pkg/runner"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

func guardCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	b, err := exec.Command(name, args...).CombinedOutput()
	require.NoError(t, err, "%s %v: %s", name, args, b)
}

// A bridge and a separate network namespace model Docker without a daemon.
// Arbitrary bridge names and creation after Apply exercise dynamic matching.
// host is the container's last address octet; containers of one id share a bridge.
func guardContainer(t *testing.T, id, host string) int {
	t.Helper()
	bridge, port, peer := "dev-"+id, "port-"+id+"-"+host, "peer-"+id+"-"+host
	if _, err := net.InterfaceByName(bridge); err != nil {
		guardCommand(t, "ip", "link", "add", bridge, "type", "bridge")
		guardCommand(t, "ip", "address", "add", "172."+id+".0.1/24", "dev", bridge)
		guardCommand(t, "ip", "-6", "address", "add", "fd"+id+"::1/64", "dev", bridge, "nodad")
		guardCommand(t, "ip", "link", "set", bridge, "up")
	}
	guardCommand(t, "ip", "link", "add", port, "type", "veth", "peer", "name", peer)
	guardCommand(t, "ip", "link", "set", port, "master", bridge)
	guardCommand(t, "ip", "link", "set", port, "up")
	child := exec.Command("unshare", "--net", os.Args[0], "-test.run=^TestGuardContainerHelper$", "-test.timeout=35s")
	child.Env = append(os.Environ(), "GUARD_CONTAINER_ID="+id, "GUARD_CONTAINER_HOST="+host)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	current, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", child.Process.Pid))
		return err == nil && ns != current
	}, 3*time.Second, 10*time.Millisecond)
	guardCommand(t, "ip", "link", "set", peer, "netns", fmt.Sprint(child.Process.Pid))
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(os.Getenv("GUARD_SMOKE_DIR"), "container-"+id+"-"+host))
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	return child.Process.Pid
}

func TestGuardContainerHelper(t *testing.T) {
	guardSmokeOnly(t)
	id, host := os.Getenv("GUARD_CONTAINER_ID"), os.Getenv("GUARD_CONTAINER_HOST")
	require.Contains(t, []string{"21", "22"}, id)
	require.Contains(t, []string{"2", "3"}, host)
	peer := "peer-" + id + "-" + host
	require.Eventually(t, func() bool {
		_, err := net.InterfaceByName(peer)
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	guardCommand(t, "ip", "link", "set", "lo", "up")
	guardCommand(t, "ip", "address", "add", "172."+id+".0."+host+"/24", "dev", peer)
	guardCommand(t, "ip", "-6", "address", "add", "fd"+id+"::"+host+"/64", "dev", peer, "nodad")
	guardCommand(t, "ip", "link", "set", peer, "up")
	guardCommand(t, "ip", "route", "add", "default", "via", "172."+id+".0.1")
	guardCommand(t, "ip", "-6", "route", "add", "default", "via", "fd"+id+"::1")
	for _, address := range [][2]string{{"tcp4", ":8080"}, {"tcp6", ":8080"}, {"tcp4", ":53"}, {"tcp6", ":53"}} {
		ln, err := net.Listen(address[0], address[1])
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		echo := address[1] == ":53"
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if echo {
					b := make([]byte, 128)
					n, _ := conn.Read(b)
					_, _ = conn.Write(b[:n])
				} else {
					_, _ = conn.Write([]byte("ok"))
				}
				_ = conn.Close()
			}
		}()
	}
	for _, address := range [][2]string{{"udp4", ":54"}, {"udp6", ":54"}, {"udp4", ":53"}, {"udp6", ":53"}} {
		conn, err := net.ListenPacket(address[0], address[1])
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		go func() {
			b := make([]byte, 128)
			for {
				n, peer, err := conn.ReadFrom(b)
				if err != nil {
					return
				}
				_, _ = conn.WriteTo(b[:n], peer)
			}
		}()
	}
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("GUARD_SMOKE_DIR"), "container-"+id+"-"+host), nil, 0600))
	select {} // The parent owns this fixture's lifetime.
}

func TestGuardProbeHelper(t *testing.T) {
	guardSmokeOnly(t)
	network, address := os.Getenv("GUARD_PROBE_NETWORK"), os.Getenv("GUARD_PROBE_ADDRESS")
	var got bool
	if dns, ok := strings.CutPrefix(network, "dns-"); ok {
		got = guardDNSEcho(dns, address)
	} else {
		got = guardReachable(network, address, 0)
	}
	require.Equal(t, os.Getenv("GUARD_PROBE_WANT") == "true", got)
}

// The engine recognizes only a well-formed query; the container's echo returns it unchanged.
func guardDNSEcho(network, address string) bool {
	msg := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if network == "tcp" {
		msg = append([]byte{0, byte(len(msg))}, msg...)
	}
	conn, err := net.DialTimeout(network, address, 250*time.Millisecond)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write(msg); err != nil {
		return false
	}
	b := make([]byte, 512)
	n, err := conn.Read(b)
	return err == nil && bytes.Equal(b[:n], msg)
}

func guardContainerProbe(t *testing.T, pid int, network, address string, want bool) {
	t.Helper()
	child := exec.Command("nsenter", fmt.Sprintf("--net=/proc/%d/ns/net", pid), "--", os.Args[0], "-test.run=^TestGuardProbeHelper$", "-test.timeout=3s")
	child.Env = append(os.Environ(), "GUARD_PROBE_NETWORK="+network, "GUARD_PROBE_ADDRESS="+address, fmt.Sprintf("GUARD_PROBE_WANT=%t", want))
	b, err := child.CombinedOutput()
	require.NoError(t, err, "container %s %s want=%t: %s", network, address, want, b)
}

func TestGuardDockerSmoke(t *testing.T) {
	guardSmokeOnly(t)
	fw := NFT{}
	require.NoError(t, fw.Apply(false))
	t.Cleanup(func() { _ = fw.Remove() })
	guardCommand(t, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.ipv4.conf.all.route_localnet=1")
	// Like Kubernetes, the cluster DNS fixture needs br_netfilter: a reply bridged
	// from the DNS pod is un-DNATed to the service address only by netfilter.
	guardCommand(t, "sysctl", "-qw", "net.bridge.bridge-nf-call-iptables=1")
	data := guardContainer(t, "21", "2")
	apps := guardContainer(t, "22", "2")
	dataPeer := guardContainer(t, "21", "3")
	// Docker uses a userspace proxy for IPv6 localhost publishing.
	ln, err := net.Listen("tcp6", "[::1]:15432")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				upstream, err := net.DialTimeout("tcp6", "[fd21::2]:8080", time.Second)
				if err != nil {
					return
				}
				defer func() { _ = upstream.Close() }()
				go func() { _, _ = io.Copy(upstream, conn) }()
				_, _ = io.Copy(conn, upstream)
			}()
		}
	}()
	// Docker-like localhost publishing with DNAT and hairpin masquerading.
	nat := `add table inet docker_fixture
add chain inet docker_fixture output { type nat hook output priority dstnat; }
add rule inet docker_fixture output ip daddr 127.0.0.1 tcp dport 15432 dnat ip to 172.21.0.2:8080
add chain inet docker_fixture postrouting { type nat hook postrouting priority srcnat; }
add rule inet docker_fixture postrouting ip saddr 127.0.0.1 ip daddr 172.21.0.2 masquerade
add chain inet docker_fixture forward { type filter hook forward priority filter; }
add chain inet docker_fixture prerouting { type nat hook prerouting priority dstnat; }
add rule inet docker_fixture prerouting ip daddr 10.96.0.10 meta l4proto { tcp, udp } th dport 53 dnat ip to 172.21.0.2
`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nat)
	b, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", b)
	local := func() {
		for _, address := range []string{"172.21.0.2:8080", "[fd21::2]:8080", "127.0.0.1:15432", "[::1]:15432"} {
			require.True(t, guardReachable("tcp", address, 0), "host to container: %s", address)
		}
		for _, address := range []string{"172.21.0.2:8080", "[fd21::2]:8080"} {
			guardContainerProbe(t, apps, "tcp", address, true)
		}
		for _, address := range []string{"172.21.0.2:54", "[fd21::2]:54"} {
			guardContainerProbe(t, apps, "udp", address, true)
		}
	}
	local()
	for _, address := range []string{"203.0.113.10:8080", "[2001:db8::10]:8080"} {
		guardContainerProbe(t, data, "tcp", address, false)
	}
	ctx := guardBoxContext()
	node := &config.Node{Protocol: "socks", Server: "192.0.2.2", RawConfig: map[string]any{"type": "socks", "server": "192.0.2.2", "server_port": 1080, "version": "5"}}
	opts, err := runner.BuildSingboxConfigWithPolicy(ctx, node, "tun", &routing.Prepared{Managed: true})
	require.NoError(t, err)
	opts.Log = &option.LogOptions{Level: "error"}
	engine, err := box.New(box.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	t.Cleanup(func() { _ = engine.Close() })
	require.NoError(t, engine.Start())
	require.NoError(t, fw.Apply(true))
	local()
	for _, address := range []string{"203.0.113.10:8080", "[2001:db8::10]:8080"} {
		guardContainerProbe(t, data, "tcp", address, true)
	}
	for _, address := range []string{"203.0.113.10:54", "[2001:db8::10]:54"} {
		guardContainerProbe(t, data, "udp", address, true)
	}
	// Pods query cluster DNS through a DNAT'ed service VIP, so the query is routed
	// instead of bridged. It stays local on the same bridge and goes to TUN otherwise.
	for _, network := range []string{"dns-tcp", "dns-udp"} {
		guardContainerProbe(t, dataPeer, network, "10.96.0.10:53", true)
		guardContainerProbe(t, apps, network, "10.96.0.10:53", false)
	}
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:2080", nil, &net.Dialer{Timeout: time.Second})
	require.NoError(t, err)
	conn, err := dialer.Dial("tcp", "203.0.113.10:8080")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	payload := make([]byte, 2)
	_, err = io.ReadFull(conn, payload)
	require.NoError(t, err)
	require.Equal(t, "ok", string(payload))
	// Our early accept must not override Docker's later isolation rules.
	guardCommand(t, "nft", "add", "rule", "inet", "docker_fixture", "forward", "ip", "daddr", "172.21.0.2", "tcp", "dport", "8080", "reject")
	guardContainerProbe(t, apps, "tcp", "172.21.0.2:8080", false)
	guardCommand(t, "nft", "flush", "chain", "inet", "docker_fixture", "forward")
	require.NoError(t, fw.Apply(false))
	require.NoError(t, engine.Close())
	local()
	for _, address := range []string{"203.0.113.10:8080", "[2001:db8::10]:8080"} {
		guardContainerProbe(t, data, "tcp", address, false)
	}
}
