//go:build linux && tun_smoke

package service

import (
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
func guardContainer(t *testing.T, id string) int {
	t.Helper()
	bridge, peer := "dev-"+id, "peer-"+id
	guardCommand(t, "ip", "link", "add", bridge, "type", "bridge")
	guardCommand(t, "ip", "address", "add", "172."+id+".0.1/24", "dev", bridge)
	guardCommand(t, "ip", "-6", "address", "add", "fd"+id+"::1/64", "dev", bridge, "nodad")
	guardCommand(t, "ip", "link", "set", bridge, "up")
	guardCommand(t, "ip", "link", "add", "port-"+id, "type", "veth", "peer", "name", peer)
	guardCommand(t, "ip", "link", "set", "port-"+id, "master", bridge)
	guardCommand(t, "ip", "link", "set", "port-"+id, "up")
	child := exec.Command("unshare", "--net", os.Args[0], "-test.run=^TestGuardContainerHelper$", "-test.timeout=35s")
	child.Env = append(os.Environ(), "GUARD_CONTAINER_ID="+id)
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
		_, err := os.Stat(filepath.Join(os.Getenv("GUARD_SMOKE_DIR"), "container-"+id))
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	return child.Process.Pid
}

func TestGuardContainerHelper(t *testing.T) {
	guardSmokeOnly(t)
	id := os.Getenv("GUARD_CONTAINER_ID")
	require.Contains(t, []string{"21", "22"}, id)
	peer := "peer-" + id
	require.Eventually(t, func() bool {
		_, err := net.InterfaceByName(peer)
		return err == nil
	}, 3*time.Second, 10*time.Millisecond)
	guardCommand(t, "ip", "link", "set", "lo", "up")
	guardCommand(t, "ip", "address", "add", "172."+id+".0.2/24", "dev", peer)
	guardCommand(t, "ip", "-6", "address", "add", "fd"+id+"::2/64", "dev", peer, "nodad")
	guardCommand(t, "ip", "link", "set", peer, "up")
	guardCommand(t, "ip", "route", "add", "default", "via", "172."+id+".0.1")
	guardCommand(t, "ip", "-6", "route", "add", "default", "via", "fd"+id+"::1")
	for _, network := range []string{"tcp4", "tcp6"} {
		ln, err := net.Listen(network, ":8080")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte("ok"))
				_ = conn.Close()
			}
		}()
	}
	for _, network := range []string{"udp4", "udp6"} {
		conn, err := net.ListenPacket(network, ":54")
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
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("GUARD_SMOKE_DIR"), "container-"+id), nil, 0600))
	select {} // The parent owns this fixture's lifetime.
}

func TestGuardProbeHelper(t *testing.T) {
	guardSmokeOnly(t)
	require.Equal(t, os.Getenv("GUARD_PROBE_WANT") == "true", guardReachable(os.Getenv("GUARD_PROBE_NETWORK"), os.Getenv("GUARD_PROBE_ADDRESS"), 0))
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
	data := guardContainer(t, "21")
	apps := guardContainer(t, "22")
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
