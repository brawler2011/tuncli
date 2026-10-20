//go:build tun_smoke

package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/tun"
	singJSON "github.com/sagernet/sing/common/json"
	singService "github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func guardBoxContext() context.Context {
	i, o, d := inbound.NewRegistry(), outbound.NewRegistry(), dns.NewTransportRegistry()
	tun.RegisterInbound(i)
	mixed.RegisterInbound(i)
	socks.RegisterOutbound(o)
	direct.RegisterOutbound(o)
	transport.RegisterUDP(d)
	transport.RegisterHTTPS(d)
	local.RegisterTransport(d)
	return singService.ContextWithDefaultRegistry(box.Context(context.Background(), i, o, endpoint.NewRegistry(), d, boxService.NewRegistry()))
}

func guardSmokeOnly(t *testing.T) {
	t.Helper()
	require.NotEmpty(t, os.Getenv("GUARD_SMOKE_DIR"))
	host := os.Getenv("GUARD_HOST_NETNS")
	require.NotEmpty(t, host)
	current, err := os.Readlink("/proc/self/ns/net")
	require.NoError(t, err)
	require.NotEqual(t, host, current, "refusing host firewall changes")
}
func TestGuardFixture(t *testing.T) {
	guardSmokeOnly(t)
	ctx := guardBoxContext()
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"inbounds":[{"type":"mixed","listen":"192.0.2.2","listen_port":1080}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`))
	require.NoError(t, err)
	opts.Log = &option.LogOptions{Level: "error"}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	defer func() { _ = instance.Close() }()
	for _, network := range []string{"tcp4", "tcp6"} {
		listener, err := net.Listen(network, ":8080")
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()
		go func() {
			for {
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_, _ = conn.Write([]byte("ok"))
				_ = conn.Close()
			}
		}()
	}
	for _, address := range []string{"192.0.2.2", "1.1.1.1", "fd00:2026::2", "203.0.113.10", "2001:db8::10"} {
		for _, port := range []int{53, 54} {
			conn, err := net.ListenPacket("udp", net.JoinHostPort(address, fmt.Sprint(port)))
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			go func() {
				b := make([]byte, 128)
				for {
					n, addr, e := conn.ReadFrom(b)
					if e != nil {
						return
					}
					_, _ = conn.WriteTo(b[:n], addr)
				}
			}()
		}
	}
	dir := os.Getenv("GUARD_SMOKE_DIR")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fixture-ready"), nil, 0600))
	deadline := time.Now().Add(50 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "done")); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("client timeout")
}
func guardReachable(network, address string, mark int) bool {
	d := net.Dialer{Timeout: 250 * time.Millisecond, Control: func(_, _ string, c syscall.RawConn) error {
		var e error
		err := c.Control(func(fd uintptr) { e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark) })
		if err != nil {
			return err
		}
		return e
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	if network == "udp" {
		if _, err = conn.Write([]byte("dns")); err != nil {
			return false
		}
	}
	b := make([]byte, 3)
	_, err = conn.Read(b)
	return err == nil
}
func TestGuardCrashHelper(t *testing.T) {
	if os.Getenv("GUARD_CRASH_HELPER") != "1" {
		t.Skip("helper")
	}
	guardSmokeOnly(t)
	require.NoError(t, (NFT{}).Apply(false))
	_ = unix.Kill(os.Getpid(), unix.SIGKILL)
}
func TestGuardSmoke(t *testing.T) {
	guardSmokeOnly(t)
	fw := NFT{}
	require.NoError(t, exec.Command("/usr/sbin/nft", "add", "table", "inet", "unrelated_fixture").Run())
	for _, address := range []string{"192.0.2.2:8080", "[fd00:2026::2]:8080"} {
		require.True(t, guardReachable("tcp", address, 0), address)
	}
	require.NoError(t, fw.Apply(false))
	defer func() { _ = fw.Remove() }()
	for _, connected := range []bool{false, true, false} {
		require.NoError(t, fw.Apply(connected))
		for _, address := range []string{"192.0.2.2:8080", "[fd00:2026::2]:8080"} {
			require.False(t, guardReachable("tcp", address, 0), "unmarked leak: "+address)
			require.True(t, guardReachable("tcp", address, 354), "transport: "+address)
			require.Equal(t, connected, guardReachable("tcp", address, 355), "direct state: "+address)
		}
		for _, address := range []string{"192.0.2.2:53", "[fd00:2026::2]:53"} {
			require.False(t, guardReachable("udp", address, 0), "DNS leak")
			require.Equal(t, connected, guardReachable("udp", address, 355), "direct DNS")
		}
		require.True(t, guardReachable("udp", "1.1.1.1:53", 356))
		require.False(t, guardReachable("udp", "1.1.1.1:54", 356))
		require.False(t, guardReachable("udp", "192.0.2.2:53", 356))
	}
	helper := exec.Command(os.Args[0], "-test.run=^TestGuardCrashHelper$")
	helper.Env = append(os.Environ(), "GUARD_CRASH_HELPER=1")
	require.Error(t, helper.Run())
	require.False(t, guardReachable("tcp", "192.0.2.2:8080", 0), "protection must survive SIGKILL")
	require.NoError(t, fw.Remove())
	for _, address := range []string{"192.0.2.2:8080", "[fd00:2026::2]:8080"} {
		require.True(t, guardReachable("tcp", address, 0), "stop restores internet")
	}
	require.NoError(t, exec.Command("/usr/sbin/nft", "list", "table", "inet", "unrelated_fixture").Run(), "foreign tables must survive")
}
