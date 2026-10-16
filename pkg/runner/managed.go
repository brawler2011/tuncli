package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

const TransportMark = DefaultXrayMark
const DirectMark = 355
const BootstrapMark = 356

// ManagedPlan contains validated engine options, never supplied by an API client.
type ManagedPlan struct {
	Node    config.Node
	Mode    string
	options option.Options
}
type ManagedEngine struct {
	instance *box.Box
	sidecar  *XraySidecar
	cancel   context.CancelFunc
}

func Selected(cfg *config.Config) (config.Node, error) {
	nodes, err := config.LoadSubscriptionNodes(cfg.SelectedSubscription)
	if err != nil {
		return config.Node{}, err
	}
	for _, n := range nodes {
		if n.Name == cfg.SelectedNode {
			return n, nil
		}
	}
	return config.Node{}, fmt.Errorf("selected node %q is missing; use tuncli select", cfg.SelectedNode)
}

// Prevent native subscription fields from giving a root engine access to client
// chosen files, interfaces, marks, detours or listeners. Transport URL paths remain valid.
func validateManagedFields(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			if strings.HasSuffix(k, "_path") || strings.HasSuffix(k, "_paths") || strings.HasSuffix(k, "_file") || k == "detour" || k == "routing_mark" || k == "bind_interface" || k == "bind_address" || k == "protect_path" || k == "netns" || k == "domain_resolver" || k == "certificate" || k == "key" || k == "listen" || k == "listen_port" {
				return fmt.Errorf("field %q is unavailable in managed subscriptions", k)
			}
			if err := validateManagedFields(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := validateManagedFields(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func PrepareManaged(ctx context.Context, cfg *config.Config) (*ManagedPlan, error) {
	if cfg.Mode != "tun" && cfg.Mode != "proxy" {
		return nil, fmt.Errorf("invalid mode %q", cfg.Mode)
	}
	if err := cfg.Routing.Validate(); err != nil {
		return nil, err
	}
	node, err := Selected(cfg)
	if err != nil {
		return nil, err
	}
	_ = getEffectiveRawConfig(&node)
	if err = validateManagedFields(node.RawConfig); err != nil {
		return nil, err
	}
	dir, err := config.GetConfigDir()
	if err != nil {
		return nil, err
	}
	prepared, warnings, err := routing.NewCache(filepath.Join(dir, "routing")).Prepare(ctx, cfg.Routing, false)
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w)
	}
	if err != nil {
		return nil, err
	}
	if prepared == nil {
		prepared = &routing.Prepared{}
	}
	prepared.Managed = true
	if net.ParseIP(node.Server) == nil {
		resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
				var e error
				err := c.Control(func(fd uintptr) {
					e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, BootstrapMark)
					if iface := GetDefaultInterface(); e == nil && iface != "" {
						e = unix.BindToDevice(int(fd), iface)
					}
				})
				return errors.Join(err, e)
			}}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		}}
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, e := resolver.LookupIP(lookupCtx, "ip", node.Server)
		cancel()
		if e != nil {
			return nil, fmt.Errorf("bootstrap DNS: %w", e)
		}
		for _, ip := range ips {
			prepared.ServerIPs = append(prepared.ServerIPs, ip.String())
		}
	}
	ctx = singboxContext(ctx)
	opts, err := BuildSingboxConfigWithPolicy(ctx, &node, cfg.Mode, prepared, DefaultXrayPort)
	if err != nil {
		return nil, err
	}
	// Constructing the engine validates protocol and TLS options without creating TUN.
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return nil, err
	}
	if err = instance.Close(); err != nil {
		return nil, err
	}
	if IsXHTTP(&node) {
		if len(prepared.ServerIPs) > 0 {
			original := node.Server
			node.RawConfig = maps.Clone(node.RawConfig)
			if node.RawConfig["sni"] == nil && node.RawConfig["servername"] == nil {
				node.RawConfig["sni"] = original
			}
			node.Server = prepared.ServerIPs[0]
		}
		if _, err = GenerateXrayConfig(&node, DefaultXrayPort, TransportMark); err != nil {
			return nil, err
		}
		if err = SecureExecutable("/usr/bin/xray"); err != nil {
			return nil, err
		}
	}
	return &ManagedPlan{Node: node, Mode: cfg.Mode, options: opts}, nil
}

func (p *ManagedPlan) Open(ctx context.Context) (engine *ManagedEngine, err error) {
	ctx, cancel := context.WithCancel(singboxContext(ctx))
	e := &ManagedEngine{cancel: cancel}
	defer func() {
		if err != nil {
			_ = e.Close()
		}
	}()
	if IsXHTTP(&p.Node) {
		e.sidecar, err = startXraySidecar(&p.Node, DefaultXrayPort, "/usr/bin/xray", true)
		if err != nil {
			return nil, err
		}
		if e.sidecar.Port != DefaultXrayPort {
			return nil, fmt.Errorf("managed Xray port %d is occupied", DefaultXrayPort)
		}
	}
	e.instance, err = box.New(box.Options{Context: ctx, Options: p.options})
	if err != nil {
		return nil, err
	}
	if err = e.instance.Start(); err != nil {
		return nil, err
	}
	return e, nil
}
func (e *ManagedEngine) Close() error {
	if e == nil {
		return nil
	}
	e.cancel()
	var err error
	if e.instance != nil {
		err = e.instance.Close()
	}
	if e.sidecar != nil {
		err = errors.Join(err, e.sidecar.Stop())
	}
	return err
}
func (e *ManagedEngine) Probe(ctx context.Context) error {
	if e.sidecar != nil {
		select {
		case <-e.sidecar.done:
			return fmt.Errorf("xray exited")
		default:
		}
	}
	outbound, ok := e.instance.Outbound().Outbound("proxy")
	if !ok {
		return fmt.Errorf("VPN outbound missing")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return outbound.DialContext(ctx, network, M.ParseSocksaddr(address))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("VPN probe HTTP %d", response.StatusCode)
	}
	return nil
}

// SecureExecutable checks every ancestor, including symlink targets.
func SecureExecutable(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return fmt.Errorf("not executable: %s", path)
	}
	for p := resolved; ; p = filepath.Dir(p) {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		raw, ok := st.Sys().(*syscall.Stat_t)
		if !ok || raw.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("service executable has an unprotected path: %s", p)
		}
		if p == "/" {
			break
		}
	}
	return nil
}
