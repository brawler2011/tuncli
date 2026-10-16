package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/routing"
	"github.com/brawler2011/tuncli/pkg/storage"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

func Start(cfg *config.Config) (runErr error) {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if err := cfg.Routing.Validate(); err != nil {
		return fmt.Errorf("routing: %w", err)
	}
	if cfg.Mode != "tun" && cfg.Mode != "proxy" {
		return fmt.Errorf("invalid mode %q", cfg.Mode)
	}
	if cfg.SelectedSubscription == "" || cfg.SelectedNode == "" {
		return fmt.Errorf("no valid node selected. Run 'tuncli select' first")
	}

	nodes, err := config.LoadSubscriptionNodes(cfg.SelectedSubscription)
	if err != nil {
		return fmt.Errorf("failed to load nodes for selected subscription: %w", err)
	}

	var node config.Node
	found := false
	for _, n := range nodes {
		if n.Name == cfg.SelectedNode {
			node = n
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("selected node %q not found in subscription %q. Please run 'tuncli select' again", cfg.SelectedNode, cfg.SelectedSubscription)
	}

	dir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	prepared, warnings, err := routing.NewCache(filepath.Join(dir, "routing")).Prepare(context.Background(), cfg.Routing, false)
	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, "Warning:", warning)
	}
	if err != nil {
		return err
	}
	if prepared == nil {
		prepared = &routing.Prepared{}
	}
	// Bootstrap outside the pure builder, before any TUN routes are installed.
	if net.ParseIP(node.Server) == nil && node.Server != "" {
		if ips, e := net.LookupIP(node.Server); e == nil {
			for _, ip := range ips {
				prepared.ServerIPs = append(prepared.ServerIPs, ip.String())
			}
		}
	}

	release, err := acquireProcessFile(processDir())
	if err != nil {
		return fmt.Errorf("cannot acquire runtime state: %w", err)
	}
	defer release()
	if cfg.Mode == "tun" && prepared.FakeIPPath != "" {
		f, err := os.OpenFile(prepared.FakeIPPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return fmt.Errorf("FakeIP cache: %w", err)
		}
		closeErr := f.Close()
		if err = storage.Own(prepared.FakeIPPath); err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(osSignals)

	fmt.Printf("Starting VPN with node: %s [%s]\n", node.Name, cfg.Mode)

	var sidecar *XraySidecar
	var xrayPort int
	if IsXHTTP(&node) {
		fmt.Println("Node uses XHTTP transport. Launching Xray sidecar...")
		var err error
		sidecar, err = StartXraySidecar(&node, DefaultXrayPort, cfg.Mode)
		if err != nil {
			return fmt.Errorf("failed to start Xray sidecar: %w", err)
		}
		defer func() {
			fmt.Println("Stopping Xray sidecar...")
			runErr = errors.Join(runErr, sidecar.Stop())
		}()
		xrayPort = sidecar.Port
		fmt.Printf("Xray sidecar running on 127.0.0.1:%d\n", xrayPort)
	}

	ctx := context.Background()
	logger := log.NewDefaultFactory(ctx, log.Formatter{
		BaseTime: time.Now(),
	}, os.Stderr, "", nil, false).Logger()
	ctx = service.ContextWith(ctx, logger)
	ctx = singboxContext(ctx)

	options, err := BuildSingboxConfigWithPolicy(ctx, &node, cfg.Mode, prepared, xrayPort)
	if err != nil {
		return fmt.Errorf("failed to build sing-box config: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize sing-box: %w", err)
	}

	defer func() {
		runErr = errors.Join(runErr, instance.Close())
		if prepared.FakeIPPath != "" {
			if _, err := os.Stat(prepared.FakeIPPath); err == nil {
				runErr = errors.Join(runErr, storage.Own(prepared.FakeIPPath))
			}
		}
	}()
	err = instance.Start()
	if err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}
	fmt.Println("Local proxy: 127.0.0.1:2080 (HTTP/SOCKS5)")
	fmt.Println("VPN is running. Press Ctrl+C to stop.")

	var xrayDone <-chan struct{}
	if sidecar != nil {
		xrayDone = sidecar.done
	}
	select {
	case <-osSignals:
		fmt.Println("\nStopping VPN...")
		return nil
	case <-xrayDone:
		return fmt.Errorf("xray sidecar exited unexpectedly: %w", sidecar.waitErr)
	}
}
