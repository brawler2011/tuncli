package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"
)

func Start(cfg *config.Config) (runErr error) {
	if cfg == nil {
		return fmt.Errorf("config is nil")
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

	release, err := acquireProcessFile(processDir())
	if err != nil {
		return fmt.Errorf("cannot acquire runtime state: %w", err)
	}
	defer release()
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

	options, err := BuildSingboxConfig(ctx, &node, cfg.Mode, xrayPort)
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

	defer func() { runErr = errors.Join(runErr, instance.Close()) }()
	err = instance.Start()
	if err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}
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
