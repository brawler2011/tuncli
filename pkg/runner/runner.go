package runner

import (
	"context"
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

func Start(cfg *config.Config) error {
	if cfg.SelectedSubscription == "" || cfg.SelectedNode == "" {
		return fmt.Errorf("no valid node selected. Run 'tuncli select' first.")
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
		return fmt.Errorf("selected node %q not found in subscription %q. Please run 'tuncli select' again.", cfg.SelectedNode, cfg.SelectedSubscription)
	}

	fmt.Printf("Starting VPN with node: %s [%s]\n", node.Name, cfg.Mode)

	ctx := context.Background()
	logger := log.NewDefaultFactory(ctx, log.Formatter{
		BaseTime: time.Now(),
	}, os.Stderr, "", nil, false).Logger()
	ctx = service.ContextWith(ctx, logger)
	ctx = singboxContext(ctx)

	options, err := BuildSingboxConfig(ctx, &node, cfg.Mode)
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

	err = instance.Start()
	if err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}
	fmt.Println("VPN is running. Press Ctrl+C to stop.")

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	<-osSignals

	fmt.Println("\nStopping VPN...")
	err = instance.Close()
	if err != nil {
		return fmt.Errorf("error during shutdown: %w", err)
	}

	return nil
}
