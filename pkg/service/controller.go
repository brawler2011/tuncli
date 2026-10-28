package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/runner"
	"github.com/brawler2011/tuncli/pkg/storage"
)

type Engine interface {
	Close() error
	Probe(context.Context) error
}
type Plan interface {
	Open(context.Context) (Engine, error)
}
type realPlan struct{ p *runner.ManagedPlan }

func (p realPlan) Open(ctx context.Context) (Engine, error) { return p.p.Open(ctx) }

type Controller struct {
	view           atomic.Pointer[Status]
	mu             sync.Mutex
	activityMu     sync.Mutex
	activeCancel   context.CancelFunc
	stopping       int
	Dir            string
	Firewall       Firewall
	Prepare        func(context.Context, *config.Config) (Plan, error)
	Command        func([]string) (string, error)
	CommandContext func(context.Context, []string) (string, error)
	status         Status
	engine         Engine
	failures       int
	retry          time.Time
	backoff        time.Duration
}

func NewController(dir string, command func([]string) (string, error)) *Controller {
	c := &Controller{Dir: dir, Firewall: NFT{}, Command: command, status: Status{State: "stopped"}, backoff: time.Second, Prepare: func(ctx context.Context, c *config.Config) (Plan, error) {
		p, e := runner.PrepareManaged(ctx, c)
		return realPlan{p}, e
	}}
	c.publish()
	return c
}
func (c *Controller) publish()          { s := c.status; c.view.Store(&s) }
func (c *Controller) statePath() string { return filepath.Join(c.Dir, "desired.json") }
func (c *Controller) saveDesired(value bool) error {
	data, _ := json.Marshal(value)
	return storage.Write(c.statePath(), data)
}
func (c *Controller) Load() error {
	b, err := os.ReadFile(c.statePath())
	if err != nil {
		return err
	}
	err = json.Unmarshal(b, &c.status.Desired)
	c.publish()
	return err
}
func (c *Controller) fail(err error) {
	c.status.State = "error"
	c.status.LastError = err.Error()
	c.retry = time.Now().Add(c.backoff)
	c.backoff = min(c.backoff*2, 30*time.Second)
	c.publish()
}
func (c *Controller) guard(direct bool) error {
	if err := c.Firewall.Apply(direct); err != nil {
		return err
	}
	c.status.Protection = true
	c.publish()
	return nil
}
func (c *Controller) closeEngine() error {
	if c.engine == nil {
		return nil
	}
	err := c.engine.Close()
	c.engine = nil
	return err
}
func (c *Controller) connect(ctx context.Context, cfg *config.Config, p Plan) error {
	if cfg.Mode == "tun" {
		if err := c.guard(false); err != nil {
			return err
		}
	}
	if err := c.closeEngine(); err != nil {
		return err
	}
	engine, err := p.Open(ctx)
	if err != nil {
		return err
	}
	c.engine = engine
	if err := ctx.Err(); err != nil {
		return errors.Join(err, c.closeEngine())
	}
	probeCtx, cancel := context.WithTimeout(ctx, runner.StartupProbeTimeout)
	err = engine.Probe(probeCtx)
	cancel()
	if err != nil {
		_ = c.closeEngine()
		return err
	}
	if cfg.Mode == "tun" {
		if err = c.guard(true); err != nil {
			_ = c.closeEngine()
			return err
		}
	} else if c.status.Protection {
		if err = c.Firewall.Remove(); err != nil {
			return err
		}
		c.status.Protection = false
	}
	c.status.State = "connected"
	c.status.LastError = ""
	c.status.Node = cfg.SelectedNode
	c.status.Mode = cfg.Mode
	c.failures = 0
	c.backoff = time.Second
	return nil
}

// Called while mu is held; stop can cancel network work without waiting for mu.
func (c *Controller) begin(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	c.activityMu.Lock()
	c.activeCancel = cancel
	if c.stopping > 0 {
		cancel()
	}
	c.activityMu.Unlock()
	return ctx, func() {
		c.activityMu.Lock()
		c.activeCancel = nil
		cancel()
		c.activityMu.Unlock()
	}
}
func (c *Controller) command(ctx context.Context, args []string) (string, error) {
	if c.CommandContext != nil {
		return c.CommandContext(ctx, args)
	}
	if c.Command == nil {
		return "", fmt.Errorf("command unavailable")
	}
	return c.Command(args)
}
func (c *Controller) Handle(request Request) Response {
	return c.HandleContext(context.Background(), request)
}
func (c *Controller) HandleContext(requestCtx context.Context, request Request) Response {
	if request.Operation == "status" {
		s := c.view.Load()
		if s == nil {
			s = &Status{State: "stopped"}
		}
		copyStatus := *s
		return Response{Status: &copyStatus}
	}
	if request.Operation == "stop" {
		c.activityMu.Lock()
		c.stopping++
		if c.activeCancel != nil {
			c.activeCancel()
		}
		c.activityMu.Unlock()
		defer func() { c.activityMu.Lock(); c.stopping--; c.activityMu.Unlock() }()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.publish()
	ctx := context.Background()
	if request.Operation != "stop" {
		var finish func()
		ctx, finish = c.begin(requestCtx)
		defer finish()
	}
	result, err := c.handle(ctx, request)
	if err != nil {
		result.Error = err.Error()
	}
	return result
}
func (c *Controller) handle(ctx context.Context, r Request) (Response, error) {
	var result Response
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if r.Operation == "status" {
		status := c.status
		result.Status = &status
		return result, nil
	}
	if r.Operation == "choices" {
		cfg, err := config.LoadConfig()
		if err != nil {
			return result, err
		}
		for _, s := range cfg.Subscriptions {
			nodes, err := config.LoadSubscriptionNodes(s.ID)
			if err != nil {
				return result, err
			}
			for _, n := range nodes {
				result.Choices = append(result.Choices, Choice{s.ID, n.Name})
			}
		}
		return result, nil
	}
	if r.Operation == "stop" {
		if err := c.saveDesired(false); err != nil {
			return result, err
		}
		c.status.Desired = false
		c.publish()
		if err := c.closeEngine(); err != nil {
			c.fail(err)
			return result, err
		}
		if err := c.Firewall.Remove(); err != nil {
			c.fail(err)
			return result, err
		}
		c.status.Protection = false
		c.status.State = "stopped"
		c.status.LastError = ""
		return result, nil
	}
	if r.Operation == "restart" && !c.status.Desired {
		return result, fmt.Errorf("VPN is stopped; use tuncli start")
	}
	if r.Operation != "start" && r.Operation != "restart" && r.Operation != "select" && r.Operation != "command" {
		return result, fmt.Errorf("unknown operation %q", r.Operation)
	}
	if r.Operation == "command" && (len(r.Args) == 1 && r.Args[0] == "list" || len(r.Args) == 2 && r.Args[0] == "routing" && r.Args[1] == "show" || len(r.Args) == 3 && r.Args[0] == "routing" && r.Args[1] == "preset" && r.Args[2] == "list") {
		output, err := c.command(ctx, r.Args)
		result.Output = output
		return result, err
	}
	if c.status.Protection {
		if err := c.guard(false); err != nil {
			_ = c.closeEngine()
			c.fail(err)
			return result, err
		}
	}
	before, err := snapshot(c.Dir)
	if err != nil {
		return result, err
	}
	journal, err := json.Marshal(before)
	if err != nil {
		return result, err
	}
	if err = storage.Write(filepath.Join(c.Dir, ".transaction.json"), journal); err != nil {
		return result, err
	}
	keepJournal := false
	defer func() {
		if !keepJournal {
			_ = os.Remove(filepath.Join(c.Dir, ".transaction.json"))
		}
	}()
	old, err := config.LoadConfig()
	if err != nil {
		return result, err
	}
	oldNode, _ := runner.Selected(old)
	wasRunning := c.engine != nil
	rollback := func(e error) (Response, error) {
		restoreErr := restore(c.Dir, before)
		if ctx.Err() == nil && wasRunning && c.status.Desired && c.engine == nil && restoreErr == nil {
			if p, err := c.Prepare(ctx, old); err == nil {
				restoreErr = c.connect(ctx, old, p)
			} else {
				restoreErr = err
			}
		} else if c.engine != nil && old.Mode == "tun" && c.status.State == "connected" {
			restoreErr = errors.Join(restoreErr, c.guard(true))
		}
		if restoreErr != nil {
			keepJournal = true
			c.fail(errors.Join(e, restoreErr))
		}
		c.status.LastError = e.Error()
		return result, errors.Join(e, restoreErr)
	}
	switch r.Operation {
	case "command":
		if c.Command == nil && c.CommandContext == nil {
			return rollback(fmt.Errorf("command unavailable"))
		}
		result.Output, err = c.command(ctx, r.Args)
		if err != nil {
			return rollback(err)
		}
	case "start", "select":
		cfg := *old
		if r.Mode != "" {
			if r.Mode != "tun" && r.Mode != "proxy" {
				return rollback(fmt.Errorf("invalid mode"))
			}
			cfg.Mode = r.Mode
		}
		if r.Node != "" {
			found := false
			subs := cfg.Subscriptions
			// Prefer current subscription for duplicate node names.
			if r.Subscription == "" {
				for i, s := range subs {
					if s.ID == cfg.SelectedSubscription {
						subs = append([]config.SubscriptionItem{s}, append(append([]config.SubscriptionItem{}, subs[:i]...), subs[i+1:]...)...)
						break
					}
				}
			}
			for _, s := range subs {
				if r.Subscription != "" && r.Subscription != s.ID {
					continue
				}
				nodes, e := config.LoadSubscriptionNodes(s.ID)
				if e != nil {
					return rollback(e)
				}
				for _, n := range nodes {
					if n.Name == r.Node {
						cfg.SelectedSubscription = s.ID
						cfg.SelectedNode = n.Name
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if !found {
				return rollback(fmt.Errorf("node %q not found", r.Node))
			}
		}
		if err = config.SaveConfig(&cfg); err != nil {
			return rollback(err)
		}
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return rollback(err)
	}
	node, nodeErr := runner.Selected(cfg)
	// Commands may prepare an incomplete configuration while stopped.
	var p Plan
	if nodeErr == nil {
		p, err = c.Prepare(ctx, cfg)
		if err != nil {
			return rollback(err)
		}
	} else if c.status.Desired || r.Operation == "start" || r.Operation == "select" {
		return rollback(nodeErr)
	}
	changed := old.Mode != cfg.Mode || old.SelectedSubscription != cfg.SelectedSubscription || !reflect.DeepEqual(oldNode, node) || !reflect.DeepEqual(old.Routing, cfg.Routing)
	if r.Operation == "command" && len(r.Args) > 1 && r.Args[0] == "routing" && r.Args[1] == "update" {
		changed = true
	}
	if r.Operation == "start" {
		if err = c.saveDesired(true); err != nil {
			return rollback(err)
		}
		c.status.Desired = true
	}
	c.status.Node = cfg.SelectedNode
	c.status.Mode = cfg.Mode
	if c.status.Desired && (changed || r.Operation == "start" || r.Operation == "restart") {
		c.status.State = "reconnecting"
		if c.engine == nil {
			c.status.State = "connecting"
		}
		c.publish()
		if cfg.Mode == "tun" {
			if err = c.guard(false); err != nil {
				c.fail(err)
				return rollback(err)
			}
		}
		if err = c.connect(ctx, cfg, p); err != nil {
			c.fail(err)
			return rollback(err)
		}
	} else if c.engine != nil && cfg.Mode == "tun" {
		if err = c.guard(c.status.State == "connected"); err != nil {
			_ = c.closeEngine()
			c.fail(err)
			return result, err
		}
	}
	return result, nil
}
func (c *Controller) Tick(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.publish()
	ctx, finish := c.begin(ctx)
	defer finish()
	if ctx.Err() != nil {
		return
	}
	if !c.status.Desired {
		return
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		c.fail(err)
		return
	}
	c.status.Node = cfg.SelectedNode
	c.status.Mode = cfg.Mode
	if c.engine != nil {
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = c.engine.Probe(probeCtx)
		cancel()
		if err == nil {
			c.failures = 0
			return
		}
		c.failures++
		if c.failures < 2 {
			return
		}
		if cfg.Mode == "tun" {
			if e := c.guard(false); e != nil {
				err = errors.Join(err, e)
			}
		}
		err = errors.Join(err, c.closeEngine())
		c.fail(err)
		return
	}
	if time.Now().Before(c.retry) {
		return
	}
	c.status.State = "connecting"
	c.publish()
	if cfg.Mode == "tun" {
		if err = c.guard(false); err != nil {
			c.fail(err)
			return
		}
	}
	p, err := c.Prepare(ctx, cfg)
	if err == nil {
		err = c.connect(ctx, cfg, p)
	}
	if err != nil {
		c.fail(err)
	}
}

// Run retries at one-second resolution; health checks use a fixed ten-second cadence.
func (c *Controller) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	nextProbe := time.Now()
	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			_ = c.closeEngine()
			c.mu.Unlock()
			return
		case now := <-ticker.C:
			c.mu.Lock()
			probe := c.engine == nil || !now.Before(nextProbe)
			c.mu.Unlock()
			if probe {
				c.Tick(ctx)
				nextProbe = now.Add(10 * time.Second)
			}
		}
	}
}

// Snapshot only settings and immutable routing copies. Never copy or replace an
// open FakeIP database. A failed update restores the previous subscription too.
func snapshot(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		if rel == "desired.json" || rel == ".transaction.json" || strings.HasSuffix(rel, ".db") {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("unexpected state file %s", path)
		}
		b, e := os.ReadFile(path)
		if e == nil {
			files[rel] = b
		}
		return e
	})
	return files, err
}
func restore(dir string, files map[string][]byte) error {
	current, err := snapshot(dir)
	if err != nil {
		return err
	}
	for path := range current {
		if _, ok := files[path]; !ok {
			if err = os.Remove(filepath.Join(dir, path)); err != nil {
				return err
			}
		}
	}
	for path, b := range files {
		if err = storage.Mkdir(filepath.Dir(filepath.Join(dir, path))); err != nil {
			return err
		}
		if err = storage.Write(filepath.Join(dir, path), b); err != nil {
			return err
		}
	}
	return nil
}

func recoverTransaction(dir string) error {
	path := filepath.Join(dir, ".transaction.json")
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var files map[string][]byte
	if err = json.Unmarshal(b, &files); err != nil {
		return err
	}
	for p := range files {
		if filepath.IsAbs(p) || filepath.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../") {
			return fmt.Errorf("invalid transaction path")
		}
	}
	if err = restore(dir, files); err != nil {
		return err
	}
	return os.Remove(path)
}
