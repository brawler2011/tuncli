package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/storage"
	"github.com/stretchr/testify/require"
)

type fakeFirewall struct {
	events []string
	direct bool
	active bool
	err    error
}

func (f *fakeFirewall) Apply(d bool) error {
	if f.err != nil {
		return f.err
	}
	f.direct = d
	f.active = true
	if d {
		f.events = append(f.events, "open")
	} else {
		f.events = append(f.events, "closed")
	}
	return nil
}
func (f *fakeFirewall) Remove() error {
	f.events = append(f.events, "removed")
	f.active = false
	return f.err
}

type fakeEngine struct {
	closed   bool
	probeErr error
	fw       *fakeFirewall
}

func (e *fakeEngine) Close() error {
	e.closed = true
	e.fw.events = append(e.fw.events, "engine stopped")
	return nil
}
func (e *fakeEngine) Probe(context.Context) error { return e.probeErr }

type fakePlan struct {
	engine *fakeEngine
	err    error
}

func (p fakePlan) Open(context.Context) (Engine, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.engine, nil
}
func controllerFixture(t *testing.T) (*Controller, *fakeFirewall) {
	t.Helper()
	dir := t.TempDir()
	previous := config.Directory
	private := storage.Private
	config.Directory = dir
	storage.Private = true
	t.Cleanup(func() { config.Directory = previous; storage.Private = private })
	require.NoError(t, config.SaveConfig(&config.Config{Mode: "tun", SelectedSubscription: "srv1", SelectedNode: "old", Subscriptions: []config.SubscriptionItem{{ID: "srv1"}}}))
	require.NoError(t, config.SaveSubscriptionNodes("srv1", []config.Node{{Name: "old", Server: "192.0.2.1"}, {Name: "new", Server: "192.0.2.2"}}))
	fw := &fakeFirewall{}
	c := NewController(dir, nil)
	c.Firewall = fw
	c.Prepare = func(context.Context, *config.Config) (Plan, error) { return fakePlan{engine: &fakeEngine{fw: fw}}, nil }
	require.NoError(t, c.saveDesired(false))
	return c, fw
}
func TestStateAndExplicitStop(t *testing.T) {
	c, fw := controllerFixture(t)
	require.Empty(t, c.Handle(Request{Operation: "start"}).Error)
	require.True(t, fw.direct)
	require.Equal(t, "connected", c.Handle(Request{Operation: "status"}).Status.State)
	engine := c.engine.(*fakeEngine)
	require.Empty(t, c.Handle(Request{Operation: "stop"}).Error)
	require.True(t, engine.closed)
	require.False(t, fw.active)
	require.Equal(t, []string{"engine stopped", "removed"}, fw.events[len(fw.events)-2:])
	restored := NewController(c.Dir, nil)
	require.NoError(t, restored.Load())
	require.False(t, restored.status.Desired)
	require.Contains(t, c.Handle(Request{Operation: "restart"}).Error, "stopped")
	require.Empty(t, c.Handle(Request{Operation: "select", Node: "new", Mode: "proxy"}).Error)
	require.Nil(t, c.engine)
	require.False(t, c.status.Desired)
}
func TestValidateBeforeStoppingAndRollback(t *testing.T) {
	for _, failure := range []string{"validation", "launch"} {
		t.Run(failure, func(t *testing.T) {
			c, fw := controllerFixture(t)
			require.Empty(t, c.Handle(Request{Operation: "start"}).Error)
			engine := c.engine.(*fakeEngine)
			c.Prepare = func(_ context.Context, cfg *config.Config) (Plan, error) {
				if cfg.SelectedNode == "new" {
					if failure == "validation" {
						return nil, errors.New("invalid")
					}
					return fakePlan{err: errors.New("launch failed")}, nil
				}
				return fakePlan{engine: &fakeEngine{fw: fw}}, nil
			}
			response := c.Handle(Request{Operation: "select", Node: "new"})
			require.NotEmpty(t, response.Error)
			cfg, err := config.LoadConfig()
			require.NoError(t, err)
			require.Equal(t, "old", cfg.SelectedNode)
			require.True(t, fw.direct)
			if failure == "validation" {
				require.False(t, engine.closed)
			} else {
				require.True(t, engine.closed)
				require.Equal(t, "connected", c.status.State)
			}
		})
	}
}
func TestHealthFailureClosesDirectAndRetries(t *testing.T) {
	c, fw := controllerFixture(t)
	require.Empty(t, c.Handle(Request{Operation: "start"}).Error)
	engine := c.engine.(*fakeEngine)
	engine.probeErr = errors.New("unreachable")
	c.Tick(context.Background())
	require.True(t, fw.direct)
	c.Tick(context.Background())
	require.False(t, fw.direct)
	require.True(t, fw.active)
	require.True(t, engine.closed)
	require.Equal(t, "error", c.status.State)
	c.retry = time.Time{}
	c.Tick(context.Background())
	require.Equal(t, "connected", c.status.State)
	require.True(t, fw.direct)
}
func TestCommandsSerializedAndUpdateUnselectedNode(t *testing.T) {
	c, _ := controllerFixture(t)
	var active atomic.Int32
	var maximum atomic.Int32
	c.Command = func(_ []string) (string, error) {
		n := active.Add(1)
		if n > maximum.Load() {
			maximum.Store(n)
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return "saved", nil
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { c.Handle(Request{Operation: "command", Args: []string{"update"}}) })
	}
	wg.Wait()
	require.EqualValues(t, 1, maximum.Load())
	require.Empty(t, c.Handle(Request{Operation: "start"}).Error)
	engine := c.engine
	c.Command = func(_ []string) (string, error) {
		nodes, err := config.LoadSubscriptionNodes("srv1")
		if err != nil {
			return "", err
		}
		nodes[1].Server = "192.0.2.3"
		return "", config.SaveSubscriptionNodes("srv1", nodes)
	}
	require.Empty(t, c.Handle(Request{Operation: "command", Args: []string{"update"}}).Error)
	require.Same(t, engine, c.engine)
}
func TestTransactionRecoveryAndPrivateFiles(t *testing.T) {
	c, _ := controllerFixture(t)
	before, err := snapshot(c.Dir)
	require.NoError(t, err)
	b, err := json.Marshal(before)
	require.NoError(t, err)
	require.NoError(t, storage.Write(filepath.Join(c.Dir, ".transaction.json"), b))
	require.NoError(t, config.SaveConfig(&config.Config{Mode: "proxy"}))
	require.NoError(t, recoverTransaction(c.Dir))
	cfg, err := config.LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "old", cfg.SelectedNode)
	st, err := os.Stat(filepath.Join(c.Dir, "config.json"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), st.Mode().Perm())
}
func TestAPIAuthenticationAndFailures(t *testing.T) {
	require.True(t, Authorized(0, 1000))
	require.True(t, Authorized(1000, 1000))
	require.False(t, Authorized(1001, 1000))
	_, err := CallSocket(context.Background(), filepath.Join(t.TempDir(), "absent"), Request{Operation: "start"})
	require.ErrorContains(t, err, "unavailable")
	for _, authorized := range []bool{true, false} {
		t.Run(map[bool]string{true: "owner", false: "other user"}[authorized], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			require.NoError(t, err)
			defer func() { _ = listener.Close() }()
			owner := uint32(os.Getuid())
			if !authorized {
				if owner == 0 {
					t.Skip("root is always authorized")
				}
				owner++
			}
			go func() {
				conn, e := listener.AcceptUnix()
				if e == nil {
					ServeConnection(conn, owner, func(Request) Response { return Response{Output: "accepted"} })
				}
			}()
			response, err := CallSocket(context.Background(), path, Request{Operation: "status"})
			if authorized {
				require.NoError(t, err)
				require.Equal(t, "accepted", response.Output)
			} else {
				require.ErrorContains(t, err, "permission denied")
			}
		})
	}
}
func TestImportPreservesOriginalAndRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, ".config", "tuncli")
	require.NoError(t, os.MkdirAll(source, 0700))
	original := []byte(`{"mode":"proxy"}`)
	require.NoError(t, os.WriteFile(filepath.Join(source, "config.json"), original, 0600))
	target := t.TempDir()
	require.NoError(t, ImportFiles(home, target))
	after, err := os.ReadFile(filepath.Join(source, "config.json"))
	require.NoError(t, err)
	require.Equal(t, original, after)
	require.NoError(t, os.Remove(filepath.Join(source, "config.json")))
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(source, "config.json")))
	require.Error(t, ImportFiles(home, t.TempDir()))
}

func TestMissingSelectedNodeRestoresSubscription(t *testing.T) {
	c, _ := controllerFixture(t)
	require.Empty(t, c.Handle(Request{Operation: "start"}).Error)
	c.Command = func([]string) (string, error) {
		return "", config.SaveSubscriptionNodes("srv1", []config.Node{{Name: "new"}})
	}
	response := c.Handle(Request{Operation: "command", Args: []string{"update"}})
	require.Contains(t, response.Error, "missing")
	nodes, err := config.LoadSubscriptionNodes("srv1")
	require.NoError(t, err)
	require.Len(t, nodes, 2)
	require.Equal(t, "old", nodes[0].Name)
	require.Equal(t, "connected", c.status.State)
}
func TestImportLegacyMigratesOnlyPrivateCopy(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, ".config", "tuncli")
	require.NoError(t, os.MkdirAll(source, 0700))
	original := []byte(`{"mode":"proxy","selected_node_index":0,"nodes":[{"name":"legacy","server":"192.0.2.1"}]}`)
	require.NoError(t, os.WriteFile(filepath.Join(source, "config.json"), original, 0600))
	target := t.TempDir()
	previous, private := config.Directory, storage.Private
	config.Directory = target
	storage.Private = true
	t.Cleanup(func() { config.Directory = previous; storage.Private = private })
	require.NoError(t, ImportFiles(home, target))
	cfg, err := config.LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "legacy", cfg.SelectedNode)
	require.Equal(t, "sub1", cfg.SelectedSubscription)
	nodes, err := config.LoadSubscriptionNodes("sub1")
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	unchanged, err := os.ReadFile(filepath.Join(source, "config.json"))
	require.NoError(t, err)
	require.Equal(t, original, unchanged)
	_, err = os.Stat(filepath.Join(source, "subscriptions"))
	require.True(t, os.IsNotExist(err))
}

type blockedPlan struct {
	entered chan struct{}
	release chan struct{}
	engine  Engine
}

func (p blockedPlan) Open(context.Context) (Engine, error) {
	close(p.entered)
	<-p.release
	return p.engine, nil
}
func TestStatusAvailableDuringConnect(t *testing.T) {
	c, fw := controllerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	c.Prepare = func(context.Context, *config.Config) (Plan, error) {
		return blockedPlan{entered, release, &fakeEngine{fw: fw}}, nil
	}
	done := make(chan Response, 1)
	go func() { done <- c.Handle(Request{Operation: "start"}) }()
	<-entered
	released := false
	defer func() {
		if !released {
			close(release)
			<-done
		}
	}()
	statusDone := make(chan Response, 1)
	go func() { statusDone <- c.Handle(Request{Operation: "status"}) }()
	select {
	case response := <-statusDone:
		require.Equal(t, "connecting", response.Status.State)
		require.True(t, response.Status.Desired)
		require.True(t, response.Status.Protection)
	case <-time.After(time.Second):
		t.Fatal("status blocked behind connection")
	}
	close(release)
	released = true
	require.Empty(t, (<-done).Error)
}
