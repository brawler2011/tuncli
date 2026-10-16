package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
	"github.com/brawler2011/tuncli/pkg/runner"
	"github.com/brawler2011/tuncli/pkg/storage"
	"golang.org/x/sys/unix"
)

const ServiceBinary = "/usr/local/libexec/tuncli/tuncli"
const DaemonUnit = `[Unit]
Description=tuncli VPN and local control API
Requires=tuncli-guard.service
After=tuncli-guard.service network.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/local/libexec/tuncli/tuncli daemon
Restart=always
RestartSec=2
KillMode=control-group
TimeoutStopSec=15
RuntimeDirectory=tuncli
RuntimeDirectoryMode=0755
UMask=0077
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tuncli /run/tuncli
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER

[Install]
WantedBy=multi-user.target
`
const GuardUnit = `[Unit]
Description=tuncli early VPN leak protection
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/tuncli/tuncli service guard
RemainAfterExit=yes
UMask=0077

[Install]
WantedBy=multi-user.target
`

func rootOnly() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("use sudo tuncli service <install|uninstall|recover>")
	}
	return nil
}
func Systemctl(args ...string) error {
	b, err := exec.Command("/usr/bin/systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, b)
	}
	return nil
}
func readManifest() (Manifest, error) {
	var m Manifest
	b, e := os.ReadFile(ManifestPath)
	if e != nil {
		return m, e
	}
	e = json.Unmarshal(b, &m)
	if m.UID < 0 {
		return m, fmt.Errorf("invalid owner UID")
	}
	return m, e
}
func privateState() error {
	if err := rootOnly(); err != nil {
		return err
	}
	// Never inherit sudo ownership rules into the service's state.
	_ = os.Unsetenv("SUDO_USER")
	_ = os.Unsetenv("SUDO_UID")
	_ = os.Unsetenv("SUDO_GID")
	_ = os.Unsetenv("DOAS_USER")
	storage.Private = true
	config.Directory = StateDir
	return nil
}
func Guard() error {
	if err := privateState(); err != nil {
		return err
	}
	c := NewController(StateDir, nil)
	if err := c.Load(); err != nil {
		return errors.Join(err, c.Firewall.Apply(false))
	}
	if !c.status.Desired {
		return c.Firewall.Remove()
	}
	if err := recoverTransaction(StateDir); err != nil {
		return errors.Join(err, c.Firewall.Apply(false))
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return errors.Join(err, c.Firewall.Apply(false))
	}
	if cfg.Mode != "proxy" {
		return c.Firewall.Apply(false)
	}
	return c.Firewall.Remove()
}
func Daemon(ctx context.Context, command func([]string) (string, error)) error {
	if err := privateState(); err != nil {
		return err
	}
	release, err := runner.AcquireRuntime()
	if err != nil {
		return err
	}
	defer release()
	if err := runner.SecureExecutable(ServiceBinary); err != nil {
		return err
	}
	m, err := readManifest()
	if err != nil {
		return err
	}
	if err = recoverTransaction(StateDir); err != nil {
		return err
	}
	c := NewController(StateDir, command)
	if err = c.Load(); err != nil {
		return err
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	c.status.Node = cfg.SelectedNode
	c.status.Mode = cfg.Mode
	if c.status.Desired && cfg.Mode == "tun" {
		if err = c.guard(false); err != nil {
			return err
		}
	} else {
		// Finish an explicit stop interrupted after persisting desired=false.
		if err = c.Firewall.Remove(); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(filepath.Dir(Socket), 0755); err != nil {
		return err
	}
	// systemd guarantees a single daemon; never unlink an active listener.
	if conn, e := net.DialTimeout("unix", Socket, time.Second); e == nil {
		_ = conn.Close()
		return fmt.Errorf("control socket already in use")
	}
	if err = os.Remove(Socket); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	if err = os.Chmod(Socket, 0666); err != nil {
		return err
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { c.Run(workerCtx); close(done) }()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, e := listener.AcceptUnix()
		if e != nil {
			cancel()
			<-done
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		go ServeConnection(conn, uint32(m.UID), c.Handle)
	}
}

// ImportFiles reads beneath the original user's home with openat2, refusing
// symlinks and traversal. The originals are never opened for writing.
func ImportFiles(home, target string) error {
	fd, err := unix.Open(home, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	dirfd, err := unix.Openat2(fd, ".config/tuncli", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(dirfd), "import")
	defer func() { _ = source.Close() }()
	var total int64
	var copyDir func(int, string) error
	copyDir = func(parent int, relative string) error {
		dup, e := unix.Openat(parent, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		d := os.NewFile(uintptr(dup), relative)
		entries, e := d.ReadDir(-1)
		_ = d.Close()
		if e != nil {
			return e
		}
		for _, entry := range entries {
			name := entry.Name()
			rel := filepath.Join(relative, name)
			if relative == "" && name != "config.json" && name != "subscriptions" && name != "routing" && name != "hwid" {
				continue
			}
			child, e := unix.Openat2(parent, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
			if e != nil {
				return e
			}
			f := os.NewFile(uintptr(child), name)
			st, e := f.Stat()
			if e != nil {
				_ = f.Close()
				return e
			}
			if st.IsDir() {
				if relative != "" {
					_ = f.Close()
					return fmt.Errorf("unexpected nested import directory")
				}
				e = copyDir(child, rel)
				_ = f.Close()
				if e != nil {
					return e
				}
				continue
			}
			if !st.Mode().IsRegular() {
				_ = f.Close()
				return fmt.Errorf("non-regular import file")
			}
			b, e := io.ReadAll(io.LimitReader(f, 16<<20+1))
			_ = f.Close()
			if e != nil {
				return e
			}
			total += int64(len(b))
			if len(b) > 16<<20 || total > 64<<20 {
				return fmt.Errorf("import too large")
			}
			if e = storage.Mkdir(filepath.Dir(filepath.Join(target, rel))); e != nil {
				return e
			}
			if e = storage.Write(filepath.Join(target, rel), b); e != nil {
				return e
			}
		}
		return nil
	}
	return copyDir(dirfd, "")
}
func Install() error {
	if err := rootOnly(); err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd is required; use tuncli run on other init systems")
	}
	if Installed() {
		return fmt.Errorf("service already installed")
	}
	lease, err := runner.AcquireRuntime()
	if err != nil {
		return fmt.Errorf("stop the foreground VPN before installing: %w", err)
	}
	leaseHeld := true
	defer func() {
		if leaseHeld {
			lease()
		}
	}()

	owner, err := user.Current()
	if err != nil {
		return err
	}
	if uid := os.Getenv("SUDO_UID"); uid != "" {
		owner, err = user.LookupId(uid)
		if err != nil {
			return err
		}
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil {
		return err
	}
	if err = privateState(); err != nil {
		return err
	}
	if _, err = os.Lstat(StateDir); err == nil {
		return fmt.Errorf("%s already exists; preserve or move the previous export before installing", StateDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = os.Mkdir(StateDir, 0700); err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.RemoveAll(StateDir)
		}
	}()
	if err = ImportFiles(owner.HomeDir, StateDir); err != nil {
		return fmt.Errorf("import (prepare with tuncli add/select first): %w", err)
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	if _, err = runner.PrepareManaged(context.Background(), cfg); err != nil {
		return fmt.Errorf("import validation: %w", err)
	}
	// Validate nft before changing the host: parse the rules in check-only mode.
	check := exec.Command("/usr/sbin/nft", "--check", "-f", "-")
	check.Stdin = strings.NewReader("add table inet " + Table + "\n" + Rules(false))
	if b, e := check.CombinedOutput(); e != nil {
		return fmt.Errorf("nft unavailable: %w: %s", e, b)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(ServiceBinary), 0755); err != nil {
		return err
	}
	// Reject preexisting user-writable ancestors before writing as root.
	if err = secureDirectory(filepath.Dir(ServiceBinary)); err != nil {
		return err
	}
	if err = storage.Write(ServiceBinary, binary); err != nil {
		return err
	}
	if err = os.Chmod(ServiceBinary, 0755); err != nil {
		return err
	}
	if err = runner.SecureExecutable(ServiceBinary); err != nil {
		return err
	}
	c := NewController(StateDir, nil)
	if err = c.saveDesired(true); err != nil {
		return err
	}
	for path, body := range map[string]string{"/etc/systemd/system/tuncli.service": DaemonUnit, "/etc/systemd/system/tuncli-guard.service": GuardUnit} {
		if err = storage.Write(path, []byte(body)); err != nil {
			return err
		}
	}
	manifest, _ := json.Marshal(Manifest{UID: uid})
	if err = storage.Write(ManifestPath, manifest); err != nil {
		return err
	}
	if err = os.Chmod(ManifestPath, 0644); err != nil {
		return err
	}
	installed = true // Preserve state and recovery controls if activation fails.
	lease()
	leaseHeld = false
	if err = Systemctl("daemon-reload"); err != nil {
		return err
	}
	return Systemctl("enable", "--now", "tuncli-guard.service", "tuncli.service")
}
func secureDirectory(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		// os.Stat uses syscall.Stat_t; use unix.Stat for a portable UID check on Linux.
		var s unix.Stat_t
		if err = unix.Lstat(p, &s); err != nil {
			return err
		}
		if !st.IsDir() || s.Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("unsafe service directory %s", p)
		}
		if p == "/" {
			return nil
		}
	}
}
func Recover() error {
	if err := privateState(); err != nil {
		return err
	}
	// Persist first, then stop the cgroup, then remove only tuncli's table.
	c := NewController(StateDir, nil)
	if err := c.saveDesired(false); err != nil {
		return err
	}
	if err := Systemctl("stop", "tuncli.service"); err != nil {
		return err
	}
	return c.Firewall.Remove()
}
func Uninstall() error {
	if err := Recover(); err != nil {
		return err
	}
	if err := Systemctl("disable", "--now", "tuncli.service", "tuncli-guard.service"); err != nil {
		return err
	}
	// StateDir remains as a root-only settings export, including subscription secrets.
	for _, p := range []string{ManifestPath, "/etc/systemd/system/tuncli.service", "/etc/systemd/system/tuncli-guard.service", ServiceBinary} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return Systemctl("daemon-reload")
}
