package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ProcessInfo identifies a particular process, rather than a reusable PID alone.
type ProcessInfo struct {
	TuncliPID int    `json:"tuncli_pid"`
	StartTime string `json:"start_time"`
}

func processDir() string { return fmt.Sprintf("/tmp/tuncli-%d", os.Geteuid()) }

// Keep runtime state out of the user's config directory: sudo must never trust
// a user-writable PID file. Open relative to a verified directory descriptor.
func openProcessFile(dir string, create bool) (*os.File, error) {
	if create {
		if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	dfd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	if err := unix.Fstat(dfd, &st); err != nil {
		return nil, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		return nil, fmt.Errorf("unsafe runtime directory: %s", dir)
	}
	flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Openat(dfd, "tuncli.pid", flags, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), filepath.Join(dir, "tuncli.pid"))
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 || st.Nlink != 1 {
		_ = f.Close()
		return nil, fmt.Errorf("unsafe PID file")
	}
	return f, nil
}

func processStartTime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	// comm may contain spaces and parentheses; fields after its last ')' start at 3.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", fmt.Errorf("invalid process stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" {
		return "", fmt.Errorf("process is unavailable")
	}
	return fields[19], nil
}

func acquireProcessFile(dir string) (func(), error) {
	f, err := openProcessFile(dir, true)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { _ = f.Close(); return nil, err }
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("another tuncli instance is running: %w", err))
	}
	start, err := processStartTime(os.Getpid())
	if err != nil {
		return fail(err)
	}
	data, err := json.Marshal(ProcessInfo{TuncliPID: os.Getpid(), StartTime: start})
	if err != nil {
		return fail(err)
	}
	if err := f.Truncate(0); err != nil {
		return fail(err)
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		return fail(err)
	}
	return func() {
		// Leave the inode in place so concurrent starters all lock the same file.
		_ = f.Truncate(0)
		_ = f.Close()
	}, nil
}

func verifiedProcess(info ProcessInfo) (int, error) {
	if info.TuncliPID <= 0 || info.StartTime == "" {
		return -1, fmt.Errorf("invalid PID record")
	}
	if _, err := strconv.ParseUint(info.StartTime, 10, 64); err != nil {
		return -1, err
	}
	// pidfd pins the process identity even if it exits and Linux reuses its PID.
	fd, err := unix.PidfdOpen(info.TuncliPID, 0)
	if err != nil {
		return -1, err
	}
	fail := func(err error) (int, error) { _ = unix.Close(fd); return -1, err }
	start, err := processStartTime(info.TuncliPID)
	if err != nil {
		return fail(err)
	}
	if start != info.StartTime {
		return fail(fmt.Errorf("stale PID record"))
	}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return fail(err)
	}
	target, err := os.Stat(fmt.Sprintf("/proc/%d/exe", info.TuncliPID))
	if err != nil {
		return fail(err)
	}
	if !os.SameFile(self, target) {
		return fail(fmt.Errorf("PID does not belong to this tuncli executable"))
	}
	return fd, nil
}

func stopProcessFile(dir string) error {
	f, err := openProcessFile(dir, false)
	if err != nil {
		return fmt.Errorf("cannot open tuncli runtime state (use the same user/sudo as start): %w", err)
	}
	defer func() { _ = f.Close() }()
	// An unlocked file is stale. Never signal a PID from such a file.
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		return fmt.Errorf("tuncli is not currently running")
	} else if !errors.Is(err, unix.EWOULDBLOCK) {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return err
	}
	var info ProcessInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return fmt.Errorf("invalid PID record: %w", err)
	}
	fd, err := verifiedProcess(info)
	if err != nil {
		return fmt.Errorf("refusing to signal an unverified process: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.PidfdSendSignal(fd, syscall.SIGTERM, nil, 0); err != nil {
		return fmt.Errorf("stop tuncli: %w", err)
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			fmt.Println("VPN stopped successfully.")
			return nil
		}
	}
	// Do not force kill the parent: it owns network and sidecar cleanup.
	return fmt.Errorf("tuncli did not finish shutdown within 5 seconds")
}

// Stop asks the running instance to close its VPN and sidecar gracefully.
func Stop() error { return stopProcessFile(processDir()) }

// AcquireRuntime prevents a managed engine from overlapping a foreground instance.
func AcquireRuntime() (func(), error) { return acquireProcessFile(processDir()) }
