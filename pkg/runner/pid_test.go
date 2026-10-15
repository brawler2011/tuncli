package runner

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestProcessFileLockAndStaleState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	release, err := acquireProcessFile(dir)
	require.NoError(t, err)
	if other, err := acquireProcessFile(dir); err == nil {
		other()
		t.Fatal("second start succeeded")
	}
	release()
	err = stopProcessFile(dir)
	require.Error(t, err)
	release, err = acquireProcessFile(dir)
	require.NoError(t, err)
	release()
}

func TestProcessFileRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"directory symlink", "directory permissions", "file symlink", "file permissions", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "runtime")
			require.NoError(t, os.Mkdir(dir, 0700))
			pid := filepath.Join(dir, "tuncli.pid")
			switch kind {
			case "directory symlink":
				link := filepath.Join(base, "link")
				require.NoError(t, os.Symlink(dir, link))
				dir = link
			case "directory permissions":
				require.NoError(t, os.Chmod(dir, 0755))
			case "file symlink":
				require.NoError(t, os.Symlink(filepath.Join(base, "target"), pid))
			case "file permissions":
				require.NoError(t, os.WriteFile(pid, []byte("unchanged"), 0644))
			case "hardlink":
				target := filepath.Join(base, "target")
				require.NoError(t, os.WriteFile(target, []byte("unchanged"), 0600))
				require.NoError(t, os.Link(target, pid))
			}
			if release, err := acquireProcessFile(dir); err == nil {
				release()
				t.Fatal("unsafe runtime state accepted")
			}
		})
	}
}

func TestVerifiedProcessRejectsReusedAndForeignPID(t *testing.T) {
	start, err := processStartTime(os.Getpid())
	require.NoError(t, err)
	if fd, err := verifiedProcess(ProcessInfo{TuncliPID: os.Getpid(), StartTime: "0"}); err == nil {
		require.NoError(t, unix.Close(fd))
		t.Fatal("reused PID accepted")
	}
	fd, err := verifiedProcess(ProcessInfo{TuncliPID: os.Getpid(), StartTime: start})
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))
	child := exec.Command("sleep", "30")
	require.NoError(t, child.Start())
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	start, err = processStartTime(child.Process.Pid)
	require.NoError(t, err)
	if fd, err := verifiedProcess(ProcessInfo{TuncliPID: child.Process.Pid, StartTime: start}); err == nil {
		require.NoError(t, unix.Close(fd))
		t.Fatal("foreign executable accepted")
	}
}

func TestStopRefusesLockedForeignPID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	release, err := acquireProcessFile(dir)
	require.NoError(t, err)
	defer release()
	child := exec.Command("sleep", "30")
	require.NoError(t, child.Start())
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	start, err := processStartTime(child.Process.Pid)
	require.NoError(t, err)
	data, _ := json.Marshal(ProcessInfo{TuncliPID: child.Process.Pid, StartTime: start})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tuncli.pid"), data, 0600))
	err = stopProcessFile(dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unverified")
	require.NoError(t, child.Process.Signal(syscall.Signal(0)))
}

func TestProcessHelper(t *testing.T) {
	dir := os.Getenv("TUNCLI_PROCESS_HELPER")
	if dir == "" {
		return
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	release, err := acquireProcessFile(dir)
	if err != nil {
		os.Exit(2)
	}
	_, err = os.Stdout.WriteString("ready\n")
	require.NoError(t, err)
	<-signals
	release()
	os.Exit(0)
}

func TestStopGracefullyTerminatesOwnedProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	child := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	child.Env = append(os.Environ(), "TUNCLI_PROCESS_HELPER="+dir)
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	defer func() { _ = child.Process.Kill() }()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	ready := make(chan bool, 1)
	go func() { s := bufio.NewScanner(stdout); ready <- s.Scan() && s.Text() == "ready" }()
	select {
	case ok := <-ready:
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("helper timeout")
	}
	require.NoError(t, stopProcessFile(dir))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("child still running")
	}
	err = stopProcessFile(dir)
	require.Error(t, err)
}
