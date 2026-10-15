package runner

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestProcessFileLockAndStaleState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	release, err := acquireProcessFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := acquireProcessFile(dir); err == nil {
		other()
		t.Fatal("second start succeeded")
	}
	release()
	if err := stopProcessFile(dir); err == nil {
		t.Fatal("stale state accepted")
	}
	release, err = acquireProcessFile(dir)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	release()
}

func TestProcessFileRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"directory symlink", "directory permissions", "file symlink", "file permissions", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "runtime")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			pid := filepath.Join(dir, "tuncli.pid")
			switch kind {
			case "directory symlink":
				link := filepath.Join(base, "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
			case "directory permissions":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "file symlink":
				if err := os.Symlink(filepath.Join(base, "target"), pid); err != nil {
					t.Fatal(err)
				}
			case "file permissions":
				if err := os.WriteFile(pid, []byte("unchanged"), 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				target := filepath.Join(base, "target")
				if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, pid); err != nil {
					t.Fatal(err)
				}
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
	if err != nil {
		t.Fatal(err)
	}
	if fd, err := verifiedProcess(ProcessInfo{TuncliPID: os.Getpid(), StartTime: "0"}); err == nil {
		unix.Close(fd)
		t.Fatal("reused PID accepted")
	}
	fd, err := verifiedProcess(ProcessInfo{TuncliPID: os.Getpid(), StartTime: start})
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	start, err = processStartTime(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if fd, err := verifiedProcess(ProcessInfo{TuncliPID: child.Process.Pid, StartTime: start}); err == nil {
		unix.Close(fd)
		t.Fatal("foreign executable accepted")
	}
}

func TestStopRefusesLockedForeignPID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	release, err := acquireProcessFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	start, err := processStartTime(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(ProcessInfo{TuncliPID: child.Process.Pid, StartTime: start})
	if err := os.WriteFile(filepath.Join(dir, "tuncli.pid"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := stopProcessFile(dir); err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if err := child.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("foreign process was signaled: %v", err)
	}
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
	os.Stdout.WriteString("ready\n")
	<-signals
	release()
	os.Exit(0)
}

func TestStopGracefullyTerminatesOwnedProcess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	child := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$")
	child.Env = append(os.Environ(), "TUNCLI_PROCESS_HELPER="+dir)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	ready := make(chan bool, 1)
	go func() { s := bufio.NewScanner(stdout); ready <- s.Scan() && s.Text() == "ready" }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("helper failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("helper timeout")
	}
	if err := stopProcessFile(dir); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child still running")
	}
	if err := stopProcessFile(dir); err == nil {
		t.Fatal("second stop succeeded")
	}
}
