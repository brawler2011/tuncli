package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/brawler2011/tuncli/pkg/config"
)

type ProcessInfo struct {
	TuncliPID int `json:"tuncli_pid"`
	XrayPID   int `json:"xray_pid,omitempty"`
}

func getPidFilePath() string {
	dir, err := config.GetConfigDir()
	if err == nil {
		testPath := filepath.Join(dir, "tuncli.pid")
		if f, err := os.OpenFile(testPath, os.O_RDWR|os.O_CREATE, 0666); err == nil {
			_ = f.Close()
			return testPath
		}
	}
	return "/tmp/tuncli.pid"
}

func writePidFile(tuncliPID int, xrayPID int) error {
	path := getPidFilePath()
	info := ProcessInfo{
		TuncliPID: tuncliPID,
		XrayPID:   xrayPID,
	}
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0666)
}

func removePidFile() error {
	paths := []string{"/tmp/tuncli.pid"}
	if dir, err := config.GetConfigDir(); err == nil {
		paths = append(paths, filepath.Join(dir, "tuncli.pid"))
	}
	for _, p := range paths {
		_ = os.Remove(p)
	}
	return nil
}

func readPidFile() (*ProcessInfo, error) {
	paths := []string{}
	if dir, err := config.GetConfigDir(); err == nil {
		paths = append(paths, filepath.Join(dir, "tuncli.pid"))
	}
	paths = append(paths, "/tmp/tuncli.pid")

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			var info ProcessInfo
			if err := json.Unmarshal(data, &info); err == nil {
				return &info, nil
			}
		}
	}
	return nil, os.ErrNotExist
}

func isProcessRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false
	}
	// On Linux, check if process is in zombie / defunct state
	statusData, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err == nil {
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "State:") {
				if strings.Contains(line, "Z (zombie)") {
					return false
				}
				break
			}
		}
	}
	return true
}

// Stop stops the currently running tuncli instance and any associated Xray sidecar.
func Stop() error {
	info, err := readPidFile()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("tuncli is not currently running (no active PID file found)")
		}
		return fmt.Errorf("failed to read PID file: %w", err)
	}

	stopped := false
	if info.TuncliPID > 0 && isProcessRunning(info.TuncliPID) {
		proc, err := os.FindProcess(info.TuncliPID)
		if err == nil {
			fmt.Printf("Stopping tuncli (PID %d)...\n", info.TuncliPID)
			_ = proc.Signal(syscall.SIGTERM)

			for i := 0; i < 30; i++ {
				time.Sleep(100 * time.Millisecond)
				if !isProcessRunning(info.TuncliPID) {
					stopped = true
					break
				}
			}
			if !stopped {
				fmt.Println("Force killing tuncli...")
				_ = proc.Signal(syscall.SIGKILL)
			}
		}
	}

	if info.XrayPID > 0 && isProcessRunning(info.XrayPID) {
		xproc, err := os.FindProcess(info.XrayPID)
		if err == nil {
			fmt.Printf("Stopping Xray sidecar (PID %d)...\n", info.XrayPID)
			_ = xproc.Signal(syscall.SIGTERM)
			xStopped := false
			for i := 0; i < 15; i++ {
				time.Sleep(50 * time.Millisecond)
				if !isProcessRunning(info.XrayPID) {
					xStopped = true
					break
				}
			}
			if !xStopped {
				_ = xproc.Signal(syscall.SIGKILL)
			}
		}
	}

	if os.Geteuid() == 0 {
		_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("%d", DefaultXrayMark), "lookup", "main", "priority", "8990").Run()
	}

	_ = removePidFile()
	fmt.Println("VPN stopped successfully.")
	return nil
}
