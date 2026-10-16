// Package storage provides atomic, original-user-owned configuration files.
package storage

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// Private disables original-user ownership for system service state.
var Private bool

func Own(path string) error {
	if Private {
		return nil
	}
	if os.Geteuid() != 0 {
		return nil
	}
	for _, key := range []string{"SUDO_USER", "DOAS_USER"} {
		if name := os.Getenv(key); name != "" {
			u, err := user.Lookup(name)
			if err != nil {
				return err
			}
			uid, err := strconv.Atoi(u.Uid)
			if err != nil {
				return err
			}
			gid, err := strconv.Atoi(u.Gid)
			if err != nil {
				return err
			}
			return os.Chown(path, uid, gid)
		}
	}
	return nil
}
func Mkdir(path string) error {
	if err := os.MkdirAll(path, directoryMode()); err != nil {
		return err
	}
	return Own(path)
}
func Write(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tuncli-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) //nolint:errcheck
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(fileMode())
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = Own(f.Name()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func directoryMode() os.FileMode {
	if Private {
		return 0700
	}
	return 0755
}
func fileMode() os.FileMode {
	if Private {
		return 0600
	}
	return 0644
}
