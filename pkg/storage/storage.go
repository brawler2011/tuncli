// Package storage provides atomic, original-user-owned configuration files.
package storage

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

func Own(path string) error {
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
	if err := os.MkdirAll(path, 0755); err != nil {
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
		err = f.Chmod(0644)
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
	return os.Rename(f.Name(), path)
}
