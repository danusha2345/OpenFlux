//go:build !windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Install atomically replaces the CLI and starts the new version with the
// original arguments. The previous binary remains as a rollback file.
func Install(staged, oldVersion string, args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	backup := exe + "." + oldVersion + ".bak"
	if _, err := os.Stat(backup); err == nil {
		return fmt.Errorf("rollback file already exists: %s", backup)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(exe, backup); err != nil {
		return err
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Rename(backup, exe)
		return err
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.Rename(exe, staged)
		_ = os.Rename(backup, exe)
		return err
	}
	return nil
}
