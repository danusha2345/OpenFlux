//go:build windows

package updater

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Windows cannot replace the running executable. A temporary copy of this
// trusted binary finishes the swap after the parent exits.
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
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	cache = filepath.Join(cache, "openflux")
	if err := os.MkdirAll(cache, 0700); err != nil {
		return err
	}
	cleanOldHelpers(cache)
	helper, err := os.CreateTemp(cache, "openflux-helper-*.exe")
	if err != nil {
		return err
	}
	helpPath := helper.Name()
	source, err := os.Open(exe)
	if err != nil {
		helper.Close()
		os.Remove(helpPath)
		return err
	}
	_, copyErr := io.Copy(helper, source)
	closeErr := helper.Close()
	source.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(helpPath)
		return fmt.Errorf("copy updater helper: %v, %v", copyErr, closeErr)
	}
	allArgs := append([]string{"--complete-update", exe, staged, backup}, args...)
	cmd := exec.Command(helpPath, allArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		os.Remove(helpPath)
		return err
	}
	return nil
}

func CompletePending(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("incomplete update arguments")
	}
	exe, staged, backup := args[0], args[1], args[2]
	var err error
	for i := 0; i < 60; i++ {
		if err = os.Rename(exe, backup); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("replace old executable: %w", err)
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Rename(backup, exe)
		return err
	}
	cmd := exec.Command(exe, args[3:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		_ = os.Rename(exe, staged)
		_ = os.Rename(backup, exe)
		return err
	}
	return nil
}

func cleanOldHelpers(dir string) {
	paths, _ := filepath.Glob(filepath.Join(dir, "openflux-helper-*.exe"))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && time.Since(info.ModTime()) > time.Hour {
			_ = os.Remove(path)
		}
	}
}
