//go:build !windows

package updater

import "fmt"

func CompletePending([]string) error {
	return fmt.Errorf("pending update helper is only used on Windows")
}
