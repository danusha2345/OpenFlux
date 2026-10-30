//go:build !windows

package routing

import "errors"

func NewOwner() (Owner, error) {
	return nil, errors.New("application VPN exceptions are supported on Windows")
}
