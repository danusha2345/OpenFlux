//go:build !windows

package main

import "fmt"

func checkWindowsTUN() error { return fmt.Errorf("--check-windows-tun is available only on Windows") }
