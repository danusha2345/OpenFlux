//go:build windows

package main

import (
	"fmt"
	firewall "github.com/p1neappleXpress/OpenFlux/internal/winfirewall"
	"os/exec"
)

func checkWindowsTUN() error {
	if _, err := exec.LookPath("netsh"); err != nil {
		return fmt.Errorf("netsh: %w", err)
	}
	if err := firewall.CheckPrerequisites(); err != nil {
		return fmt.Errorf("WFP prerequisites: %w", err)
	}
	fmt.Println("WFP process identity and session: OK. No filters or routes were installed.")
	fmt.Println("This does not verify Wintun, carrier connectivity or live leak protection.")
	return nil
}
