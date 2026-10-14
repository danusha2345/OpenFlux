//go:build linux && !android

package main

import (
	"bufio"
	"fmt"
	"golang.zx2c4.com/wireguard/tun"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeTun struct {
	tun.Device
	closed bool
}

func (d *fakeTun) Close() error { d.closed = true; return nil }

// All external commands are fakes: this test must never modify host networking.
func TestLinuxTunnelRollsBackFailedIPv6Route(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "commands")
	t.Setenv("OPENFLUX_TEST_LOG", log)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	scripts := map[string]string{
		"nft": `printf '%s\n' "nft $*" >>"$OPENFLUX_TEST_LOG"; if [ "$1" = '-f' ]; then cat >/dev/null; fi`,
		"ip":  `printf '%s\n' "ip $*" >>"$OPENFLUX_TEST_LOG"; if [ "$1" = '-6' ]; then exit 1; fi`,
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	dev := &fakeTun{}
	c := &TUNClient{dev: dev, name: "testtun", guard: "openflux_test"}
	if err := c.ConfigureDefault(); err == nil {
		t.Fatal("IPv6 route failure accepted")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !dev.closed {
		t.Fatal("adapter left open")
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "nft delete table inet openflux_test") {
		t.Fatalf("guard not removed: %s", data)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

// The watchdog must clean up even when the core cannot run deferred cleanup.
func TestLinuxGuardCleanupAfterProcessCrash(t *testing.T) {
	if os.Getenv("OPENFLUX_CRASH_HELPER") == "1" {
		c := &TUNClient{dev: &fakeTun{}, name: "testtun", guard: "openflux_crash_test"}
		if err := c.ConfigureDefault(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("READY")
		time.Sleep(time.Minute)
		return
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "commands")
	for _, name := range []string{"nft", "ip", "resolvectl"} {
		script := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >>\"$OPENFLUX_TEST_LOG\"\n"
		if name == "nft" {
			script += "if [ \"$1\" = '-f' ]; then cat >/dev/null; fi\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxGuardCleanupAfterProcessCrash$")
	cmd.Env = append(os.Environ(), "OPENFLUX_CRASH_HELPER=1", "OPENFLUX_TEST_LOG="+log, "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() || scanner.Text() != "READY" {
		t.Fatal("helper did not install guard")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(log)
		if strings.Contains(string(data), "nft delete table inet openflux_crash_test") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("guard remained after abrupt core exit")
}
