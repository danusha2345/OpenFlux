package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadVPNExceptionsIsStrictAndBounded(t *testing.T) {
	for _, s := range []string{`{"lan":true,"domains":["bank.test"],"apps":["C:\\Torrent\\anything.exe"]}`, `{"lan":true,"typo":true}`, `{} {}`, `{"domains":["https://bad.test"]}`, `{"apps":["C:\\bad\nline.exe"]}`, `{"apps":["not-an-exe"]}`} {
		p := filepath.Join(t.TempDir(), "routing.json")
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		c, e := loadBypass(p)
		if strings.Contains(s, "bank.test") {
			if e != nil || !c.LAN || !c.App(`C:\Torrent\anything.exe`) {
				t.Fatal(c, e)
			}
		} else if e == nil {
			t.Fatalf("accepted invalid config %s", s)
		}
	}
}
func TestBypassConfigCannotHideTrailingDataBeyondSizeLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "oversize.json")
	os.WriteFile(p, []byte(`{}`+strings.Repeat(" ", 64<<10)+` {}`), 0600)
	if _, e := loadBypass(p); e == nil {
		t.Fatal("oversized configuration accepted")
	}
}
