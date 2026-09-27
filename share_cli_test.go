package main

import (
	"os"
	"path/filepath"
	"testing"

	"openflux/transport"
)

func TestBuildShareUsesExistingNoiseIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exit.key")
	key, _, err := transport.LoadOrCreateStaticKey(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := buildShare(roleExit, "mailru", "https://cloud.mail.ru/public/a/b", path, "", codecBatched)
	if err != nil {
		t.Fatal(err)
	}
	if c.PeerKey != transport.PublicKeyString(key.Public) {
		t.Fatal("share key differs from exit identity")
	}
	if _, err := buildShare(roleExit, "mailru", c.URL, path, "secret", codecBatched); err == nil {
		t.Fatal("PSK-protected node was accepted")
	}
	if _, err := buildShare(roleClient, "mailru", c.URL, path, "", codecBatched); err == nil {
		t.Fatal("client was accepted as exit")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := buildShare(roleExit, "mailru", c.URL, path, "", codecBatched); err == nil {
		t.Fatal("publicly readable key file was accepted")
	}
}
