package avito

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGatePersistDoesNotFollowPredictableTempSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "protected")
	path := filepath.Join(dir, "gate")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".tmp"); err != nil {
		t.Skip(err)
	}
	g := newSharedGate(path)
	g.persist()
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "unchanged" {
		t.Fatalf("target overwritten: %q %v", b, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
