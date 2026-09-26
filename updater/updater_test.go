package updater

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckSelectsOnlyNewerVerifiedPlatformAsset(t *testing.T) {
	asset := Asset{
		Name:        "openflux-linux-amd64",
		DownloadURL: "https://github.com/danusha2345/OpenFlux/releases/download/0.1.2/openflux-linux-amd64",
		Digest:      "sha256:" + strings.Repeat("a", 64),
		Size:        1234,
	}
	release := Release{TagName: "0.1.2", Assets: []Asset{asset}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "OpenFlux-updater" {
			t.Error("missing updater User-Agent")
		}
		_ = json.NewEncoder(w).Encode(release)
	}))
	defer server.Close()

	update, err := check(context.Background(), server.Client(), server.URL, "0.1.1", "linux", "amd64")
	if err != nil || update == nil || update.Version != "0.1.2" || update.Asset != asset {
		t.Fatalf("update=%+v err=%v", update, err)
	}
	update, err = check(context.Background(), server.Client(), server.URL, "0.1.2", "linux", "amd64")
	if err != nil || update != nil {
		t.Fatalf("same release: update=%+v err=%v", update, err)
	}
	release.Assets[0].Digest = ""
	if _, err := check(context.Background(), server.Client(), server.URL, "0.1.1", "linux", "amd64"); err == nil {
		t.Fatal("asset without SHA-256 was accepted")
	}
}

func TestAutoCompatible(t *testing.T) {
	if !AutoCompatible("0.1.1", "0.1.2") || AutoCompatible("0.1.2", "0.2.0") || AutoCompatible("dev", "0.1.2") {
		t.Fatal("wrong automatic update compatibility")
	}
}
