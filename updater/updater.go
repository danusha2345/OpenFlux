package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	latestURL  = "https://api.github.com/repos/danusha2345/OpenFlux/releases/latest"
	maxBinary  = 150 << 20
	maxRelease = 1 << 20
)

type Asset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
	Digest      string `json:"digest"`
	Size        int64  `json:"size"`
}

type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

type Update struct {
	Version string
	Asset   Asset
}

func client() *http.Client {
	return &http.Client{Timeout: 8 * time.Second}
}

// Check finds a newer release for the current OS/architecture. A dev build
// has no release lineage and must be updated manually.
func Check(ctx context.Context, currentVersion string) (*Update, error) {
	return check(ctx, client(), latestURL, currentVersion, runtime.GOOS, runtime.GOARCH)
}

func check(ctx context.Context, httpClient *http.Client, endpoint, currentVersion, goos, goarch string) (*Update, error) {
	current, ok := parseVersion(currentVersion)
	if !ok {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "OpenFlux-updater")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release API: HTTP %d", resp.StatusCode)
	}
	var release Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRelease)).Decode(&release); err != nil {
		return nil, fmt.Errorf("release API: %w", err)
	}
	newer, ok := parseVersion(release.TagName)
	if !ok || !newer.after(current) {
		return nil, nil
	}
	name := "openflux-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		if err := validateAsset(asset, release.TagName); err != nil {
			return nil, err
		}
		return &Update{Version: release.TagName, Asset: asset}, nil
	}
	return nil, fmt.Errorf("release %s has no asset for %s/%s", release.TagName, goos, goarch)
}

type version struct{ major, minor, patch int }

func parseVersion(raw string) (version, bool) {
	raw = strings.TrimPrefix(raw, "v")
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return version{}, false
	}
	values := [3]int{}
	for i, part := range parts {
		if part == "" || len(part) > 5 {
			return version{}, false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return version{}, false
			}
		}
		value, err := strconv.Atoi(part)
		if err != nil {
			return version{}, false
		}
		values[i] = value
	}
	return version{values[0], values[1], values[2]}, true
}

func (v version) after(old version) bool {
	if v.major != old.major {
		return v.major > old.major
	}
	if v.minor != old.minor {
		return v.minor > old.minor
	}
	return v.patch > old.patch
}

// AutoCompatible limits unattended updates to the current protocol series.
// Operators can explicitly request a larger jump with --self-update.
func AutoCompatible(currentVersion, nextVersion string) bool {
	current, okCurrent := parseVersion(currentVersion)
	next, okNext := parseVersion(nextVersion)
	return okCurrent && okNext && current.major == next.major && current.minor == next.minor
}

func validateAsset(asset Asset, tag string) error {
	if asset.Size <= 0 || asset.Size > maxBinary {
		return fmt.Errorf("invalid release asset size")
	}
	digest := strings.TrimPrefix(asset.Digest, "sha256:")
	if len(digest) != 64 || !strings.HasPrefix(asset.Digest, "sha256:") {
		return fmt.Errorf("release asset has no SHA-256 digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("invalid release SHA-256 digest")
	}
	parsed, err := url.Parse(asset.DownloadURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid release asset URL")
	}
	want := "/danusha2345/OpenFlux/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(asset.Name)
	if parsed.EscapedPath() != want {
		return fmt.Errorf("release asset URL does not match tag")
	}
	return nil
}

// Download fetches the exact release asset and verifies its size and digest.
// It leaves a private, executable staged file beside the current binary.
func Download(ctx context.Context, update *Update) (string, error) {
	if err := validateAsset(update.Asset, update.Version); err != nil {
		return "", err
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp(filepath.Dir(exe), ".openflux-update-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	completed := false
	defer func() {
		file.Close()
		if !completed {
			os.Remove(path)
		}
	}()
	if err = file.Chmod(0700); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, update.Asset.DownloadURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, update.Asset.Size+1))
	if err != nil {
		return "", err
	}
	if n != update.Asset.Size || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), strings.TrimPrefix(update.Asset.Digest, "sha256:")) {
		return "", fmt.Errorf("downloaded asset size or SHA-256 mismatch")
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	completed = true
	return path, nil
}
