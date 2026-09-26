package yandex

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrManualChallenge = errors.New("Yandex requires browser verification")

func isChallengeURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	return strings.Contains(path, "showcaptcha")
}

func allowedYandexHost(host string) bool {
	host = strings.ToLower(strings.TrimPrefix(host, "."))
	for _, domain := range []string{"yandex.ru", "yandex.kz", "yandex.net", "yandex.com"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// recordChallenge stores the redirect URL privately for an operator to open
// through the VPS. It never puts the document key or challenge token in logs.
func recordChallenge(parentURL, location, path string) error {
	if path == "" {
		return ErrManualChallenge
	}
	parent, err := url.Parse(parentURL)
	if err != nil {
		return fmt.Errorf("%w: invalid parent URL", ErrManualChallenge)
	}
	ref, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("%w: invalid challenge URL", ErrManualChallenge)
	}
	challenge := parent.ResolveReference(ref)
	if challenge.Scheme != "https" || !allowedYandexHost(challenge.Hostname()) || challenge.User != nil || !isChallengeURL(challenge.String()) {
		return fmt.Errorf("%w: untrusted challenge URL", ErrManualChallenge)
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".openflux-challenge-*")
	if err != nil {
		return fmt.Errorf("%w: cannot create challenge file: %v", ErrManualChallenge, err)
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return fmt.Errorf("%w: cannot protect challenge file: %v", ErrManualChallenge, err)
	}
	if _, err := f.WriteString(challenge.String() + "\n"); err != nil {
		f.Close()
		return fmt.Errorf("%w: cannot write challenge file: %v", ErrManualChallenge, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: cannot close challenge file: %v", ErrManualChallenge, err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("%w: cannot publish challenge file: %v", ErrManualChallenge, err)
	}
	return ErrManualChallenge
}

func waitForCookieChange(ctx context.Context, path string) bool {
	if path == "" {
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	before, _ := os.Stat(path)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			if info, err := os.Stat(path); err == nil &&
				(before == nil || !os.SameFile(info, before) ||
					info.ModTime().After(before.ModTime()) || info.Size() != before.Size()) {
				return true
			}
		}
	}
}
