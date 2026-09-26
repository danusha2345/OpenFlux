package yandex

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openflux/transport"
)

func TestManualChallengeIsRecognizedAndSavedPrivately(t *testing.T) {
	const challenge = "https://docs.yandex.ru/showcaptchafast?test-token=private"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", challenge)
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	for _, kind := range []string{"docs", "volga"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "challenge.url")
			var err error
			if kind == "docs" {
				tr := NewYandexDocsTransport(server.URL, transport.DefaultConfig())
				tr.ConfigureManualChallenge("", path)
				_, err = tr.fetchDocInfo(context.Background(), server.URL, "123")
			} else {
				_, err = authorizeWithManual(context.Background(), server.URL, "", path)
			}
			if !errors.Is(err, ErrManualChallenge) || strings.Contains(err.Error(), "private") {
				t.Fatalf("challenge error = %v", err)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil || string(data) != challenge+"\n" {
				t.Fatalf("challenge file: data=%q err=%v", data, readErr)
			}
			info, statErr := os.Stat(path)
			if statErr != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("challenge file mode: info=%v err=%v", info, statErr)
			}
		})
	}
}

func TestManualChallengeRejectsUntrustedRedirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "challenge.url")
	err := recordChallenge("https://docs.yandex.ru/edit/doc", "https://example.test/showcaptcha", path)
	if !errors.Is(err, ErrManualChallenge) {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("untrusted challenge was saved: %v", statErr)
	}
}

func TestManualChallengeWaitWakesOnCookieFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.txt")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- waitForCookieChange(ctx, path) }()
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(path, []byte("cookies"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case woke := <-done:
		if !woke {
			t.Fatal("wait did not wake after cookie file appeared")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("wait missed the cookie file update")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if waitForCookieChange(cancelled, path) {
		t.Fatal("cancelled wait returned true")
	}
}
