package yandex

import (
	"context"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"openflux/transport"
)

type volgaRoundTrip func(*http.Request) (*http.Response, error)

func (f volgaRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testVolgaAuth(token string) *volgaAuth {
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse("https://volga.yandex.ru/")
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: token}})
	return &volgaAuth{Token: token, docURL: "https://example.invalid/doc", Session: &http.Client{Jar: jar}}
}

func TestVolgaAuthorizationRejectsChallengeAndHTTPFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   string
	}{
		{"challenge", http.StatusFound, "interactive verification"},
		{"server-error", http.StatusInternalServerError, "unexpected status 500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("User-Agent"); got != volgaUserAgent {
					t.Errorf("User-Agent = %q", got)
				}
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "/showcaptchafast?token=secret")
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			_, err := authorize(context.Background(), server.URL+"/document?key=secret")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("authorize error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("authorization error exposed URL query: %v", err)
			}
		})
	}
}

func TestVolgaConcurrentAuthRefresh(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			r := newRelayClient(testVolgaAuth("old"), DefaultVolgaConfig(), &VolgaStats{})
			defer r.Stop()
			var refreshes, delivered atomic.Int32
			r.authorize = func(ctx context.Context, doc string) (*volgaAuth, error) {
				refreshes.Add(1)
				return testVolgaAuth("new"), nil
			}
			r.httpClient.Transport = volgaRoundTrip(func(req *http.Request) (*http.Response, error) {
				cookie, err := req.Cookie("session")
				if err != nil || "Bearer "+cookie.Value != req.Header.Get("Authorization") {
					t.Error("cookie/auth snapshot mismatch")
				}
				code := status
				if req.Header.Get("Authorization") == "Bearer new" {
					code = 204
					delivered.Add(1)
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			})
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := r.sendBatch([][]byte{{1, 2, 3}}); err != nil {
						t.Error(err)
					}
				}()
			}
			wg.Wait()
			if refreshes.Load() != 1 || delivered.Load() != 32 {
				t.Fatalf("refreshes=%d delivered=%d", refreshes.Load(), delivered.Load())
			}
			if r.stats.PacketsSent.Load() != 32 {
				t.Fatal("retried packets counted incorrectly")
			}
		})
	}
}

func TestVolgaAuthRetryBounded(t *testing.T) {
	r := newRelayClient(testVolgaAuth("old"), DefaultVolgaConfig(), &VolgaStats{})
	defer r.Stop()
	var requests atomic.Int32
	r.authorize = func(context.Context, string) (*volgaAuth, error) { return testVolgaAuth("new"), nil }
	r.httpClient.Transport = volgaRoundTrip(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if r.sendBatch([][]byte{{1, 2}}) == nil || requests.Load() != 2 {
		t.Fatalf("requests=%d", requests.Load())
	}
}

func TestVolgaStopCancelsRefresh(t *testing.T) {
	r := newRelayClient(testVolgaAuth("old"), DefaultVolgaConfig(), &VolgaStats{})
	entered := make(chan struct{})
	r.authorize = func(ctx context.Context, _ string) (*volgaAuth, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { done <- r.refreshAuth(r.getAuth()) }()
	<-entered
	r.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("refresh did not stop")
	}
	for i := 0; i < 100; i++ {
		if r.Send([]byte{1, 2}) == nil {
			t.Fatal("Send accepted after Stop")
		}
	}
}

func TestVolgaMalformedBatchRejected(t *testing.T) {
	for _, b := range [][]byte{{1}, {0, 0}, {0, 4, 1, 2}, {0, 1, 7, 0}, {0, 1, 7, 0, 0}} {
		if got := decodeBatch(b); len(got) != 0 {
			t.Fatalf("%x decoded as %x", b, got)
		}
	}
	got := decodeBatch([]byte{0, 2, 1, 2, 0, 1, 3})
	if len(got) != 2 {
		t.Fatal(got)
	}
}

func TestVolgaConcurrentStop(t *testing.T) {
	tr := NewYandexVolgaTransport("", transport.TransportConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); tr.Stop() }()
	}
	wg.Wait()
}

func TestVolgaStopClosesBlockedRead(t *testing.T) {
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	w := newWSListener(testVolgaAuth("a"), DefaultVolgaConfig(), &VolgaStats{}, nil, nil)
	w.conn = conn
	w.wg.Add(1)
	go func() { defer w.wg.Done(); conn.ReadMessage() }()
	done := make(chan struct{})
	go func() { w.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("Stop blocked on read")
	}
}

func TestVolgaStopAllowsReceiveCallbackToFinishSending(t *testing.T) {
	tr := NewYandexVolgaTransport("", transport.TransportConfig{})
	tr.relay = newRelayClient(testVolgaAuth("a"), DefaultVolgaConfig(), tr.stats)
	tr.ws = newWSListener(tr.relay.getAuth(), tr.config, tr.stats, tr.relay, nil)
	tr.ws.wg.Add(1)
	go func() {
		defer tr.ws.wg.Done()
		<-tr.relay.ctx.Done()
		// A receive callback can produce a handshake response while Stop waits
		// for the WS reader. Sending must not require Stop's lifecycle lock.
		if err := tr.Send([]byte{1, 2}); err == nil {
			t.Error("send accepted while stopping")
		}
	}()
	done := make(chan struct{})
	go func() { tr.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop deadlocked with receive callback")
	}
}

func TestVolgaFailedRefreshBackoff(t *testing.T) {
	r := newRelayClient(testVolgaAuth("old"), DefaultVolgaConfig(), &VolgaStats{})
	defer r.Stop()
	var calls atomic.Int32
	r.authorize = func(context.Context, string) (*volgaAuth, error) { calls.Add(1); return nil, fmt.Errorf("unavailable") }
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.refreshAuth(r.getAuth()) == nil {
				t.Error("failure lost")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("refresh storm: %d", calls.Load())
	}
	r.refreshAfter = time.Time{}
	if r.refreshAuth(r.getAuth()) == nil || calls.Load() != 2 || r.refreshDelay != 2*time.Second {
		t.Fatal("backoff did not allow a later retry")
	}
}

func TestVolgaStopDuringInitialAuthorization(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	tr := NewYandexVolgaTransport(server.URL, transport.DefaultConfig())
	started := make(chan error, 1)
	go func() { started <- tr.Start() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authorization did not start")
	}
	stopped := make(chan struct{})
	go func() { tr.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for authorization timeout")
	}
	if err := <-started; err == nil {
		t.Fatal("cancelled Start succeeded")
	}
	if tr.IsRunning() || tr.IsConnected() {
		t.Fatal("cancelled transport remained active")
	}
}
