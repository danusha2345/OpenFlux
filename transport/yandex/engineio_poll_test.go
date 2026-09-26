package yandex

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"openflux/transport"
)

func TestYandexStrictBalancerUsesPollingSIDAndProbe(t *testing.T) {
	upgraded := make(chan struct{}, 1)
	balancer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("transport") {
		case "polling":
			w.Header().Set("Set-Cookie", "route=new; Path=/")
			fmt.Fprint(w, `0{"sid":"strict-session","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":30000}`)
		case "websocket":
			if r.URL.Query().Get("sid") != "strict-session" || !strings.Contains(r.Header.Get("Cookie"), "route=new") {
				http.Error(w, "polling session required", http.StatusForbidden)
				return
			}
			conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			_, first, err := conn.ReadMessage()
			if err != nil || string(first) != "2probe" {
				t.Errorf("first frame %q: %v", first, err)
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte("3probe")); err != nil {
				t.Error(err)
				return
			}
			_, second, err := conn.ReadMessage()
			if err != nil || string(second) != "5" {
				t.Errorf("upgrade frame %q: %v", second, err)
				return
			}
			upgraded <- struct{}{}
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		default:
			http.Error(w, "unknown transport", http.StatusBadRequest)
		}
	}))
	defer balancer.Close()

	config := fmt.Sprintf(`{"officeActionData":{"balancer_url":%q,"editor_config":{"token":"token","document":{"key":"doc","fileType":"docx","url":"https://example.test/doc","title":"doc"}}}}`, balancer.URL)
	document := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, clientConfigPage(config))
	}))
	defer document.Close()

	client := NewYandexDocsTransport(document.URL, transport.DefaultConfig())
	client.tlsConfig = &tls.Config{InsecureSkipVerify: true} // local test server only
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Stop()
	select {
	case <-upgraded:
	case <-time.After(3 * time.Second):
		t.Fatal("strict balancer upgrade did not complete")
	}
}
