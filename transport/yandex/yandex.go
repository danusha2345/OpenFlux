package yandex

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	neturl "net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"openflux/transport"
	"openflux/utils"
)

// Precompiled once. cursorPayloadRe in particular runs on every inbound
// message, so compiling it per call (as before) was pure overhead on the hot
// receive path.
var (
	cursorPayloadRe = regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)
	clientConfigRe  = regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
)

type YandexDocsInfo struct {
	CookieStr   string
	Token       string
	DocID       string
	CallbackURL string
	UserID      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type DocSession struct {
	Info       YandexDocsInfo
	Conn       *websocket.Conn
	WriteQueue chan []byte
	UserID     string
	writeMu    sync.Mutex

	// connID is this connection's id on the server (the Socket.IO sid), as
	// listed in participant lists. Read loop only.
	connID string
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	return s.Conn.WriteMessage(messageType, data)
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	userCounter atomic.Int32
	baseUserID  string

	// Lifecycle. Every goroutine the transport starts is tracked by wg and
	// watches ctx, so Stop can end them all (including a pending reconnect
	// backoff or an in-flight dial) and wait for them.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// tlsConfig overrides the WebSocket TLS settings; tests only.
	tlsConfig     *tls.Config
	cookieFile    string
	challengeFile string
}

// stopWaitTimeout bounds how long Stop waits for the transport's goroutines.
// They all exit within milliseconds once cancelled; the bound only protects
// callers (such as the iOS bridge, which holds a lock) from a stuck one.
const stopWaitTimeout = 5 * time.Second

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
	}
	t.baseUserID = randUserID()
	return t
}

func (t *YandexDocsTransport) ConfigureManualChallenge(cookieFile, challengeFile string) {
	t.cookieFile, t.challengeFile = cookieFile, challengeFile
}

func (t *YandexDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	t.Mu.Lock()
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.session = nil
	t.Mu.Unlock()

	t.spawn("yandex.keepAlive", t.keepAliveLoop)
	t.connectToDoc(0)

	return nil
}

// Stop cancels every background goroutine, closes the live WebSocket so a
// blocked read returns, and waits for the goroutines to exit.
func (t *YandexDocsTransport) Stop() error {
	err := t.BaseTransport.Stop()

	t.Mu.Lock()
	cancel := t.cancel
	session := t.session
	t.Mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if session != nil && session.Conn != nil {
		session.Conn.Close()
	}

	done := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopWaitTimeout):
		utils.Debugf("[YDOCS] Stop: goroutines still running after %v", stopWaitTimeout)
	}
	return err
}

// spawn runs fn in a tracked, panic-safe goroutine.
func (t *YandexDocsTransport) spawn(name string, fn func()) {
	t.wg.Add(1)
	utils.SafeGo(name, func() {
		defer t.wg.Done()
		fn()
	})
}

// runCtx is the context of the current Start; Background before any Start.
func (t *YandexDocsTransport) runCtx() context.Context {
	t.Mu.RLock()
	defer t.Mu.RUnlock()
	if t.ctx == nil {
		return context.Background()
	}
	return t.ctx
}

// sleepCtx sleeps for d and reports false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (t *YandexDocsTransport) Send(data []byte) error {
	if !t.IsConnected() {
		return fmt.Errorf("transport not connected")
	}

	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()

	if session == nil {
		return fmt.Errorf("no active session")
	}

	select {
	case session.WriteQueue <- data:
		t.RecordSend(len(data))
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *YandexDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}

	utils.Debugf("[YDOCS] connectToDoc attempt ...")

	t.spawn("yandex.connect", func() {
		ctx := t.runCtx()
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		// Always mint a fresh doc userID for every reconnect attempt.
		//
		// The previous session's participant lingers on Yandex's side for
		// several seconds after the WebSocket goes away (server-visible even
		// after a client-initiated close). Dialing back in with the same
		// userID lands as a "duplicate participant" on the collab server,
		// which then closes the new socket right after the socket.io CONNECT
		// with `websocket: close 1005 (no status)` and no frames on it. That
		// keeps repeating until the ghost times out, so a single normal
		// server-side drop turns into 30-120s of unusable reconnect churn.
		//
		// Confirmed by logging otherwise-unhandled incoming frames right
		// before this change: after Yandex kicks a healthy session with
		// disconnectReason code 4007 ("drop", ~66s of clean operation), the
		// first ~10 reconnect attempts all get close 1005 within ~50ms with
		// zero recv frames. Bumping userCounter every attempt eliminates that
		// window entirely.
		//
		// The write queue (session.WriteQueue) is still preserved across
		// reconnects on the line below, so packets that were mid-flight when
		// the old socket died are not dropped.
		suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
		userID := t.baseUserID + suffix
		_ = existingSession

		info, err := t.fetchDocInfo(ctx, t.url, userID)
		if err != nil {
			if errors.Is(err, ErrManualChallenge) {
				utils.Infof("[YDOCS] browser verification required; challenge file: %s", t.challengeFile)
				if waitForCookieChange(ctx, t.cookieFile) {
					t.connectToDoc(attempt + 1)
				}
				return
			}
			utils.Debugf("[YDOCS] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}
		wsURL := info.WsURL
		wsCookies := info.CookieStr
		readTimeout := 45 * time.Second
		polled := false
		if sid, cookies, timeout, pollErr := t.engineIOPoll(ctx, info); pollErr == nil {
			u, err := neturl.Parse(info.WsURL)
			if err != nil {
				utils.Debugf("[YDOCS] invalid websocket URL: %v", err)
				t.scheduleReconnect(attempt)
				return
			}
			q := u.Query()
			q.Set("sid", sid)
			u.RawQuery = q.Encode()
			wsURL, wsCookies, readTimeout, polled = u.String(), cookies, timeout, true
		} else {
			utils.Debugf("[YDOCS] engine.io polling unavailable; trying direct websocket")
		}

		// Hard TCP dial timeout so a stuck connect/DNS to the balancer host
		// can't hang the whole transport (HandshakeTimeout alone proved
		// insufficient on iOS).
		dialer := websocket.Dialer{
			HandshakeTimeout: 15 * time.Second,
			NetDialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig: t.tlsConfig,
		}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", wsCookies)
		headers.Set("Host", info.Host)

		utils.Debugf("[YDOCS] WebSocket dial %s", maskURL(wsURL))
		conn, resp, err := dialer.DialContext(ctx, wsURL, headers)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			utils.Debugf("[YDOCS] WebSocket dial failed (http %d): %v", status, err)
			t.scheduleReconnect(attempt)
			return
		}
		utils.Debugf("[YDOCS] WebSocket connected to %s", info.Host)

		stopClose := context.AfterFunc(ctx, func() { conn.Close() })
		defer stopClose()
		if polled {
			if err := engineIOProbe(conn); err != nil {
				utils.Debugf("[YDOCS] engine.io upgrade failed: %v", err)
				conn.Close()
				t.scheduleReconnect(attempt)
				return
			}
		} else {
			// Direct websocket is accepted by some balancers. Wait for OPEN
			// before sending any socket.io frame on that path.
			conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			_, first, err := conn.ReadMessage()
			var openErr error
			if err == nil {
				readTimeout, openErr = engineReadTimeout(first)
			}
			if err != nil || openErr != nil {
				utils.Debugf("[YDOCS] invalid engine.io OPEN: read=%v parse=%v", err, openErr)
				conn.Close()
				t.scheduleReconnect(attempt)
				return
			}
		}
		conn.SetReadDeadline(time.Now().Add(readTimeout))

		writeQueue := make(chan []byte, t.GetConfig().MaxQueueSize)
		if existingSession != nil {
			writeQueue = existingSession.WriteQueue
		}

		session := &DocSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: writeQueue,
			UserID:     userID,
		}

		t.Mu.Lock()
		t.session = session
		t.SetConnected(true)
		t.Mu.Unlock()

		// Stop may have run while we were dialing and missed this conn.
		if !t.IsRunning() {
			t.SetConnected(false)
			conn.Close()
			return
		}

		if existingSession == nil {
			t.spawn("yandex.writer", t.writerLoop)
		}

		// Auth - use safeWrite
		auth1 := fmt.Sprintf(`40{"token":"%s"}`, info.Token)
		session.safeWrite(websocket.TextMessage, []byte(auth1))

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart))))

		connectedAt := time.Now()
		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
				t.SetConnected(false)
				conn.Close()
				// If the session was healthy for a while, treat the next
				// connect as fresh (attempt -1 -> next attempt 0) so backoff
				// doesn't keep growing across normal long-lived reconnects.
				next := attempt
				if time.Since(connectedAt) > 15*time.Second {
					next = -1
				}
				t.scheduleReconnect(next)
				return
			}
			conn.SetReadDeadline(time.Now().Add(readTimeout))
			t.handleMessage(session, message)
		}
		conn.Close()
	})
}

// Engine.IO advertises heartbeat times in milliseconds. Bound untrusted
// values before converting to Duration; tolerate older servers without them.
func engineReadTimeout(open []byte) (time.Duration, error) {
	var timing struct {
		PingInterval int64 `json:"pingInterval"`
		PingTimeout  int64 `json:"pingTimeout"`
	}
	if len(open) < 2 || open[0] != '0' {
		return 0, fmt.Errorf("expected OPEN")
	}
	if err := json.Unmarshal(open[1:], &timing); err != nil {
		return 0, err
	}
	if timing.PingInterval <= 0 || timing.PingTimeout <= 0 || timing.PingInterval > 300000 || timing.PingTimeout > 300000 {
		return 45 * time.Second, nil
	}
	return time.Duration(timing.PingInterval+timing.PingTimeout) * time.Millisecond, nil
}

// engineIOPoll obtains a session id for balancers that require the standard
// Engine.IO polling-to-websocket upgrade. A caller may keep the direct path
// when polling is unavailable, since older balancers accept websocket first.
func (t *YandexDocsTransport) engineIOPoll(ctx context.Context, info YandexDocsInfo) (string, string, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u, err := neturl.Parse(info.WsURL)
	if err != nil || u.Scheme != "wss" {
		return "", "", 0, fmt.Errorf("invalid websocket URL")
	}
	u.Scheme = "https"
	q := u.Query()
	q.Set("transport", "polling")
	u.RawQuery = q.Encode()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if t.tlsConfig != nil {
		tr.TLSClientConfig = t.tlsConfig
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Origin", info.Origin)
	req.Header.Set("Cookie", info.CookieStr)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("polling status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		return "", "", 0, fmt.Errorf("polling response too large or unreadable: %v", err)
	}
	if i := strings.IndexByte(string(data), 0x1e); i >= 0 {
		data = data[:i]
	}
	var open struct {
		SID      string   `json:"sid"`
		Upgrades []string `json:"upgrades"`
	}
	if len(data) < 2 || data[0] != '0' || json.Unmarshal(data[1:], &open) != nil || open.SID == "" {
		return "", "", 0, fmt.Errorf("invalid engine.io polling OPEN")
	}
	upgradeOK := false
	for _, name := range open.Upgrades {
		upgradeOK = upgradeOK || name == "websocket"
	}
	if !upgradeOK {
		return "", "", 0, fmt.Errorf("websocket upgrade unavailable")
	}
	readTimeout, err := engineReadTimeout(data)
	if err != nil {
		return "", "", 0, err
	}
	return open.SID, mergeCookies(info.CookieStr, resp.Cookies()), readTimeout, nil
}

func mergeCookies(base string, updated []*http.Cookie) string {
	values := make(map[string]string)
	for _, part := range strings.Split(base, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && name != "" {
			values[name] = value
		}
	}
	for _, cookie := range updated {
		values[cookie.Name] = cookie.Value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+values[name])
	}
	return strings.Join(parts, "; ")
}

func engineIOProbe(conn *websocket.Conn) error {
	if err := conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("2probe")); err != nil {
		return err
	}
	for i := 0; i < 5; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			return err
		}
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		switch string(msg) {
		case "3probe":
			if err := conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
				return err
			}
			return conn.WriteMessage(websocket.TextMessage, []byte("5"))
		case "2":
			if err := conn.WriteMessage(websocket.TextMessage, []byte("3")); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected engine.io probe response")
		}
	}
	return fmt.Errorf("engine.io probe response not received")
}

func (t *YandexDocsTransport) writerLoop() {
	// The write queue is created once and preserved across reconnects, so we
	// capture it and block on it instead of polling with a 10ms sleep. The old
	// poll added up to 10ms of latency to every send and woke the CPU 100x/sec
	// while idle.
	ctx := t.runCtx()
	var queue chan []byte
	for t.IsRunning() && queue == nil {
		t.Mu.Lock()
		if t.session != nil {
			queue = t.session.WriteQueue
		}
		t.Mu.Unlock()
		if queue == nil && !sleepCtx(ctx, 5*time.Millisecond) {
			return
		}
	}
	if queue == nil {
		return
	}

	var pending []byte
	for t.IsRunning() {
		if pending == nil {
			select {
			case packet, ok := <-queue:
				if !ok {
					return
				}
				pending = packet
			case <-ctx.Done():
				return
			}
		}

		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()
		if session == nil || session.Conn == nil || !t.IsConnected() {
			// Mid-reconnect: hold the packet and retry rather than drop it.
			if !sleepCtx(ctx, 15*time.Millisecond) {
				return
			}
			continue
		}

		payload := base64.StdEncoding.EncodeToString(pending)
		msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)
		if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
			utils.Debugf("[YDOCS] Write error: %v", err)
			session.Conn.Close()
			if !sleepCtx(ctx, 15*time.Millisecond) {
				return
			}
			continue // keep pending; the reconnect will bring up a new conn
		}
		pending = nil
	}
}

// keepAliveMarker is kept wire-compatible with older peers. Padding and timing
// vary so keepalives do not have a fixed TLS-record size and cadence.
const keepAliveMarker = "---KA---"

func makeKeepAliveFrame() []byte {
	padding := make([]byte, 4+rand.Intn(48))
	if _, err := crand.Read(padding); err != nil {
		// A keepalive does not need cryptographic randomness. math/rand is an
		// acceptable fallback when the OS RNG is temporarily unavailable.
		_, _ = rand.Read(padding)
	}
	encoded := base64.StdEncoding.EncodeToString(padding)
	return []byte(fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s%s"}]`,
		keepAliveMarker, encoded))
}

func (t *YandexDocsTransport) keepAliveLoop() {
	ctx := t.runCtx()
	for t.IsRunning() {
		base := t.GetConfig().KeepAliveInterval
		if base <= 0 {
			base = 10 * time.Second
		}
		// 0.5x..1.5x, while remaining interruptible by Stop().
		delay := base/2 + time.Duration(rand.Int63n(int64(base)))
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, makeKeepAliveFrame()); err != nil {
				utils.Debugf("[YDOCS] Keep-alive failed: %v", err)
				// A failed write leaves the conn unusable for writes while
				// reads may still block for a long time. Close it so the read
				// loop fails and reconnects, instead of the stream sitting
				// disconnected forever. Only mark the transport down if this
				// session has not been replaced meanwhile.
				t.Mu.Lock()
				if t.session == session {
					t.SetConnected(false)
				}
				t.Mu.Unlock()
				session.Conn.Close()
			}
		}
	}
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)
	if text == "1" || text == "41" || strings.HasPrefix(text, "44") {
		if session != nil && session.Conn != nil {
			session.Conn.Close()
		}
		return
	}

	if strings.Contains(text, keepAliveMarker) || strings.Contains(text, "__KA__") {
		// The server never echoes our own cursor messages back, so this is
		// the peer's keepalive: proof that this document reaches it.
		t.RecordPeerActivity()
		return
	}

	// The server says why it is about to drop us, e.g.
	// {"type":"disconnectReason","code":4007,"description":"drop"}. 4007 is
	// not a ban: on live documents it arrived when another participant left,
	// and the document accepted new sessions right away. So it gets no special
	// backoff; the log is for diagnosis.
	if strings.Contains(text, `"disconnectReason"`) {
		utils.Debugf("[YDOCS] server disconnect: %s", text)
		return
	}

	// Participant lists: the server's Socket.IO connect frame gives our
	// connection id, the auth reply and connectState pushes list who is in
	// the document.
	if strings.HasPrefix(text, "40{") ||
		strings.Contains(text, `"type":"auth"`) || strings.Contains(text, `"type":"connectState"`) {
		t.handleParticipants(session, text)
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			session.safeWrite(websocket.TextMessage, []byte("3"))
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}

		t.RecordReceive(len(decoded))
		t.CallReceive(decoded)
	}
}

// handleParticipants tracks our connection id and reacts to participant
// lists. A list with nobody but us means the peer has left this document (or
// sits on another document backend, where nothing reaches it): forget that it
// was heard from, so a multi-stream tunnel stops routing here at once instead
// of after the keepalive timeout. A longer list proves nothing (stale
// participants linger for a while), so only the peer's traffic marks it back;
// we just send a keepalive so a newly joined peer hears us right away.
func (t *YandexDocsTransport) handleParticipants(session *DocSession, text string) {
	if session == nil {
		return
	}
	if strings.HasPrefix(text, "40{") {
		var connect struct {
			Sid string `json:"sid"`
		}
		if json.Unmarshal([]byte(text[2:]), &connect) == nil {
			session.connID = connect.Sid
		}
		return
	}

	var frame []json.RawMessage
	if !strings.HasPrefix(text, "42") || json.Unmarshal([]byte(text[2:]), &frame) != nil || len(frame) < 2 {
		return
	}
	var msg struct {
		Participants []struct {
			ConnectionID string `json:"connectionId"`
		} `json:"participants"`
	}
	if json.Unmarshal(frame[1], &msg) != nil || msg.Participants == nil || session.connID == "" {
		return
	}
	for _, p := range msg.Participants {
		if p.ConnectionID != session.connID {
			// Someone else is here, possibly the peer that just (re)joined:
			// greet it so it hears us without waiting for our next tick.
			session.safeWrite(websocket.TextMessage, makeKeepAliveFrame())
			return
		}
	}
	utils.Debugf("[YDOCS] no other participant in the document")
	t.ForgetPeer()
}

func (t *YandexDocsTransport) extractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}

	matches := cursorPayloadRe.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (t *YandexDocsTransport) scheduleReconnect(attempt int) {
	next := attempt + 1
	if !t.IsRunning() || next >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	// Back off before retrying so a server that closes us immediately doesn't
	// turn into a tight connect/close loop (previously reconnect was instant).
	d := reconnectBackoff(next)
	utils.Debugf("[YDOCS] reconnecting in %v (attempt %d)", d, next)
	if !sleepCtx(t.runCtx(), d) || !t.IsRunning() {
		return
	}

	t.RecordReconnect()
	t.connectToDoc(next)
}

// reconnectBackoff returns an exponential backoff with jitter, capped at 30s.
//
// Each reconnect dials a brand new WebSocket, which the doc-collab server
// registers as a brand new participant in the doc's room regardless of
// client-side user-id reuse - a fast connect/close/reconnect loop piles up
// visible "ghost" participants quickly (confirmed by logging the server's
// participant-list messages during a failure streak). The floor here (was
// 500ms) is raised to slow that churn down; this doesn't change steady-state
// throughput since successful connects never hit backoff at all.
func reconnectBackoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	shift := n - 1
	if shift > 4 {
		shift = 4
	}
	d := 1500 * time.Millisecond * time.Duration(1<<uint(shift))
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	// add up to +50% jitter
	d += time.Duration(rand.Int63n(int64(d/2) + 1))
	return d
}

func (t *YandexDocsTransport) fetchDocInfo(ctx context.Context, url, userID string) (YandexDocsInfo, error) {
	jar, _ := cookiejar.New(nil)
	if t.cookieFile != "" {
		if err := loadYandexCookies(t.cookieFile, jar); err != nil && !errors.Is(err, os.ErrNotExist) {
			return YandexDocsInfo{}, err
		}
	}
	client := &http.Client{
		Jar: jar,
		// Cap redirects so an auth/login redirect loop fails fast instead of
		// hanging until the timeout (a private doc redirects to passport).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if isChallengeURL(req.URL.String()) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects (login required? doc not public?)")
			}
			return nil
		},
		Timeout: 15 * time.Second,
	}

	utils.Debugf("[YDOCS] fetchDocInfo GET %s", maskURL(url))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && isChallengeURL(resp.Header.Get("Location")) {
		return YandexDocsInfo{}, recordChallenge(resp.Request.URL.String(), resp.Header.Get("Location"), t.challengeFile)
	}
	if isChallengeURL(resp.Request.URL.String()) {
		return YandexDocsInfo{}, recordChallenge(resp.Request.URL.String(), resp.Request.URL.String(), t.challengeFile)
	}

	htmlBytes, _ := io.ReadAll(resp.Body)
	html := string(htmlBytes)
	utils.Debugf("[YDOCS] response status=%d finalURL=%s body=%dB", resp.StatusCode, maskURL(resp.Request.URL.String()), len(html))

	cookieHeader := mergeCookies("", jar.Cookies(resp.Request.URL))

	matches := clientConfigRe.FindStringSubmatch(html)
	if len(matches) < 2 {
		// Help diagnose: is this a login page, a new-editor page, etc.?
		hint := "no client-config script"
		if strings.Contains(html, "passport") || strings.Contains(strings.ToLower(html), "login") {
			hint = "looks like a login page (doc not public?)"
		}
		return YandexDocsInfo{}, fmt.Errorf("config not found: %s (status %d, final %s)", hint, resp.StatusCode, maskURL(resp.Request.URL.String()))
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("client-config is not valid JSON: %w", err)
	}

	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok || officeAction == nil {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData missing - will reconnect")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := officeAction["balancer_url"].(string)
	if !ok || balancerURL == "" {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData.balancer_url missing - will reconnect")
	}
	host := strings.TrimPrefix(balancerURL, "https://")

	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok || document == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document missing - will reconnect")
	}

	token, ok := editorConfigRaw["token"].(string)
	if !ok || token == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.token missing - will reconnect")
	}

	docKey, ok := document["key"].(string)
	if !ok || docKey == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document.key missing - will reconnect")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
	}

	return YandexDocsInfo{
		CookieStr:   cookieHeader,
		Token:       token,
		DocID:       docKey,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docKey),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     docKey,
			"userid": userID,
			"format": document["fileType"],
			"url":    document["url"],
			"title":  document["title"],
			"lcid":   25,
		},
	}, nil
}

// maskURL keeps scheme+host but hides the path and query, which carry the
// document key and session tokens (users paste these logs into issues).
func maskURL(u string) string {
	parsed, err := neturl.Parse(u)
	if err != nil {
		return "<url>"
	}
	return parsed.Scheme + "://" + parsed.Host + "/<redacted>"
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}
