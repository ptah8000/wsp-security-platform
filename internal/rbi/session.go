package rbi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// SessionOpts configures an isolated browsing session.
type SessionOpts struct {
	BlockCopyFrom bool
	BlockCopyTo   bool
	// ClientIP optional binding metadata (logging / future authz).
	ClientIP string
	Username string
}

// Session is a live RBI browsing session (container + CDP + optional viewer WS).
type Session interface {
	ID() string
	TargetURL() string
	ContainerID() string
	// Attach binds a viewer WebSocket and streams frames / accepts input until disconnect.
	Attach(ws interface{}) error
	// Stop tears down CDP and container.
	Stop(ctx context.Context) error
}

// liveSession is the concrete session implementation.
type liveSession struct {
	id          string
	targetURL   string
	containerID string
	cdpAddr     string
	opts        SessionOpts

	orch *Orchestrator

	mu       sync.Mutex
	browser  *rod.Browser
	page     *rod.Page
	stopped  atomic.Bool
	attached atomic.Bool

	// screencast
	cancelCast context.CancelFunc
	castWG     sync.WaitGroup
}

func (s *liveSession) ID() string          { return s.id }
func (s *liveSession) TargetURL() string   { return s.targetURL }
func (s *liveSession) ContainerID() string { return s.containerID }

// connectCDP dials go-rod against the container CDP endpoint and navigates.
func (s *liveSession) connectCDP(ctx context.Context) error {
	controlURL, err := resolveControlURL(ctx, s.cdpAddr)
	if err != nil {
		return err
	}

	browser := rod.New().ControlURL(controlURL).Context(ctx)
	if err := browser.Connect(); err != nil {
		return fmt.Errorf("rod connect: %w", err)
	}

	// Isolated browser is the disposable sandbox: ignore origin TLS errors so
	// missing CA bundles inside Chromium images do not fail isolation.
	_ = proto.SecuritySetIgnoreCertificateErrors{Ignore: true}.Call(browser)

	page, err := browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		_ = browser.Close()
		return fmt.Errorf("rod page: %w", err)
	}
	if err := page.Context(ctx).Navigate(s.targetURL); err != nil {
		_ = browser.Close()
		return fmt.Errorf("navigate %s: %w", s.targetURL, err)
	}
	// Best-effort wait; don't fail isolation if the page is slow.
	_ = page.Context(ctx).Timeout(20 * time.Second).WaitLoad()

	s.mu.Lock()
	s.browser = browser
	s.page = page
	s.mu.Unlock()

	s.applyClipboardGuards()
	return nil
}

func resolveControlURL(ctx context.Context, cdpAddr string) (string, error) {
	// Prefer DevTools /json/version resolution (standard Chromium + browserless).
	base := "http://" + cdpAddr
	u, err := launcher.ResolveURL(base)
	if err == nil && u != "" {
		return u, nil
	}
	// Fall back to bare ws URL (some browserless builds).
	ws := "ws://" + cdpAddr
	if err != nil {
		slog.Debug("rbi ResolveURL failed; trying bare ws", "addr", cdpAddr, "err", err)
	}
	_ = ctx
	return ws, nil
}

func (s *liveSession) applyClipboardGuards() {
	s.mu.Lock()
	page := s.page
	opts := s.opts
	s.mu.Unlock()
	if page == nil {
		return
	}
	// Best-effort: prevent copy/cut/paste in the remote page when policy asks.
	// Viewer-side also suppresses clipboard events.
	js := `() => {
		const blockCopy = %t;
		const blockPaste = %t;
		if (blockCopy) {
			document.addEventListener('copy', e => e.preventDefault(), true);
			document.addEventListener('cut', e => e.preventDefault(), true);
		}
		if (blockPaste) {
			document.addEventListener('paste', e => e.preventDefault(), true);
		}
	}`
	// block copy FROM site → block copy/cut events; block copy TO site → block paste.
	snippet := fmt.Sprintf(js, opts.BlockCopyFrom, opts.BlockCopyTo)
	_, _ = page.Eval(snippet)
}

// Attach implements Session.Attach. ws must be *websocket.Conn.
func (s *liveSession) Attach(ws interface{}) error {
	if s == nil || s.stopped.Load() {
		return fmt.Errorf("session stopped")
	}
	conn, ok := ws.(*websocket.Conn)
	if !ok || conn == nil {
		return fmt.Errorf("Attach expects *websocket.Conn")
	}
	if !s.attached.CompareAndSwap(false, true) {
		return fmt.Errorf("session already has a viewer attached")
	}
	defer s.attached.Store(false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.startScreencast(ctx, conn); err != nil {
		return err
	}
	defer s.stopScreencast()

	// Input loop (blocks until disconnect / error).
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return nil // normal disconnect
		}
		if s.stopped.Load() {
			return nil
		}
		var msg clientMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Type != "input" {
			continue
		}
		s.handleInput(msg.Event)
	}
}

type clientMessage struct {
	Type  string          `json:"type"`
	Event json.RawMessage `json:"event"`
}

type inputEvent struct {
	Kind   string  `json:"kind"` // mouse | key | wheel | resize
	Type   string  `json:"type"` // mousePressed, mouseReleased, mouseMoved, keyDown, keyUp, char, ...
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Button string  `json:"button,omitempty"`
	DeltaX float64 `json:"deltaX,omitempty"`
	DeltaY float64 `json:"deltaY,omitempty"`
	Key    string  `json:"key,omitempty"`
	Code   string  `json:"code,omitempty"`
	Text   string  `json:"text,omitempty"`
	// Modifiers: Alt=1, Ctrl=2, Meta/Command=4, Shift=8 (CDP bitmask).
	Modifiers int `json:"modifiers,omitempty"`
}

func (s *liveSession) handleInput(raw json.RawMessage) {
	var ev inputEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		return
	}
	s.mu.Lock()
	page := s.page
	s.mu.Unlock()
	if page == nil {
		return
	}

	switch ev.Kind {
	case "mouse":
		btn := proto.InputMouseButtonNone
		switch ev.Button {
		case "left", "0":
			btn = proto.InputMouseButtonLeft
		case "middle", "1":
			btn = proto.InputMouseButtonMiddle
		case "right", "2":
			btn = proto.InputMouseButtonRight
		}
		typ := proto.InputDispatchMouseEventType(ev.Type)
		if ev.Type == "" {
			typ = proto.InputDispatchMouseEventTypeMouseMoved
		}
		mouse := proto.InputDispatchMouseEvent{
			Type:       typ,
			X:          ev.X,
			Y:          ev.Y,
			Button:     btn,
			ClickCount: 1,
			Modifiers:  ev.Modifiers,
		}
		_ = mouse.Call(page)

	case "wheel":
		wheel := proto.InputDispatchMouseEvent{
			Type:   proto.InputDispatchMouseEventTypeMouseWheel,
			X:      ev.X,
			Y:      ev.Y,
			DeltaX: ev.DeltaX,
			DeltaY: ev.DeltaY,
		}
		_ = wheel.Call(page)

	case "key":
		typ := proto.InputDispatchKeyEventType(ev.Type)
		if ev.Type == "" {
			typ = proto.InputDispatchKeyEventTypeKeyDown
		}
		keyEv := proto.InputDispatchKeyEvent{
			Type:      typ,
			Modifiers: ev.Modifiers,
			Text:      ev.Text,
			Key:       ev.Key,
			Code:      ev.Code,
		}
		_ = keyEv.Call(page)
		// When client sends a single char event, also emit a char type if text set.
		if ev.Text != "" && (ev.Type == "keyDown" || ev.Type == "") {
			charEv := proto.InputDispatchKeyEvent{
				Type: proto.InputDispatchKeyEventTypeChar,
				Text: ev.Text,
			}
			_ = charEv.Call(page)
		}
	}
}

func (s *liveSession) startScreencast(ctx context.Context, conn *websocket.Conn) error {
	s.mu.Lock()
	page := s.page
	s.mu.Unlock()
	if page == nil {
		return fmt.Errorf("no CDP page")
	}

	castCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancelCast = cancel
	s.mu.Unlock()

	// Enable page domain (required for screencast / capture on some Chrome builds).
	_ = proto.PageEnable{}.Call(page)

	quality := 55
	everyNth := 1
	startReq := proto.PageStartScreencast{
		Format:        proto.PageStartScreencastFormatJpeg,
		Quality:       &quality,
		EveryNthFrame: &everyNth,
	}
	useScreencast := startReq.Call(page) == nil
	if !useScreencast {
		slog.Info("rbi screencast unavailable; using screenshot polling", "session", s.id)
	}

	s.castWG.Add(1)
	go func() {
		defer s.castWG.Done()
		pageCtx := page.Context(castCtx)

		writeFrame := func(jpeg []byte) bool {
			if len(jpeg) == 0 {
				return true
			}
			b64 := base64.StdEncoding.EncodeToString(jpeg)
			payload, _ := json.Marshal(map[string]string{
				"type": "frame",
				"data": b64,
			})
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			s.mu.Lock()
			err := conn.WriteMessage(websocket.TextMessage, payload)
			s.mu.Unlock()
			if err != nil {
				cancel()
				return false
			}
			return true
		}

		if useScreencast {
			wait := pageCtx.EachEvent(func(e *proto.PageScreencastFrame) {
				ack := proto.PageScreencastFrameAck{SessionID: e.SessionID}
				_ = ack.Call(pageCtx)
				// e.Data is already decoded bytes in rod (not base64 string).
				if !writeFrame(e.Data) {
					return
				}
			})
			// Also poll screenshots as backup for headless builds that stop screencast.
			go s.pollScreenshots(castCtx, page, writeFrame)
			wait()
			return
		}

		s.pollScreenshots(castCtx, page, writeFrame)
	}()

	// Push one immediate screenshot so the canvas is not black while screencast warms up.
	go func() {
		time.Sleep(150 * time.Millisecond)
		s.mu.Lock()
		p := s.page
		s.mu.Unlock()
		if p == nil {
			return
		}
		bin, err := proto.PageCaptureScreenshot{
			Format:      proto.PageCaptureScreenshotFormatJpeg,
			Quality:     &quality,
			FromSurface: true,
		}.Call(p)
		if err != nil || bin == nil || len(bin.Data) == 0 {
			return
		}
		b64 := base64.StdEncoding.EncodeToString(bin.Data)
		payload, _ := json.Marshal(map[string]string{"type": "frame", "data": b64})
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		s.mu.Lock()
		_ = conn.WriteMessage(websocket.TextMessage, payload)
		s.mu.Unlock()
	}()

	return nil
}

func (s *liveSession) pollScreenshots(ctx context.Context, page *rod.Page, writeFrame func([]byte) bool) {
	quality := 55
	t := time.NewTicker(200 * time.Millisecond) // ~5 fps
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.stopped.Load() {
				return
			}
			bin, err := proto.PageCaptureScreenshot{
				Format:      proto.PageCaptureScreenshotFormatJpeg,
				Quality:     &quality,
				FromSurface: true,
			}.Call(page.Context(ctx))
			if err != nil || bin == nil {
				continue
			}
			if !writeFrame(bin.Data) {
				return
			}
		}
	}
}

func (s *liveSession) stopScreencast() {
	s.mu.Lock()
	page := s.page
	cancel := s.cancelCast
	s.cancelCast = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if page != nil {
		_ = proto.PageStopScreencast{}.Call(page)
	}
	s.castWG.Wait()
}

// Stop closes CDP and removes the container.
func (s *liveSession) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if !s.stopped.CompareAndSwap(false, true) {
		return nil
	}
	s.stopScreencast()

	s.mu.Lock()
	browser := s.browser
	s.browser = nil
	s.page = nil
	s.mu.Unlock()
	if browser != nil {
		_ = browser.Close()
	}

	var remErr error
	if s.orch != nil && s.orch.Runtime != nil && s.containerID != "" {
		remErr = s.orch.Runtime.Remove(ctx, s.containerID, true)
		if remErr != nil {
			slog.Warn("rbi container remove", "container_id", shortID(s.containerID), "err", remErr)
		} else {
			slog.Info("rbi container removed", "container_id", shortID(s.containerID), "session", s.id)
		}
	}
	if s.orch != nil {
		s.orch.forget(s.id)
	}
	return remErr
}

// newSessionID returns an unguessable session id.
func newSessionID() string {
	return uuid.NewString()
}
