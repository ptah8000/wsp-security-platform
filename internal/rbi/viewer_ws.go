package rbi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// PathPrefix is the URL prefix for RBI control routes on the proxy/MITM path.
	PathPrefix = "/rbi/"
	// SessionPathPrefix serves viewer HTML: /rbi/session/{id}
	SessionPathPrefix = "/rbi/session/"
	// WSPathPrefix upgrades to viewer WebSocket: /rbi/ws/{id}
	WSPathPrefix = "/rbi/ws/"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  16 << 10,
	WriteBufferSize: 512 << 10,
	// Viewer is served under arbitrary isolated origins (MITM); accept all.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// IsControlPath reports whether path is an RBI viewer/session control route.
func IsControlPath(path string) bool {
	return strings.HasPrefix(path, PathPrefix)
}

// ServeRBIPath serves /rbi/session/{id} (HTML) and /rbi/ws/{id} (WebSocket).
// Returns true if the request was handled as an RBI control path.
func (o *Orchestrator) ServeRBIPath(w http.ResponseWriter, req *http.Request) bool {
	if o == nil || req == nil || req.URL == nil {
		return false
	}
	path := req.URL.Path
	switch {
	case strings.HasPrefix(path, WSPathPrefix):
		id := strings.TrimPrefix(path, WSPathPrefix)
		id = strings.Trim(id, "/")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "invalid session id", http.StatusBadRequest)
			return true
		}
		o.serveWS(w, req, id)
		return true
	case strings.HasPrefix(path, SessionPathPrefix):
		id := strings.TrimPrefix(path, SessionPathPrefix)
		id = strings.Trim(id, "/")
		if id == "" || strings.Contains(id, "/") {
			http.Error(w, "invalid session id", http.StatusBadRequest)
			return true
		}
		o.serveViewerHTML(w, req, id)
		return true
	default:
		if strings.HasPrefix(path, PathPrefix) {
			http.NotFound(w, req)
			return true
		}
		return false
	}
}

func (o *Orchestrator) serveViewerHTML(w http.ResponseWriter, req *http.Request, id string) {
	sess, ok := o.Get(id)
	if !ok {
		http.Error(w, "RBI session not found or expired", http.StatusNotFound)
		return
	}
	_ = sess
	flags := o.viewerFlags(id)
	body := []byte(viewerHTML(id, flags))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Seamless: full-screen viewer; allow WS + data images only.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type viewerFlags struct {
	BlockCopyFrom bool
	BlockCopyTo   bool
	TargetURL     string
}

func (o *Orchestrator) viewerFlags(id string) viewerFlags {
	o.mu.RLock()
	defer o.mu.RUnlock()
	s, ok := o.sessions[id]
	if !ok || s == nil {
		return viewerFlags{}
	}
	return viewerFlags{
		BlockCopyFrom: s.opts.BlockCopyFrom,
		BlockCopyTo:   s.opts.BlockCopyTo,
		TargetURL:     s.targetURL,
	}
}

func (o *Orchestrator) serveWS(w http.ResponseWriter, req *http.Request, id string) {
	sess, ok := o.Get(id)
	if !ok {
		http.Error(w, "RBI session not found or expired", http.StatusNotFound)
		return
	}
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		slog.Warn("rbi websocket upgrade", "session", id, "err", err)
		return
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(o.idleTimeout()))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(o.idleTimeout()))
		return nil
	})

	// Periodic pings to detect dead clients.
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(20 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}()

	err = sess.Attach(conn)
	close(done)
	if err != nil {
		slog.Debug("rbi viewer attach ended", "session", id, "err", err)
	}

	// Tear down session when viewer disconnects (one-shot v1 model).
	stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := o.Stop(stopCtx, id); err != nil {
		slog.Debug("rbi stop after viewer close", "session", id, "err", err)
	}
}

// WriteIsolationHTML writes a seamless full-screen isolation viewer (same URL bar / origin).
// Used by HandleIsolation under MITM so the user is not redirected away from the site host.
func WriteIsolationHTML(w http.ResponseWriter, sessionID, targetURL string, flags viewerFlags) {
	if w == nil {
		return
	}
	flags.TargetURL = targetURL
	body := []byte(viewerHTML(sessionID, flags))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Do not advertise isolation; keep UI chrome minimal.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	// Keep-alive safe: explicit length so the browser runs scripts immediately.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// WriteIsolationRedirect is retained for optional admin-plane handoff (not used by default).
func WriteIsolationRedirect(w http.ResponseWriter, viewerURL, targetURL string) {
	if w == nil {
		return
	}
	w.Header().Set("Location", viewerURL)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")
	w.WriteHeader(http.StatusFound)
	body := fmt.Sprintf(
		`<!DOCTYPE html><html><head><meta charset="utf-8"/><meta http-equiv="refresh" content="0;url=%s"/><title></title></head><body></body></html>`,
		htmlEscape(viewerURL),
	)
	_, _ = w.Write([]byte(body))
}

func viewerHTML(sessionID string, flags viewerFlags) string {
	// Relative WS path so MITM same-origin works without leaving the site host.
	wsPath := WSPathPrefix + sessionID
	blockCopy := "false"
	blockPaste := "false"
	if flags.BlockCopyFrom {
		blockCopy = "true"
	}
	if flags.BlockCopyTo {
		blockPaste = "true"
	}
	// Seamless: no “RBI” branding, full-viewport canvas, subtle loading status only.
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>%s</title>
<style>
  html,body{margin:0;height:100%%;background:#111;overflow:hidden;font-family:system-ui,sans-serif}
  #wrap{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:#111}
  canvas{max-width:100%%;max-height:100%%;background:#111;cursor:default;outline:none}
  #status{position:fixed;left:12px;bottom:10px;color:rgba(255,255,255,.45);font-size:12px;pointer-events:none;z-index:2}
  #err{position:fixed;inset:0;display:none;align-items:center;justify-content:center;color:#ff8a80;background:#111;padding:24px;text-align:center;z-index:3}
</style>
</head>
<body>
<div id="wrap"><canvas id="c" width="1280" height="720" tabindex="0"></canvas></div>
<div id="status">Loading…</div>
<div id="err"></div>
<script>
(function(){
  const sessionId = %q;
  const wsPath = %q;
  const blockCopy = %s;
  const blockPaste = %s;
  const canvas = document.getElementById('c');
  const ctx = canvas.getContext('2d');
  const status = document.getElementById('status');
  const errEl = document.getElementById('err');
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  let ws;
  let frames = 0;
  try {
    ws = new WebSocket(proto + '//' + location.host + wsPath);
  } catch (e) {
    showErr('Unable to open secure display channel');
    return;
  }
  ws.binaryType = 'arraybuffer';

  function showErr(msg){
    errEl.style.display = 'flex';
    errEl.textContent = msg;
    status.textContent = '';
  }

  ws.onopen = () => {
    status.textContent = '';
    canvas.focus();
    // Request first frame
    try { ws.send(JSON.stringify({type:'ping'})); } catch(e) {}
  };
  ws.onclose = () => { if (frames === 0) showErr('Secure session ended before content loaded'); else status.textContent = ''; };
  ws.onerror = () => { if (frames === 0) showErr('Secure session connection failed'); };

  let drawing = false;
  let pending = null;
  function paint(dataUrl){
    pending = dataUrl;
    if (drawing) return;
    drawing = true;
    const img = new Image();
    img.onload = () => {
      if (img.width && img.height && (canvas.width !== img.width || canvas.height !== img.height)) {
        canvas.width = img.width;
        canvas.height = img.height;
      }
      ctx.drawImage(img, 0, 0);
      frames++;
      if (frames === 1) status.textContent = '';
      drawing = false;
      if (pending && pending !== dataUrl) {
        const n = pending; pending = null; paint(n);
      } else {
        pending = null;
      }
    };
    img.onerror = () => { drawing = false; };
    img.src = dataUrl;
  }

  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch(e) { return; }
    if (msg.type === 'frame' && msg.data) {
      paint('data:image/jpeg;base64,' + msg.data);
    } else if (msg.type === 'error' && msg.message) {
      showErr(msg.message);
    }
  };

  function sendInput(event){
    if (!ws || ws.readyState !== 1) return;
    ws.send(JSON.stringify({type:'input', event:event}));
  }

  function relCoords(e){
    const r = canvas.getBoundingClientRect();
    const sx = canvas.width / Math.max(r.width, 1);
    const sy = canvas.height / Math.max(r.height, 1);
    return { x: (e.clientX - r.left) * sx, y: (e.clientY - r.top) * sy };
  }

  function mods(e){
    let m = 0;
    if (e.altKey) m |= 1;
    if (e.ctrlKey) m |= 2;
    if (e.metaKey) m |= 4;
    if (e.shiftKey) m |= 8;
    return m;
  }

  canvas.addEventListener('mousemove', e => {
    const p = relCoords(e);
    sendInput({kind:'mouse', type:'mouseMoved', x:p.x, y:p.y, modifiers:mods(e)});
  });
  canvas.addEventListener('mousedown', e => {
    e.preventDefault();
    canvas.focus();
    const p = relCoords(e);
    const button = e.button === 2 ? 'right' : (e.button === 1 ? 'middle' : 'left');
    sendInput({kind:'mouse', type:'mousePressed', x:p.x, y:p.y, button:button, clickCount:1, modifiers:mods(e)});
  });
  canvas.addEventListener('mouseup', e => {
    e.preventDefault();
    const p = relCoords(e);
    const button = e.button === 2 ? 'right' : (e.button === 1 ? 'middle' : 'left');
    sendInput({kind:'mouse', type:'mouseReleased', x:p.x, y:p.y, button:button, clickCount:1, modifiers:mods(e)});
  });
  canvas.addEventListener('wheel', e => {
    e.preventDefault();
    const p = relCoords(e);
    sendInput({kind:'wheel', type:'mouseWheel', x:p.x, y:p.y, deltaX:e.deltaX, deltaY:e.deltaY, modifiers:mods(e)});
  }, {passive:false});
  canvas.addEventListener('contextmenu', e => e.preventDefault());

  window.addEventListener('keydown', e => {
    if (blockPaste && (e.key === 'v' || e.key === 'V') && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      return;
    }
    if (blockCopy && (e.key === 'c' || e.key === 'C' || e.key === 'x' || e.key === 'X') && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      return;
    }
    sendInput({kind:'key', type:'keyDown', key:e.key, code:e.code, text:e.key.length===1?e.key:'', modifiers:mods(e)});
  });
  window.addEventListener('keyup', e => {
    sendInput({kind:'key', type:'keyUp', key:e.key, code:e.code, modifiers:mods(e)});
  });

  if (blockCopy || blockPaste) {
    document.addEventListener('copy', e => { if (blockCopy) e.preventDefault(); }, true);
    document.addEventListener('cut', e => { if (blockCopy) e.preventDefault(); }, true);
    document.addEventListener('paste', e => { if (blockPaste) e.preventDefault(); }, true);
  }
})();
</script>
</body>
</html>
`, htmlEscape(displayTitle(flags.TargetURL)), sessionID, wsPath, blockCopy, blockPaste)
}

func displayTitle(target string) string {
	if target == "" {
		return "Secure session"
	}
	// Keep the browser tab title looking like the real site (path/host only).
	return htmlEscape(target)
}

func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
