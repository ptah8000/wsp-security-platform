package rbi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
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
	WriteBufferSize: 256 << 10,
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Content-Security-Policy: no origin scripts; only our inline viewer.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src blob: data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	_, _ = w.Write([]byte(viewerHTML(id, o.viewerFlags(id))))
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
		t := time.NewTicker(30 * time.Second)
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

// WriteIsolationHTML writes the isolation landing page that boots the viewer for a new session.
// Used by HandleIsolation — does not re-lookup the session beyond embedding the id.
func WriteIsolationHTML(w http.ResponseWriter, sessionID, targetURL string, flags viewerFlags) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src blob: data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
	w.WriteHeader(http.StatusOK)
	flags.TargetURL = targetURL
	_, _ = w.Write([]byte(viewerHTML(sessionID, flags)))
}

func viewerHTML(sessionID string, flags viewerFlags) string {
	// Relative WS path so MITM / same-origin proxy paths work without knowing the gateway host.
	wsPath := WSPathPrefix + sessionID
	blockCopy := "false"
	blockPaste := "false"
	if flags.BlockCopyFrom {
		blockCopy = "true"
	}
	if flags.BlockCopyTo {
		blockPaste = "true"
	}
	title := "Isolated browser"
	if flags.TargetURL != "" {
		title = "Isolated: " + htmlEscape(flags.TargetURL)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>%s</title>
<style>
  html,body{margin:0;height:100%%;background:#0f1419;color:#e7ecf1;font-family:system-ui,sans-serif;overflow:hidden}
  #bar{display:flex;align-items:center;gap:12px;padding:8px 12px;background:#1a2332;border-bottom:1px solid #2a3544;font-size:13px}
  #bar .badge{background:#c45c26;color:#fff;padding:2px 8px;border-radius:4px;font-weight:600;letter-spacing:.02em}
  #bar .url{opacity:.85;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
  #status{opacity:.7}
  #wrap{position:absolute;inset:40px 0 0 0;display:flex;align-items:center;justify-content:center}
  canvas{max-width:100%%;max-height:100%%;background:#000;cursor:default;box-shadow:0 0 0 1px #2a3544}
  #err{color:#ff8a80;padding:24px;display:none}
</style>
</head>
<body>
<div id="bar">
  <span class="badge">RBI</span>
  <span class="url" title="%s">%s</span>
  <span id="status">connecting…</span>
</div>
<div id="wrap"><canvas id="c" width="1280" height="720"></canvas><div id="err"></div></div>
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
  const ws = new WebSocket(proto + '//' + location.host + wsPath);
  ws.binaryType = 'arraybuffer';

  function showErr(msg){
    errEl.style.display = 'block';
    errEl.textContent = msg;
    status.textContent = 'error';
  }

  ws.onopen = () => { status.textContent = 'isolated session'; };
  ws.onclose = () => { status.textContent = 'session ended'; };
  ws.onerror = () => { showErr('WebSocket error — isolation viewer disconnected'); };

  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch(e) { return; }
    if (msg.type === 'frame' && msg.data) {
      const img = new Image();
      img.onload = () => {
        if (img.width && img.height && (canvas.width !== img.width || canvas.height !== img.height)) {
          canvas.width = img.width;
          canvas.height = img.height;
        }
        ctx.drawImage(img, 0, 0);
      };
      img.src = 'data:image/jpeg;base64,' + msg.data;
    }
  };

  function sendInput(event){
    if (ws.readyState !== 1) return;
    ws.send(JSON.stringify({type:'input', event:event}));
  }

  function relCoords(e){
    const r = canvas.getBoundingClientRect();
    const sx = canvas.width / r.width;
    const sy = canvas.height / r.height;
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
    const p = relCoords(e);
    const button = e.button === 2 ? 'right' : (e.button === 1 ? 'middle' : 'left');
    sendInput({kind:'mouse', type:'mousePressed', x:p.x, y:p.y, button:button, modifiers:mods(e)});
  });
  canvas.addEventListener('mouseup', e => {
    e.preventDefault();
    const p = relCoords(e);
    const button = e.button === 2 ? 'right' : (e.button === 1 ? 'middle' : 'left');
    sendInput({kind:'mouse', type:'mouseReleased', x:p.x, y:p.y, button:button, modifiers:mods(e)});
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
`, title, htmlEscape(flags.TargetURL), htmlEscape(flags.TargetURL), sessionID, wsPath, blockCopy, blockPaste)
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
