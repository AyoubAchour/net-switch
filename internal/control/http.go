package control

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	assets "github.com/AyoubAchour/net-switch"
	"github.com/AyoubAchour/net-switch/internal/apps"
	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

type ClientError struct{ Message string }

func (e *ClientError) Error() string { return e.Message }
func bad(message string) error       { return &ClientError{message} }

type HTTP struct {
	Core  *Core
	Port  int
	Token string
	Quit  func()
}

func (h *HTTP) sameToken(s string) bool {
	return len(s) == len(h.Token) && subtle.ConstantTimeCompare([]byte(s), []byte(h.Token)) == 1
}
func sendJSON(w http.ResponseWriter, status int, v any) {
	b, err := js.Marshal(v)
	if err != nil {
		status = 500
		b = []byte(`{"error":"Something went wrong. Try again."}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
func (h *HTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A panic may interrupt a routing transaction while holding state locks.
	// Log it and stop routing through the fatal crash net instead of letting
	// net/http recover and keep serving a possibly inconsistent controller.
	// Ordinary returned errors still use the legacy HTTP error responses.
	defer h.Core.op.Crash.Recover("HTTP request")
	allowed := func(host string) bool {
		return host == "127.0.0.1:"+strconv.Itoa(h.Port) || host == "localhost:"+strconv.Itoa(h.Port)
	}
	if !allowed(r.Host) {
		sendJSON(w, 403, map[string]any{"error": "Forbidden"})
		return
	}
	if origin := r.Header.Get("Origin"); r.Method != "GET" && origin != "" && (!strings.HasPrefix(origin, "http://") || !allowed(strings.TrimPrefix(origin, "http://"))) {
		sendJSON(w, 403, map[string]any{"error": "Forbidden"})
		return
	}
	path := r.URL.Path
	if path == "/api/icon" {
		var icon []byte
		if h.sameToken(r.URL.Query().Get("token")) {
			h.Core.mu.Lock()
			info := h.Core.info[apps.AppKey(r.URL.Query().Get("key"))]
			icon, _ = base64.StdEncoding.DecodeString(js.Text(info["icon"]))
			h.Core.mu.Unlock()
		}
		if len(icon) == 0 {
			sendJSON(w, 404, map[string]any{"error": "Not found"})
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		_, _ = w.Write(icon)
		return
	}
	if strings.HasPrefix(path, "/api/") {
		if !h.sameToken(r.Header.Get("X-Token")) {
			sendJSON(w, 401, map[string]any{"error": "Open Net Switch from its shortcut."})
			return
		}
		if !knownRoute(r.Method, path) {
			sendJSON(w, 404, map[string]any{"error": "Not found"})
			return
		}
		body := map[string]any{}
		if r.Method == "POST" {
			b, err := io.ReadAll(io.LimitReader(r.Body, 65537))
			if err != nil {
				sendJSON(w, 400, map[string]any{"error": "The request could not be read."})
				return
			}
			if len(b) > 65536 {
				sendJSON(w, 400, map[string]any{"error": "Request too large."})
				return
			}
			if len(b) > 0 {
				if !json.Valid(b) {
					sendJSON(w, 400, map[string]any{"error": "The request could not be read."})
					return
				}
				v, err := js.Decode(b)
				if err != nil {
					sendJSON(w, 400, map[string]any{"error": "The request could not be read."})
					return
				}
				if v == nil {
					sendJSON(w, 500, map[string]any{"error": "Something went wrong. Try again."})
					return
				}
				if m := js.Object(v); m != nil {
					body = m
				}
			}
		}
		v, err := h.Core.Action(r.Context(), r.Method, path, body)
		if err != nil {
			status := 500
			message := "Something went wrong. Try again."
			if e, ok := err.(*ClientError); ok {
				status = 400
				message = e.Message
			} else {
				h.Core.log("request failed (%s %s): %v", r.Method, path, err)
			}
			sendJSON(w, status, map[string]any{"error": message})
			return
		}
		sendJSON(w, 200, v)
		if path == "/api/quit" && h.Quit != nil {
			h.Quit()
		}
		return
	}
	files := map[string][2]string{"/": {"index.html", "text/html; charset=utf-8"}, "/app.js": {"app.js", "text/javascript; charset=utf-8"}, "/styles.css": {"styles.css", "text/css; charset=utf-8"}, "/favicon.svg": {"favicon.svg", "image/svg+xml"}}
	f, ok := files[path]
	if !ok || r.Method != "GET" {
		sendJSON(w, 404, map[string]any{"error": "Not found"})
		return
	}
	b, err := assets.UI.ReadFile("ui/" + f[0])
	if err != nil {
		h.Core.log("read embedded UI: %v", err)
		sendJSON(w, 500, map[string]any{"error": "Something went wrong. Try again."})
		return
	}
	w.Header().Set("Content-Type", f[1])
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}
func knownRoute(method, path string) bool {
	if method == "GET" {
		return path == "/api/ping" || path == "/api/state" || path == "/api/installed-apps"
	}
	if method != "POST" {
		return false
	}
	switch path {
	case "/api/routing", "/api/app-line", "/api/lines/add", "/api/lines/remove", "/api/lines/update", "/api/lines/order", "/api/reconnect", "/api/update/check", "/api/update/dismiss", "/api/combine", "/api/settings", "/api/setup/cable-default", "/api/setup/keep-both", "/api/setup/undo", "/api/quit":
		return true
	}
	return false
}
func routeError(method, path string) error {
	return fmt.Errorf("unregistered action %s %s", method, path)
}
