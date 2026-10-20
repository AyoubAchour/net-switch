package lifecycle

import (
	"embed"
	"fmt"
	"net/http"
	"strings"
)

//go:embed web/*
var browser embed.FS

func servePair(w http.ResponseWriter, r *http.Request, port int) {
	origin := fmt.Sprintf("127.0.0.1:%d", port)
	if r.Host != origin && r.Host != fmt.Sprintf("localhost:%d", port) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	name, content := "pair.html", "text/html; charset=utf-8"
	if r.URL.Path == "/pair.js" {
		name, content = "pair.js", "text/javascript; charset=utf-8"
	}
	if r.URL.Path == "/pair.css" {
		name, content = "pair.css", "text/css; charset=utf-8"
	}
	b, err := browser.ReadFile("web/" + name)
	if err != nil {
		http.Error(w, "Pairing page unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", content)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}

// ServiceAsset adapts authentication at the serving boundary while leaving the
// frozen Node UI assets byte-identical. M5 will retire the legacy hash handoff.
func ServiceAsset(name string, b []byte) []byte {
	if name != "app.js" {
		return b
	}
	source := string(b)
	start := strings.Index(source, "function readToken() {")
	if start < 0 {
		panic("embedded UI readToken contract changed")
	}
	end := strings.Index(source[start:], "\n}\n")
	if start < 0 || end < 0 {
		panic("embedded UI readToken contract changed")
	}
	source = source[:start] + `function readToken() {
  const current = sessionStorage.getItem('token');
  if (!current) location.replace('/pair');
  return current;
}` + source[start+end+3:]
	old := "    const src = `/api/icon?key=${encodeURIComponent(app.key)}&token=${encodeURIComponent(token)}`;\n    return h('span', { class: 'app-icon has-image' }, h('img', { src, alt: '', width: 18, height: 18 }));"
	next := `    const image = h('img', { alt: '', width: 18, height: 18 });
    fetch('/api/icon?key=' + encodeURIComponent(app.key), { headers: { 'X-Token': token }, credentials: 'omit' })
      .then(response => { if (!response.ok) throw new Error('Icon unavailable'); return response.blob(); })
      .then(blob => { const url = URL.createObjectURL(blob); image.onload = image.onerror = () => URL.revokeObjectURL(url); image.src = url; })
      .catch(() => image.remove());
    return h('span', { class: 'app-icon has-image' }, image);`
	if !strings.Contains(source, old) {
		panic("embedded UI icon authentication contract changed")
	}
	source = strings.Replace(source, old, next, 1)
	source = strings.Replace(source, "response = await fetch(path, {", "response = await fetch(path, {\n      credentials: 'omit',", 1)
	return []byte(source)
}
