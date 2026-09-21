package api

import (
	"bytes"
	"embed"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

//go:embed assets/ui-kit.css assets/ui-kit.js assets/img
var uiKitFS embed.FS

// mountUIKit registers the shared Liquid Glass stylesheet + runtime + image
// assets on a mux. Both the admin console (Routes) and the public verifier
// (VerifyRoutes) serve them from their own origin so the pages can
// <link>/<script src>/<img src> them.
func (s *Server) mountUIKit(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui-kit.css", uiKitAsset("assets/ui-kit.css", "text/css; charset=utf-8", 300))
	mux.HandleFunc("GET /ui-kit.js", uiKitAsset("assets/ui-kit.js", "text/javascript; charset=utf-8", 300))
	mux.HandleFunc("GET /assets/img/{name}", uiKitImage)
}

func uiKitAsset(name, ctype string, maxAge int) http.HandlerFunc {
	body, _ := uiKitFS.ReadFile(name)
	modtime := time.Now()
	cc := "public, max-age=" + strconv.Itoa(maxAge)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", cc)
		http.ServeContent(w, r, name, modtime, bytes.NewReader(body))
	}
}

var uiKitImgModtime = time.Now()

// uiKitImage serves an embedded background / logo PNG. The set is fixed
// (assets/img/*.png), so a clean basename is all that is accepted.
func uiKitImage(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.PathValue("name"))
	if !strings.HasSuffix(name, ".png") || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	body, err := uiKitFS.ReadFile("assets/img/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, name, uiKitImgModtime, bytes.NewReader(body))
}

// --- shared page chrome ------------------------------------------------

// lgHead is the <link>/<script> pair plus the inline theme-preboot that
// stops a light/dark flash. Placed in every page <head>.
const lgHead = `<link rel="stylesheet" href="/ui-kit.css">
<script>(function(){try{var t=localStorage.getItem("pqc_theme");if(t==="light"||t==="dark")document.documentElement.setAttribute("data-theme",t);}catch(e){}})();</script>`

// lgScripts is placed at the end of <body>.
const lgScripts = `<script src="/ui-kit.js" defer></script>`

// lgBackground is the fixed photographic backdrop (from Assets/) plus a thin
// theme-tinted legibility scrim. The photo itself lives in ui-kit.css as a
// fixed body::before layer that swaps by theme; this element only adds the
// wash + a couple of floating brand-logo accents.
const lgBackground = `<div class="lg-mesh" aria-hidden="true"></div>
<div class="lg-scrim" aria-hidden="true"></div>
<canvas id="lg-flow" aria-hidden="true"></canvas>
<img class="lg-orb lg-orb-a float lt" data-parallax="0.10" src="/assets/img/doc-light.png" alt="" aria-hidden="true">
<img class="lg-orb lg-orb-a float dk" data-parallax="0.10" src="/assets/img/doc-dark.png" alt="" aria-hidden="true">
<img class="lg-orb lg-orb-b float-2 lt" data-parallax="0.16" src="/assets/img/ca-light.png" alt="" aria-hidden="true">
<img class="lg-orb lg-orb-b float-2 dk" data-parallax="0.16" src="/assets/img/ca-dark.png" alt="" aria-hidden="true">`

// lgMark is the brand logo (PNG from Assets/, one per theme; CSS shows one).
const lgMark = `<img class="mark lt" src="/assets/img/logo-light.png" alt="PQC PDF Sign">` +
	`<img class="mark dk" src="/assets/img/logo-dark.png" alt="PQC PDF Sign">`

// lgThemeToggle is the round sun/moon switch. It needs no wiring — ui-kit.js
// binds every [data-theme-toggle].
const lgThemeToggle = `<button class="theme-toggle" type="button" data-theme-toggle aria-label="Ganti tema terang / gelap">
  <svg class="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z"/></svg>
  <svg class="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2v2.5M12 19.5V22M4.2 4.2l1.8 1.8M18 18l1.8 1.8M2 12h2.5M19.5 12H22M4.2 19.8 6 18M18 6l1.8-1.8"/></svg>
</button>`
