/* =====================================================================
   PQC PDF Sign — Liquid Glass UI Kit (runtime)

   Motion systems
     1. Microinteraction + spring physics (press, magnetic pull, counters)
     2. Smooth page transition + shared-element transition (View Transitions)
     3. Particle / data-flow canvas
     4. Mouse parallax (smoothed, depth-layered)
     5. Border glow / rotating border gradient  (CSS, wired by class)
     6. 3D card tilt (spring return + glare)
     7. Gradient flow / mesh gradient          (CSS, wired by class)
     8. Spotlight effect (pointer-tracked light on glass)

   Pure vanilla, no dependencies. Every pointer-driven effect shares one
   rAF ticker so the page stays at 60fps. All of it degrades to nothing
   under prefers-reduced-motion.
   ===================================================================== */
(function () {
  "use strict";
  var PQCUI = (window.PQCUI = window.PQCUI || {});
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var root = document.documentElement;
  // mark that JS is live so the CSS reveal fallback (visible-by-default) lifts
  root.classList.add("pqc-js");

  /* ================= shared rAF ticker ============================= */
  var tickers = [], ticking = false;
  function addTick(fn) {
    tickers.push(fn);
    if (!ticking) { ticking = true; requestAnimationFrame(tick); }
    return fn;
  }
  function removeTick(fn) {
    var i = tickers.indexOf(fn);
    if (i >= 0) tickers.splice(i, 1);
  }
  function tick(now) {
    for (var i = tickers.length - 1; i >= 0; i--) {
      if (tickers[i](now) === false) tickers.splice(i, 1);
    }
    if (tickers.length) requestAnimationFrame(tick);
    else ticking = false;
  }
  function lerp(a, b, t) { return a + (b - a) * t; }

  /* ================= 1. spring engine ============================== */
  // Critically-ish damped spring. onUpdate(value) each frame, onDone at rest.
  function spring(from, to, onUpdate, opts) {
    opts = opts || {};
    var stiffness = opts.stiffness || 180,
        damping = opts.damping || 20,
        mass = opts.mass || 1,
        precision = opts.precision || 0.004;
    if (reduce) { onUpdate(to); if (opts.onDone) opts.onDone(); return function () {}; }
    var x = from, v = opts.velocity || 0, last = 0;
    var fn = addTick(function (now) {
      if (!last) { last = now; return; }
      var dt = Math.min((now - last) / 1000, 1 / 30);
      last = now;
      var f = -stiffness * (x - to) - damping * v;
      v += (f / mass) * dt;
      x += v * dt;
      if (Math.abs(to - x) < precision && Math.abs(v) < precision) {
        x = to; onUpdate(x);
        if (opts.onDone) opts.onDone();
        return false;
      }
      onUpdate(x);
    });
    return function cancel() { removeTick(fn); };
  }
  PQCUI.spring = spring;

  /* ================= theme ========================================= */
  var THEME_KEY = "pqc_theme";
  function systemTheme() {
    return window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  function storedTheme() {
    try { return localStorage.getItem(THEME_KEY) || ""; } catch (e) { return ""; }
  }
  PQCUI.applyTheme = function (t) {
    if (t === "light" || t === "dark") root.setAttribute("data-theme", t);
    else root.removeAttribute("data-theme");
  };
  PQCUI.currentTheme = function () {
    return root.getAttribute("data-theme") || storedTheme() || systemTheme();
  };
  PQCUI.toggleTheme = function () {
    var next = PQCUI.currentTheme() === "dark" ? "light" : "dark";
    try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
    // cross-fade the whole document when the browser can
    PQCUI.transition(function () { PQCUI.applyTheme(next); }, "theme");
    window.dispatchEvent(new CustomEvent("pqc:theme", { detail: next }));
  };
  (function () { var s = storedTheme(); if (s) PQCUI.applyTheme(s); })();

  function wireThemeToggles() {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      if (btn.__wired) return; btn.__wired = 1;
      btn.addEventListener("click", PQCUI.toggleTheme);
    });
  }

  /* ================= 2. page / shared-element transition =========== */
  // Uses the View Transitions API when available (Chrome/Edge/Safari 18):
  // elements carrying view-transition-name morph between states — that is
  // the shared-element part. Everywhere else it just runs the callback and
  // lets the CSS keyframes handle it.
  PQCUI.transition = function (apply, kind) {
    if (reduce || !document.startViewTransition) { apply(); return; }
    root.setAttribute("data-vt", kind || "view");
    var vt = document.startViewTransition(apply);
    vt.finished.then(function () { root.removeAttribute("data-vt"); },
                     function () { root.removeAttribute("data-vt"); });
    return vt;
  };

  /* ================= toast ========================================= */
  var toastEl = null, toastT = null;
  PQCUI.toast = function (text, kind) {
    if (!toastEl) {
      toastEl = document.createElement("div");
      toastEl.className = "pqc-toast";
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = text;
    toastEl.className = "pqc-toast show " + (kind || "");
    clearTimeout(toastT);
    toastT = setTimeout(function () { toastEl.className = "pqc-toast"; }, kind === "err" ? 7000 : 3600);
  };

  /* ================= scroll reveal ================================= */
  function initReveal(scope) {
    var els = (scope || document).querySelectorAll(".reveal:not(.in)");
    if (!("IntersectionObserver" in window) || reduce) {
      els.forEach(function (el) { el.classList.add("in"); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
      });
    }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });
    els.forEach(function (el) { io.observe(el); });
    setTimeout(function () { els.forEach(function (el) { el.classList.add("in"); }); }, 1600);
  }

  /* ================= 6. 3D card tilt (spring return) =============== */
  function wireTilt(scope) {
    if (reduce) return;
    (scope || document).querySelectorAll("[data-tilt]").forEach(function (card) {
      if (card.__tilt) return; card.__tilt = 1;
      var max = parseFloat(card.getAttribute("data-tilt")) || 7;
      var rect = null, tx = 0, ty = 0, cx = 0, cy = 0, sc = 1, want = 1, live = null;

      function paint() {
        card.style.transform =
          "perspective(1000px) rotateX(" + cy.toFixed(2) + "deg) rotateY(" + cx.toFixed(2) + "deg) scale(" + sc.toFixed(4) + ")";
      }
      function run() {
        if (live) return;
        live = addTick(function () {
          cx = lerp(cx, tx, 0.16); cy = lerp(cy, ty, 0.16); sc = lerp(sc, want, 0.14);
          paint();
          if (Math.abs(cx - tx) < 0.01 && Math.abs(cy - ty) < 0.01 && Math.abs(sc - want) < 0.0005) {
            cx = tx; cy = ty; sc = want; paint();
            if (want === 1 && tx === 0 && ty === 0) card.style.transform = "";
            live = null;
            return false;
          }
        });
      }
      card.addEventListener("pointerenter", function () {
        rect = card.getBoundingClientRect(); want = 1.015; run();
      });
      card.addEventListener("pointermove", function (e) {
        if (!rect) rect = card.getBoundingClientRect();
        var px = (e.clientX - rect.left) / rect.width;
        var py = (e.clientY - rect.top) / rect.height;
        ty = (0.5 - py) * max * 2;
        tx = (px - 0.5) * max * 2;
        card.style.setProperty("--mx", (px * 100).toFixed(1) + "%");
        card.style.setProperty("--my", (py * 100).toFixed(1) + "%");
        run();
      });
      card.addEventListener("pointerleave", function () {
        rect = null; tx = 0; ty = 0; want = 1; run();
      });
    });
  }

  /* ================= 8. spotlight on glass surfaces ================ */
  // A soft light follows the pointer across any .spotlight surface. The
  // gradient itself lives in CSS; here we only feed it --sx/--sy.
  function wireSpotlight(scope) {
    if (reduce) return;
    (scope || document).querySelectorAll(".spotlight").forEach(function (el) {
      if (el.__spot) return; el.__spot = 1;
      var rect = null, queued = false;
      el.addEventListener("pointerenter", function () { rect = el.getBoundingClientRect(); });
      el.addEventListener("pointermove", function (e) {
        if (!rect) rect = el.getBoundingClientRect();
        if (queued) return;
        queued = true;
        requestAnimationFrame(function () {
          queued = false;
          el.style.setProperty("--sx", (e.clientX - rect.left).toFixed(0) + "px");
          el.style.setProperty("--sy", (e.clientY - rect.top).toFixed(0) + "px");
        });
      });
      el.addEventListener("pointerleave", function () { rect = null; });
    });
  }

  /* ================= 1b. magnetic buttons (microinteraction) ======= */
  function wireMagnetic(scope) {
    if (reduce) return;
    (scope || document).querySelectorAll(".btn:not([data-no-magnet]), [data-magnetic]").forEach(function (el) {
      if (el.__mag) return; el.__mag = 1;
      var rect = null, tx = 0, ty = 0, cx = 0, cy = 0, live = null;
      var pull = parseFloat(el.getAttribute("data-magnetic")) || 0.22;
      function run() {
        if (live) return;
        live = addTick(function () {
          cx = lerp(cx, tx, 0.18); cy = lerp(cy, ty, 0.18);
          el.style.setProperty("--mag-x", cx.toFixed(2) + "px");
          el.style.setProperty("--mag-y", cy.toFixed(2) + "px");
          if (Math.abs(cx - tx) < 0.05 && Math.abs(cy - ty) < 0.05) {
            el.style.setProperty("--mag-x", tx + "px");
            el.style.setProperty("--mag-y", ty + "px");
            live = null; return false;
          }
        });
      }
      el.addEventListener("pointerenter", function () { rect = el.getBoundingClientRect(); });
      el.addEventListener("pointermove", function (e) {
        if (!rect) rect = el.getBoundingClientRect();
        tx = (e.clientX - (rect.left + rect.width / 2)) * pull;
        ty = (e.clientY - (rect.top + rect.height / 2)) * pull;
        el.style.setProperty("--bx", (e.clientX - rect.left).toFixed(0) + "px");
        el.style.setProperty("--by", (e.clientY - rect.top).toFixed(0) + "px");
        run();
      });
      el.addEventListener("pointerleave", function () { rect = null; tx = 0; ty = 0; run(); });
      // spring press
      el.addEventListener("pointerdown", function () { el.classList.add("is-pressed"); });
      ["pointerup", "pointerleave", "pointercancel"].forEach(function (ev) {
        el.addEventListener(ev, function () { el.classList.remove("is-pressed"); });
      });
    });
  }

  /* ================= ripple ======================================== */
  function spawnRipple(el, e) {
    var rect = el.getBoundingClientRect();
    var d = Math.max(rect.width, rect.height) * 1.1;
    var ink = document.createElement("span");
    ink.className = "ripple-ink";
    ink.style.width = ink.style.height = d + "px";
    ink.style.left = ((e.clientX || rect.left + rect.width / 2) - rect.left - d / 2) + "px";
    ink.style.top = ((e.clientY || rect.top + rect.height / 2) - rect.top - d / 2) + "px";
    el.appendChild(ink);
    setTimeout(function () { ink.remove(); }, 700);
  }
  function wireRipple(scope) {
    (scope || document).querySelectorAll(".btn:not([data-no-ripple]), [data-ripple]").forEach(function (el) {
      if (el.__ripple) return; el.__ripple = 1;
      el.addEventListener("pointerdown", function (e) { spawnRipple(el, e); });
    });
  }

  /* ================= 1c. spring number counters ==================== */
  // Zero markup needed: watch the stat values and spring from the old
  // number to the new one whenever the app writes a fresh figure.
  function fmt(n, decimals) {
    return decimals ? n.toFixed(decimals) : String(Math.round(n));
  }
  function initCounters(scope) {
    (scope || document).querySelectorAll("[data-count], .stat .v").forEach(function (el) {
      if (el.__count) return; el.__count = 1;
      el.__last = null;
      var mo = new MutationObserver(function () {
        if (el.__busy) return;
        var raw = (el.textContent || "").trim();
        var target = parseFloat(raw.replace(/[^\d.-]/g, ""));
        if (isNaN(target)) { el.__last = null; return; }
        if (el.__last === target) return;
        var from = el.__last == null ? 0 : el.__last;
        el.__last = target;
        if (reduce || from === target) return;
        var dec = (raw.split(".")[1] || "").length;
        el.__busy = true;
        spring(from, target, function (v) { el.textContent = fmt(v, dec); }, {
          stiffness: 120, damping: 18, precision: dec ? 0.001 : 0.4,
          onDone: function () { el.textContent = fmt(target, dec); el.__busy = false; }
        });
      });
      mo.observe(el, { childList: true, characterData: true, subtree: true });
    });
  }

  /* ================= 3. particle / data-flow canvas ================ */
  // Drifting nodes joined by faint links, with packets running along the
  // links — a quiet "signatures moving through the network" motif.
  function initFlow() {
    if (reduce) return;
    var cv = document.getElementById("lg-flow");
    if (!cv) return;
    var ctx = cv.getContext("2d");
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var w = 0, h = 0, nodes = [], packets = [], running = true, colour = "120,200,255";

    function readColour() {
      colour = getComputedStyle(root).getPropertyValue("--dust-color").trim() || "120,200,255";
    }
    function mk() {
      return {
        x: Math.random() * w, y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.16,
        vy: -(Math.random() * 0.16 + 0.03),
        r: Math.random() * 1.6 + 0.6,
        tw: Math.random() * Math.PI * 2
      };
    }
    function size() {
      w = window.innerWidth; h = window.innerHeight;
      cv.width = w * dpr; cv.height = h * dpr;
      cv.style.width = w + "px"; cv.style.height = h + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      var n = Math.round((w * h) / 34000);
      n = Math.max(22, Math.min(64, n));
      nodes = [];
      for (var i = 0; i < n; i++) nodes.push(mk());
      packets = [];
    }
    var LINK = 168, LINK2 = LINK * LINK;
    function frame() {
      if (!running) return false;
      ctx.clearRect(0, 0, w, h);

      // nodes
      var i, j, a, b, dx, dy, d2;
      for (i = 0; i < nodes.length; i++) {
        a = nodes[i];
        a.x += a.vx; a.y += a.vy; a.tw += 0.018;
        if (a.y < -20) { a.y = h + 20; a.x = Math.random() * w; }
        if (a.x < -20) a.x = w + 20; else if (a.x > w + 20) a.x = -20;
      }
      // links
      ctx.lineWidth = 1;
      for (i = 0; i < nodes.length; i++) {
        a = nodes[i];
        for (j = i + 1; j < nodes.length; j++) {
          b = nodes[j];
          dx = a.x - b.x; dy = a.y - b.y; d2 = dx * dx + dy * dy;
          if (d2 > LINK2) continue;
          var alpha = (1 - d2 / LINK2) * 0.16;
          ctx.strokeStyle = "rgba(" + colour + "," + alpha.toFixed(3) + ")";
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          // occasionally send a packet down this link
          if (packets.length < 18 && Math.random() < 0.0009) {
            packets.push({ a: a, b: b, t: 0, sp: 0.006 + Math.random() * 0.01 });
          }
        }
      }
      // node dots
      for (i = 0; i < nodes.length; i++) {
        a = nodes[i];
        var tw = 0.55 + Math.sin(a.tw) * 0.45;
        ctx.fillStyle = "rgba(" + colour + "," + (0.34 * tw).toFixed(3) + ")";
        ctx.beginPath(); ctx.arc(a.x, a.y, a.r, 0, Math.PI * 2); ctx.fill();
      }
      // packets travelling along links (the "data flow")
      for (i = packets.length - 1; i >= 0; i--) {
        var p = packets[i];
        p.t += p.sp;
        if (p.t >= 1) { packets.splice(i, 1); continue; }
        var px = p.a.x + (p.b.x - p.a.x) * p.t;
        var py = p.a.y + (p.b.y - p.a.y) * p.t;
        var fade = Math.sin(p.t * Math.PI);
        var g = ctx.createRadialGradient(px, py, 0, px, py, 7);
        g.addColorStop(0, "rgba(" + colour + "," + (0.85 * fade).toFixed(3) + ")");
        g.addColorStop(1, "rgba(" + colour + ",0)");
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(px, py, 7, 0, Math.PI * 2); ctx.fill();
      }
    }
    readColour();
    size();
    window.addEventListener("resize", size, { passive: true });
    window.addEventListener("pqc:theme", function () { setTimeout(readColour, 60); });
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) { running = false; }
      else if (!running) { running = true; addTick(frame); }
    });
    addTick(frame);
  }

  /* ================= 4. mouse parallax (smoothed) ================== */
  function initParallax() {
    if (reduce) return;
    var layers = [].slice.call(document.querySelectorAll("[data-parallax]"));
    if (!layers.length) return;
    var tmx = 0, tmy = 0, mx = 0, my = 0, sy = 0, live = null;

    function run() {
      if (live) return;
      live = addTick(function () {
        mx = lerp(mx, tmx, 0.075); my = lerp(my, tmy, 0.075);
        for (var i = 0; i < layers.length; i++) {
          var el = layers[i];
          var sp = parseFloat(el.getAttribute("data-parallax")) || 0.15;
          var ty = sy * sp * -0.12 + my * sp * 46;
          var tx = mx * sp * 58;
          el.style.transform = "translate3d(" + tx.toFixed(2) + "px," + ty.toFixed(2) + "px,0)";
        }
        if (Math.abs(mx - tmx) < 0.0005 && Math.abs(my - tmy) < 0.0005) { live = null; return false; }
      });
    }
    window.addEventListener("scroll", function () { sy = window.scrollY || 0; run(); }, { passive: true });
    window.addEventListener("pointermove", function (e) {
      tmx = (e.clientX / window.innerWidth) - 0.5;
      tmy = (e.clientY / window.innerHeight) - 0.5;
      run();
    }, { passive: true });
  }

  /* ================= cursor aura (global spotlight) ================ */
  function initCursorAura() {
    if (reduce || !window.matchMedia || !matchMedia("(pointer: fine)").matches) return;
    var aura = document.createElement("div");
    aura.className = "lg-aura";
    aura.setAttribute("aria-hidden", "true");
    document.body.appendChild(aura);
    var tx = -999, ty = -999, x = -999, y = -999, live = null;
    function run() {
      if (live) return;
      live = addTick(function () {
        x = lerp(x, tx, 0.14); y = lerp(y, ty, 0.14);
        aura.style.transform = "translate3d(" + x.toFixed(1) + "px," + y.toFixed(1) + "px,0) translate(-50%,-50%)";
        if (Math.abs(x - tx) < 0.4 && Math.abs(y - ty) < 0.4) { live = null; return false; }
      });
    }
    window.addEventListener("pointermove", function (e) {
      if (x < -900) { x = e.clientX; y = e.clientY; }
      tx = e.clientX; ty = e.clientY;
      aura.classList.add("on");
      run();
    }, { passive: true });
    document.addEventListener("pointerleave", function () { aura.classList.remove("on"); });
  }

  /* ================= public re-scan ================================ */
  PQCUI.refresh = function (scope) {
    initReveal(scope);
    wireTilt(scope);
    wireRipple(scope);
    wireMagnetic(scope);
    wireSpotlight(scope);
    initCounters(scope);
    wireThemeToggles();
  };

  /* ================= boot ========================================== */
  function boot() {
    PQCUI.refresh(document);
    initFlow();
    initParallax();
    initCursorAura();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
