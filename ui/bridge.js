/* Shared HenkerDPI web bridge + settings/theme panel.
   Every theme page includes this. Live data comes from the engine via
   window.pywebview.api (real) or a localStorage-backed mock (browser preview).
   The real api is chosen PER CALL, so it works even though pywebview injects
   window.pywebview.api slightly after this script loads. */
(function () {
  "use strict";

  // ---- mock engine for plain-browser preview (persists across navigation) ----
  const mock = (function () {
    const load = () => { try { return JSON.parse(localStorage.getItem("hdpi_mock")) || {}; } catch (e) { return {}; } };
    const save = () => { try { localStorage.setItem("hdpi_mock", JSON.stringify(s)); } catch (e) {} };
    const s = Object.assign({
      running: false, bypassed: 0, passed: 0, started: 0, mode: "all",
      dns: "cloudflare", dns_name: "Cloudflare", dns_ip: "1.1.1.1", dns_enabled: true, autostart: false, theme: "mevcut",
    }, load());
    const NAME = { cloudflare: "Cloudflare", google: "Google", quad9: "Quad9" };
    const IP = { cloudflare: "1.1.1.1", google: "8.8.8.8", quad9: "9.9.9.9" };
    let timer = null, events = [];
    const DOMAINS = ["discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net",
      "youtube.com", "i.ytimg.com", "googlevideo.com", "x.com", "twimg.com", "instagram.com",
      "cdninstagram.com", "whatsapp.net", "open.spotify.com", "reddit.com"];
    // Server IPs for mock "engel" (QUIC refused) events — the real engine logs
    // the destination address of each refused QUIC Initial.
    const IPS = ["162.159.135.234", "142.250.187.14", "31.13.72.36", "104.16.248.249", "35.186.224.25"];
    const stamp = () => { const d = new Date(), p = n => String(n).padStart(2, "0"); return p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds()); };
    const tick = () => {
      s.bypassed += 3 + Math.floor(Math.random() * 11);
      const r = Math.random();
      if (r < 0.28) events.push({ t: stamp(), host: IPS[Math.floor(Math.random() * IPS.length)], act: "block" });
      else events.push({ t: stamp(), host: DOMAINS[Math.floor(Math.random() * DOMAINS.length)], act: r < 0.92 ? "bypass" : "pass" });
      if (events.length > 80) events.shift();
      save();
    };
    if (s.running) timer = setInterval(tick, 850);
    return {
      get_state() { const up = s.running ? Math.floor((Date.now() - s.started) / 1000) : 0; return Promise.resolve(Object.assign({}, s, { uptime: up })); },
      toggle() { s.running = !s.running; if (s.running) { s.started = Date.now(); s.bypassed = 0; timer = setInterval(tick, 850); } else { clearInterval(timer); } save(); return Promise.resolve(); },
      set_mode(m) { s.mode = m; save(); return Promise.resolve(); },
      set_dns(d) { s.dns = d; s.dns_name = NAME[d] || "Cloudflare"; s.dns_ip = IP[d] || "1.1.1.1"; save(); return Promise.resolve(); },
      set_dns_enabled(b) { s.dns_enabled = !!b; save(); return Promise.resolve(); },
      set_autostart(b) { s.autostart = !!b; save(); return Promise.resolve(); },
      set_theme(t) { s.theme = t; save(); return Promise.resolve(); },
      get_log(n) { return Promise.resolve(events.slice(-(n || 20)).reverse()); },
    };
  })();

  // real engine bridge if present, else the mock — resolved at call time
  const T = () => (window.pywebview && window.pywebview.api) ? window.pywebview.api : mock;
  const inWebview = () => typeof window.pywebview !== "undefined";
  function whenReady(cb) {
    if (window.pywebview && window.pywebview.api) return cb();
    if (inWebview()) return window.addEventListener("pywebviewready", cb, { once: true });
    cb(); // plain browser: mock is ready now
  }

  const THEMES = [
    ["mevcut", "Mevcut", "#4d8bff"], ["console", "Console", "#2dd4bf"],
    ["bento", "Bento", "#38bdf8"], ["arcade", "Arcade", "#ff3d9a"], ["combat", "Combat", "#16a34a"],
  ];
  const DNS = [["cloudflare", "Cloudflare"], ["google", "Google"], ["quad9", "Quad9"]];

  const getState = () => Promise.resolve(T().get_state());
  const nav = (theme) => Promise.resolve(T().set_theme(theme)).then(() => { location.href = theme + ".html"; });

  // ---- visibility-aware polling (pauses in tray to save CPU) ----
  function poll(render) {
    let timer = null;
    async function tick() { if (document.hidden) return; try { render(await getState()); } catch (e) {} }
    const start = () => { if (timer) return; whenReady(() => { tick(); timer = setInterval(tick, 1000); }); };
    const stop = () => { clearInterval(timer); timer = null; };
    document.addEventListener("visibilitychange", () => (document.hidden ? stop() : start()));
    start();
    return { start, stop, tick };
  }

  // ---- shared settings + theme panel (injected once; any theme's gear opens it) ----
  let panel = null;
  function buildPanel() {
    const css = `
    .hdpi-ov{position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);display:none;
      font:14px/1.4 "Segoe UI",-apple-system,system-ui,sans-serif;color:#eceef2}
    .hdpi-ov.open{display:block}
    .hdpi-sheet{position:absolute;right:0;top:0;bottom:0;width:min(320px,90vw);background:#14161b;
      border-left:1px solid #2c2f37;padding:16px;overflow:auto;transform:translateX(100%);transition:transform .18s}
    .hdpi-ov.open .hdpi-sheet{transform:none}
    .hdpi-sheet h3{font-size:15px;font-weight:700;display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
    .hdpi-sheet h3 .x{cursor:pointer;color:#9499a6;font-weight:400}
    .hdpi-grp{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#6d7280;margin:16px 0 8px}
    .hdpi-th{display:grid;grid-template-columns:repeat(5,1fr);gap:7px}
    .hdpi-th b{aspect-ratio:1;border-radius:9px;cursor:pointer;border:2px solid transparent;display:grid;
      place-items:center;font-size:8px;font-weight:700;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.6)}
    .hdpi-th b.on{border-color:#fff}
    .hdpi-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-top:1px solid #24262b}
    .hdpi-row .t{font-size:13px;font-weight:600}.hdpi-row small{display:block;font-size:11px;color:#6d7280;font-weight:400}
    .hdpi-pick{background:#0e1014;border:1px solid #24262b;border-radius:8px;padding:8px 11px;cursor:pointer;font-size:13px}
    .hdpi-sw{width:40px;height:23px;border-radius:99px;background:#2c2f37;position:relative;cursor:pointer;flex:none;transition:.15s}
    .hdpi-sw.on{background:#4d8bff}.hdpi-sw::after{content:"";position:absolute;top:3px;left:3px;width:17px;height:17px;border-radius:50%;background:#fff;transition:.15s}
    .hdpi-sw.on::after{transform:translateX(17px)}`;
    const st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);
    const ov = document.createElement("div"); ov.className = "hdpi-ov";
    ov.innerHTML = '<div class="hdpi-sheet"><h3>Ayarlar <span class="x">✕</span></h3>'
      + '<div class="hdpi-grp">Tema</div><div class="hdpi-th" id="hdpiTh"></div>'
      + '<div class="hdpi-grp">Ağ</div>'
      + '<div class="hdpi-row"><div class="t">Bypass Modu<small id="hdpiModeSub"></small></div><div class="hdpi-pick" id="hdpiMode"></div></div>'
      + '<div class="hdpi-row"><div class="t">DNS<small>Güvenli çözümleyici</small></div><div class="hdpi-pick" id="hdpiDns"></div></div>'
      + '<div class="hdpi-row"><div class="t">Güvenli DNS<small>Şifreli DNS</small></div><div class="hdpi-sw" id="hdpiSwDns"></div></div>'
      + '<div class="hdpi-grp">Sistem</div>'
      + '<div class="hdpi-row"><div class="t">Açılışta başlat<small>Windows ile</small></div><div class="hdpi-sw" id="hdpiSwAuto"></div></div></div>';
    document.body.appendChild(ov);
    ov.addEventListener("click", (e) => { if (e.target === ov || e.target.classList.contains("x")) ov.classList.remove("open"); });
    const th = ov.querySelector("#hdpiTh");
    THEMES.forEach(([k, name, col]) => { const b = document.createElement("b"); b.style.background = col; b.textContent = name; b.dataset.k = k;
      b.addEventListener("click", () => nav(k)); th.appendChild(b); });
    ov.querySelector("#hdpiMode").addEventListener("click", async () => { const s = await getState(); await T().set_mode(s.mode === "all" ? "selective" : "all"); syncPanel(); });
    ov.querySelector("#hdpiDns").addEventListener("click", async () => { const s = await getState(); const i = DNS.findIndex(d => d[0] === s.dns); await T().set_dns(DNS[(i + 1) % DNS.length][0]); syncPanel(); });
    ov.querySelector("#hdpiSwDns").addEventListener("click", async (e) => { e.currentTarget.classList.toggle("on"); await T().set_dns_enabled(e.currentTarget.classList.contains("on")); });
    ov.querySelector("#hdpiSwAuto").addEventListener("click", async (e) => { e.currentTarget.classList.toggle("on"); await T().set_autostart(e.currentTarget.classList.contains("on")); });
    return ov;
  }
  async function syncPanel() {
    if (!panel) return; const s = await getState();
    panel.querySelectorAll("#hdpiTh b").forEach(b => b.classList.toggle("on", b.dataset.k === s.theme));
    panel.querySelector("#hdpiMode").textContent = s.mode === "all" ? "Tümü" : "Seçili";
    panel.querySelector("#hdpiModeSub").textContent = s.mode === "all" ? "Tüm siteler" : "Seçili kategoriler";
    panel.querySelector("#hdpiDns").textContent = s.dns_name || "Cloudflare";
    panel.querySelector("#hdpiSwDns").classList.toggle("on", !!s.dns_enabled);
    panel.querySelector("#hdpiSwAuto").classList.toggle("on", !!s.autostart);
  }
  function openSettings() { if (!panel) panel = buildPanel(); syncPanel(); panel.classList.add("open"); }

  // ---- frameless window chrome: custom min/close + drag strip (no OS titlebar) ----
  // Window size per theme (frameless: content == window, no black surround).
  const THEME_SIZE = {
    mevcut: [408, 688], console: [416, 634], bento: [384, 616],
    arcade: [416, 690], combat: [384, 616],
  };
  // ---- live traffic graph, driven by REAL throughput (not a synthetic wave) ----
  // sample(rate) is fed the packets/sec measured each poll; idle => flat, busy => tall.
  function makeGraph(cvs, lineHex, rgb) {
    if (!cvs) return { sample() {} };
    const gx = cvs.getContext("2d"), N = 60, PUSH = 1000;
    let samples = new Array(N + 1).fill(0), peak = 1, lastT = 0;   // one extra point slides in from the right
    const fit = () => { const r = cvs.getBoundingClientRect(); cvs.width = Math.max(120, r.width | 0); cvs.height = Math.max(30, r.height | 0); };
    fit(); window.addEventListener("resize", fit);
    function draw(now) {
      const W = cvs.width, H = cvs.height, st = W / (N - 1), Y = v => H - 4 - v * (H - 9);
      let frac = lastT ? (now - lastT) / PUSH : 1; if (frac > 1) frac = 1; if (frac < 0) frac = 0;
      gx.clearRect(0, 0, W, H);
      const path = () => { for (let i = 0; i <= N; i++) { const x = (i - frac) * st, y = Y(samples[i]); i ? gx.lineTo(x, y) : gx.moveTo(x, y); } };
      gx.beginPath(); path(); gx.lineTo((N - frac) * st, H); gx.lineTo(-frac * st, H); gx.closePath();
      const g = gx.createLinearGradient(0, 0, 0, H); g.addColorStop(0, "rgba(" + rgb + ",.42)"); g.addColorStop(1, "rgba(" + rgb + ",0)");
      gx.fillStyle = g; gx.fill();
      gx.beginPath(); path(); gx.strokeStyle = lineHex; gx.lineWidth = 2; gx.stroke();
      gx.fillStyle = lineHex; gx.beginPath(); gx.arc(Math.min(W - 1, (N - frac) * st), Y(samples[N]), 2.5, 0, 7); gx.fill();
      requestAnimationFrame(draw);
    }
    requestAnimationFrame(draw);
    // one real sample per ~second (auto-scaled to a decaying peak); the draw loop glides between them
    return { sample(rate) { const now = performance.now(); if (now - lastT < PUSH - 80) return; lastT = now;
      rate = Math.max(0, rate || 0); peak = Math.max(rate, peak * 0.9, 1);
      samples.push(Math.min(1, rate / peak)); samples.shift(); } };
  }

  const api = () => (window.pywebview && window.pywebview.api) || null;
  const winMin = () => { const a = api(); if (a && a.win_minimize) a.win_minimize(); };
  const winClose = () => { const a = api(); if (a && a.win_close) a.win_close(); else if (!inWebview()) window.close(); };
  const resizeTo = (w, h) => { const a = api(); if (a && a.win_resize) a.win_resize(w, h); };

  function injectTitlebar() {
    if (document.getElementById("hdpi-tb")) return;
    const css =
      "#hdpi-tb{position:fixed;top:0;left:0;right:0;height:34px;z-index:99990;display:flex;"
      + "align-items:center;justify-content:flex-end;pointer-events:none}"
      + "#hdpi-tb .drag{position:absolute;inset:0;pointer-events:auto}"
      + "#hdpi-tb .btns{position:relative;display:flex;gap:2px;padding-right:7px;pointer-events:auto}"
      + "#hdpi-tb button{width:32px;height:24px;border:none;background:transparent;color:rgba(233,236,242,.5);"
      + "cursor:pointer;border-radius:7px;display:grid;place-items:center;transition:background .12s,color .12s}"
      + "#hdpi-tb button:hover{background:rgba(255,255,255,.13);color:#fff}"
      + "#hdpi-tb button.close:hover{background:#e11d48;color:#fff}"
      + "#hdpi-tb svg{width:13px;height:13px;pointer-events:none}"
      + "#hdpi-tb .logo{position:absolute;left:9px;top:6px;width:20px;height:20px;border-radius:6px;pointer-events:none}";
    const st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);
    const tb = document.createElement("div"); tb.id = "hdpi-tb";
    tb.innerHTML =
      '<div class="drag pywebview-drag-region"></div><img class="logo" src="logo.png" alt=""><div class="btns">'
      + '<button class="min" title="Küçült" aria-label="Küçült"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 12h14"/></svg></button>'
      + '<button class="close" title="Kapat" aria-label="Kapat"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg></button>'
      + '</div>';
    document.body.appendChild(tb);
    tb.querySelector(".min").addEventListener("click", winMin);
    tb.querySelector(".close").addEventListener("click", winClose);
  }
  // Scale a fixed-size card theme (any <figure>) DOWN to fit the window — never overflows,
  // stays pixel-faithful, and is immune to the OS display-scaling (DPI) that shrinks the viewport.
  function fitCard() {
    const fig = document.querySelector("figure");
    if (!fig) return;                       // fill/canvas themes (mevcut, arcade) handle their own size
    fig.style.transform = "none";
    const dw = fig.offsetWidth, dh = fig.offsetHeight;
    if (!dw || !dh) return;
    const availW = Math.max(220, window.innerWidth - 18);
    const availH = Math.max(220, window.innerHeight - 34 - 14);   // 34 = titlebar
    const sc = Math.min(1, availW / dw, availH / dh);
    fig.style.transformOrigin = "center center";
    fig.style.transform = sc < 0.999 ? "scale(" + sc.toFixed(4) + ")" : "none";
  }

  if (document.body) injectTitlebar(); else document.addEventListener("DOMContentLoaded", injectTitlebar);
  if (document.querySelector("figure")) {
    fitCard(); window.addEventListener("resize", fitCard);
    window.addEventListener("load", fitCard); setTimeout(fitCard, 250);
  }
  // size the frameless window to this theme (real webview only; no-op in a browser)
  whenReady(function () { getState().then(function (s) { const z = THEME_SIZE[s && s.theme]; if (z) resizeTo(z[0], z[1]); }).catch(function () {}); });

  window.HDPI = {
    THEMES, DNS, THEME_SIZE, getState, poll, nav, openSettings, whenReady, makeGraph,
    winMin, winClose, resizeTo,
    getLog: (n) => Promise.resolve(T().get_log ? T().get_log(n) : []),
    toggle: () => T().toggle(), setMode: (m) => T().set_mode(m), setDns: (d) => T().set_dns(d),
    setDnsEnabled: (b) => T().set_dns_enabled(b), setAutostart: (b) => T().set_autostart(b),
  };
})();
