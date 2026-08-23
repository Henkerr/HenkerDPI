"""Turn the Pro Fidelity (f91da11f) designs into bridge-driven theme pages.

Extracts the shared design CSS+fonts once to ui/pf.css, then emits ui/<name>.html
for bento + combat with data hooks, a LIVE traffic canvas (bento), and each theme's
OWN in-page, full-window, theme-matched settings screen (no generic drawer).
The approved resting look is unchanged; only ids, the settings overlay, and the
live graph are added.
"""
import re, os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = r"C:\Users\mumin\.claude\projects\C--Users-mumin-henkerdpi-v2\e7b5044d-28e3-4241-a490-349a8ca8ed60\tool-results\artifact-f91da11f-1786550487-5a58.html"
UI = os.path.join(HERE, "ui")

html = open(SRC, encoding="utf-8", errors="replace").read()
ds = next(s for s in re.findall(r"<style>(.*?)</style>", html, re.S) if "@font-face" in s)
open(os.path.join(UI, "pf.css"), "w", encoding="utf-8").write(ds)
figs = re.findall(r"<figure.*?</figure>", html, re.S)
get_fig = lambda kw: re.sub(r"<figcaption>.*?</figcaption>", "", next(x for x in figs if kw in x), flags=re.S)

HEAD = ('<!doctype html>\n<html lang="tr"><head>\n<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<title>HenkerDPI</title>\n<link rel="stylesheet" href="pf.css">\n<style>\n'
        'html,body{height:100%}\n'
        'body{margin:0;display:grid;place-items:center;width:100vw;height:100vh;overflow:hidden;'
        'box-sizing:border-box;padding-top:34px;'
        'background:#08080b;user-select:none;-webkit-user-select:none}\n'
        'figure{width:360px;margin:0}\nfigure figcaption{display:none}\n'
        '.win.off .stat b{opacity:.72}\n{EXTRA}\n</style>\n</head><body>\n')

COMMON = (
    "const $=id=>document.getElementById(id), p2=n=>String(n).padStart(2,'0'),"
    " fmt=n=>Number(n).toLocaleString('tr-TR');\n"
    "function setTxt(el,t){for(const n of el.childNodes){if(n.nodeType===3&&n.nodeValue.trim()){n.nodeValue=t;return;}}el.appendChild(document.createTextNode(t));}\n"
    "function buildTh(el){HDPI.THEMES.forEach(([k,name,col])=>{const b=document.createElement('b');"
    "b.style.background=col;b.textContent=name;b.dataset.k=k;b.addEventListener('click',()=>HDPI.nav(k));el.appendChild(b);});}\n"
)

def page(fig, extra_css, overlay, wiring):
    return (HEAD.replace("{EXTRA}", extra_css) + fig + "\n" + overlay
            + '\n<script src="bridge.js"></script>\n<script>\n' + COMMON + wiring + '\n</script>\n</body></html>\n')

# shared switch look, themed by accent via currentColor swaps per theme
SWATCH_CSS = (
    "{P} b{aspect-ratio:1;border-radius:10px;cursor:pointer;border:2px solid transparent;display:grid;"
    "place-items:center;font-size:8px;font-weight:700;color:#fff;text-align:center;line-height:1;"
    "text-shadow:0 1px 2px rgba(0,0,0,.55)}\n")

# ============================================================ BENTO
b = get_fig("Bento")
b = b.replace('<div class="win">', '<div class="win" id="win">', 1)
b = b.replace('<button class="ibtn">', '<button class="ibtn" id="gear">', 1)
b = b.replace('<b>Korumalı</b>', '<b id="bStatus">Korumalı</b>', 1)
b = b.replace('<button class="pbtn">', '<button class="pbtn" id="pbtn">', 1)
b = b.replace('<div class="num">1284</div>', '<div class="num" id="numBypass">0</div>', 1)
b = b.replace('<div class="num">12:30</div>', '<div class="num" id="numSure">&mdash;</div>', 1)
b = b.replace('<div class="chip">', '<div class="chip" id="modeChip">', 1)
b = b.replace('<div class="dns">', '<div class="dns" id="dnsVal">', 1)
b = re.sub(r'<div class="spark">.*?</div>', '<div class="spark"><canvas id="spark"></canvas></div>', b, count=1, flags=re.S)

BENTO_CSS = (
    ".ben .win.off .pbtn{filter:grayscale(.5) brightness(.92)}\n"
    ".ben .spark canvas{width:100%;height:100%;display:block}\n"
    ".bset{position:fixed;inset:0;z-index:50;display:none;background:rgba(6,8,12,.66);"
    "backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px);font-family:'SG',system-ui,sans-serif;padding:14px;place-items:center}\n"
    ".bset.open{display:grid}\n"
    ".bset-card{width:100%;max-width:340px;max-height:94vh;overflow:auto;background:radial-gradient(120% 80% at 50% 0%,#12151d,#0b0d12);"
    "border:1px solid #22252f;border-radius:16px;padding:16px;box-shadow:0 24px 60px rgba(0,0,0,.6)}\n"
    ".bset-hd{display:flex;justify-content:space-between;align-items:center;font-size:16px;font-weight:600;color:#f0f2f7}\n"
    ".bset-hd .x{cursor:pointer;color:#9aa0b0;border:1px solid #22252f;background:#141620;border-radius:8px;width:30px;height:30px;display:grid;place-items:center;font-size:13px}\n"
    ".bset-grp{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#7a808f;margin:15px 0 8px}\n"
    ".bset-th{display:grid;grid-template-columns:repeat(5,1fr);gap:7px}\n"
    + SWATCH_CSS.replace("{P}", ".bset-th")
    + ".bset-th b.on{border-color:#f0f2f7;box-shadow:0 0 0 2px rgba(56,189,248,.3)}\n"
    ".bset-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 0;border-top:1px solid #191c24}\n"
    ".bset-row .bl{font-size:13px;font-weight:600;color:#e7ebf2}\n"
    ".bset-row .bl small{display:block;font-size:11px;color:#7a808f;font-weight:400;margin-top:1px}\n"
    ".bset .chip{margin-top:0}\n.bset .chip span{padding:5px 11px}\n.bset .dns{margin-top:0;cursor:pointer}\n"
    ".bsw{width:42px;height:24px;border-radius:99px;background:#23262f;position:relative;cursor:pointer;flex:none;transition:.15s}\n"
    ".bsw.on{background:#38bdf8}\n"
    ".bsw::after{content:'';position:absolute;top:3px;left:3px;width:18px;height:18px;border-radius:50%;background:#fff;transition:.15s}\n"
    ".bsw.on::after{transform:translateX(18px)}\n")

BENTO_OVERLAY = (
    '<div class="bset" id="bset"><div class="bset-card">'
    '<div class="bset-hd"><span>Ayarlar</span><button class="x" id="bsetClose">&times;</button></div>'
    '<div class="bset-grp">Tema</div><div class="bset-th" id="bTh"></div>'
    '<div class="bset-grp">Ağ</div>'
    '<div class="bset-row"><div class="bl">Bypass Modu<small id="bModeSub">Tüm siteler</small></div>'
    '<div class="chip" id="bMode"><span class="on">Tümü</span><span>Seçili</span></div></div>'
    '<div class="bset-row"><div class="bl">DNS<small>Güvenli çözümleyici</small></div><div class="dns" id="bDns">Cloudflare</div></div>'
    '<div class="bset-row"><div class="bl">Güvenli DNS<small>Şifreli DNS</small></div><div class="bsw" id="bSwDns"></div></div>'
    '<div class="bset-grp">Sistem</div>'
    '<div class="bset-row"><div class="bl">Açılışta başlat<small>Windows ile</small></div><div class="bsw" id="bSwAuto"></div></div>'
    '</div></div>')

BENTO_WIRE = r"""
const graph=HDPI.makeGraph($("spark"), "#38bdf8", "56,189,248");
let lastTot=0;
buildTh($("bTh"));
function render(s){
  const on=s.running, win=$("win"); win.classList.toggle("off",!on);
  $("bStatus").textContent = on?"Korumalı":"Kapalı";
  setTxt($("pbtn"), on?"Korumayı Durdur":"Korumayı Başlat");
  $("numBypass").textContent = on?fmt(s.bypassed):"0";
  $("numSure").textContent = on?(p2(Math.floor(s.uptime/60))+":"+p2(s.uptime%60)):"\u2014";
  $("modeChip").querySelectorAll("span").forEach(sp=>sp.classList.toggle("on",(sp.textContent.trim()==="Tümü")===(s.mode==="all")));
  setTxt($("dnsVal"), s.dns_name||"Cloudflare");
  let rate=0; if(on){ const tot=(s.bypassed||0)+(s.passed||0); rate=Math.max(0,tot-lastTot); lastTot=tot; } else lastTot=0;
  graph.sample(on?rate:0);
  // settings mirror
  $("bTh").querySelectorAll("b").forEach(b=>b.classList.toggle("on",b.dataset.k===s.theme));
  $("bMode").querySelectorAll("span").forEach(sp=>sp.classList.toggle("on",(sp.textContent.trim()==="Tümü")===(s.mode==="all")));
  $("bModeSub").textContent = s.mode==="all"?"Tüm siteler":"Seçili kategoriler";
  setTxt($("bDns"), s.dns_name||"Cloudflare");
  $("bSwDns").classList.toggle("on",!!s.dns_enabled);
  $("bSwAuto").classList.toggle("on",!!s.autostart);
}
const P=HDPI.poll(render);
const cycleMode=async e=>{ const sp=e.target.closest("span"); if(!sp)return; await HDPI.setMode(sp.textContent.trim()==="Tümü"?"all":"selective"); P.tick(); };
$("pbtn").addEventListener("click", async()=>{ await HDPI.toggle(); P.tick(); });
$("modeChip").addEventListener("click", cycleMode);
$("bMode").addEventListener("click", cycleMode);
$("dnsVal").addEventListener("click", async()=>{ const D=HDPI.DNS,s=await HDPI.getState(); const i=D.findIndex(d=>d[1]===s.dns_name); await HDPI.setDns(D[(i+1)%D.length][0]); P.tick(); });
$("bDns").addEventListener("click", async()=>{ const D=HDPI.DNS,s=await HDPI.getState(); const i=D.findIndex(d=>d[1]===s.dns_name); await HDPI.setDns(D[(i+1)%D.length][0]); P.tick(); });
$("bSwDns").addEventListener("click", async()=>{ const s=await HDPI.getState(); await HDPI.setDnsEnabled(!s.dns_enabled); P.tick(); });
$("bSwAuto").addEventListener("click", async()=>{ const s=await HDPI.getState(); await HDPI.setAutostart(!s.autostart); P.tick(); });
$("gear").addEventListener("click", ()=>{ $("bset").classList.add("open"); });
$("bsetClose").addEventListener("click", ()=>$("bset").classList.remove("open"));
$("bset").addEventListener("click", e=>{ if(e.target.id==="bset") e.target.classList.remove("open"); });
"""
open(os.path.join(UI, "bento.html"), "w", encoding="utf-8").write(page(b, BENTO_CSS, BENTO_OVERLAY, BENTO_WIRE))

# ============================================================ COMBAT
c = get_fig("Combat")
c = c.replace('<div class="win">', '<div class="win" id="win">', 1)
c = c.replace('<button class="ibtn">', '<button class="ibtn" id="gear">', 1)
c = c.replace('<div class="gt">GUARDIAN · TAM GÜÇ</div>', '<div class="gt" id="gtLabel">GUARDIAN · TAM GÜÇ</div>', 1)
c = c.replace('<div class="combo">1284</div>', '<div class="combo" id="numCombo">0</div>', 1)
c = c.replace('<button class="stop">', '<button class="stop" id="stopBtn">', 1)

COMBAT_CSS = (
    ".cmb .win.off .mid .shl{filter:grayscale(.6) brightness(.85)}\n"
    ".cset{position:fixed;inset:0;z-index:50;display:none;background:rgba(10,6,8,.7);"
    "backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px);font-family:'RJ',system-ui,sans-serif;padding:14px;place-items:center}\n"
    ".cset.open{display:grid}\n"
    ".cset-card{width:100%;max-width:340px;max-height:94vh;overflow:auto;background:radial-gradient(90% 60% at 50% 0%,#1c0c11,#0a0608);"
    "border:1px solid #43141b;border-radius:14px;padding:16px;box-shadow:0 24px 60px rgba(0,0,0,.6)}\n"
    ".cset-hd{display:flex;justify-content:space-between;align-items:center;font-family:'OR';font-weight:700;font-size:13px;letter-spacing:.06em;color:#f2e6e8}\n"
    ".cset-hd .x{cursor:pointer;color:#c9a6ab;border:1px solid #3a2a2d;background:#180d10;border-radius:8px;width:30px;height:30px;display:grid;place-items:center;font-size:13px}\n"
    ".cset-grp{font-family:'OR';font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:#ff8a97;margin:15px 0 8px}\n"
    ".cset-th{display:grid;grid-template-columns:repeat(5,1fr);gap:7px}\n"
    + SWATCH_CSS.replace("{P}", ".cset-th").replace("border-radius:10px", "border-radius:8px")
    + ".cset-th b.on{border-color:#4ADE80;box-shadow:0 0 10px rgba(74,222,128,.45)}\n"
    ".cset-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:11px 0;border-top:1px solid #2a1216}\n"
    ".cset-row .cl{font-family:'OR';font-size:12px;color:#f2e6e8}\n"
    ".cset-row .cl small{display:block;font-family:'RJ';font-size:11px;color:#a97b82;font-weight:400;margin-top:2px}\n"
    ".cseg{display:inline-flex;gap:3px;background:#180d10;border:1px solid #3a2a2d;border-radius:8px;padding:3px}\n"
    ".cseg span{font-family:'OR';font-size:11px;padding:5px 10px;border-radius:6px;color:#c9a6ab;font-weight:700;cursor:pointer}\n"
    ".cseg .on{background:#4ADE80;color:#0a0608}\n"
    ".cmenu{font-family:'OR';color:#4ADE80;font-size:13px;cursor:pointer}\n"
    ".csw{width:42px;height:24px;border-radius:99px;background:#2a1216;border:1px solid #43141b;position:relative;cursor:pointer;flex:none;transition:.15s}\n"
    ".csw.on{background:#4ADE80;border-color:#4ADE80}\n"
    ".csw::after{content:'';position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:#f2e6e8;transition:.15s}\n"
    ".csw.on::after{transform:translateX(18px);background:#0a0608}\n")

COMBAT_OVERLAY = (
    '<div class="cset" id="cset"><div class="cset-card">'
    '<div class="cset-hd"><span>AYARLAR</span><button class="x" id="csetClose">&times;</button></div>'
    '<div class="cset-grp">Tema</div><div class="cset-th" id="cTh"></div>'
    '<div class="cset-grp">Ağ</div>'
    '<div class="cset-row"><div class="cl">Bypass Modu<small id="cModeSub">Tüm siteler</small></div>'
    '<div class="cseg" id="cMode"><span class="on">TÜMÜ</span><span>ÖZEL</span></div></div>'
    '<div class="cset-row"><div class="cl">DNS<small>Güvenli çözümleyici</small></div><div class="cmenu" id="cDns">CLOUDFLARE</div></div>'
    '<div class="cset-row"><div class="cl">Güvenli DNS<small>Şifreli DNS</small></div><div class="csw" id="cSwDns"></div></div>'
    '<div class="cset-grp">Sistem</div>'
    '<div class="cset-row"><div class="cl">Açılışta başlat<small>Windows ile</small></div><div class="csw" id="cSwAuto"></div></div>'
    '</div></div>')

COMBAT_WIRE = r"""
buildTh($("cTh"));
function render(s){
  const on=s.running; $("win").classList.toggle("off",!on);
  $("gtLabel").textContent = on ? "GUARDIAN · TAM GÜÇ" : "GUARDIAN · BEKLEMEDE";
  $("numCombo").textContent = on ? fmt(s.bypassed) : "0";
  setTxt($("stopBtn"), on ? "Geri Çekil" : "Devreye Al");
  $("cTh").querySelectorAll("b").forEach(b=>b.classList.toggle("on",b.dataset.k===s.theme));
  $("cMode").querySelectorAll("span").forEach(sp=>sp.classList.toggle("on",(sp.textContent.trim()==="TÜMÜ")===(s.mode==="all")));
  $("cModeSub").textContent = s.mode==="all"?"Tüm siteler":"Seçili kategoriler";
  $("cDns").textContent = (s.dns_name||"Cloudflare").toUpperCase();
  $("cSwDns").classList.toggle("on",!!s.dns_enabled);
  $("cSwAuto").classList.toggle("on",!!s.autostart);
}
const P=HDPI.poll(render);
$("stopBtn").addEventListener("click", async()=>{ await HDPI.toggle(); P.tick(); });
$("cMode").addEventListener("click", async e=>{ const sp=e.target.closest("span"); if(!sp)return; await HDPI.setMode(sp.textContent.trim()==="TÜMÜ"?"all":"selective"); P.tick(); });
$("cDns").addEventListener("click", async()=>{ const D=HDPI.DNS,s=await HDPI.getState(); const i=D.findIndex(d=>d[1].toUpperCase()===$("cDns").textContent.trim()); await HDPI.setDns(D[(i+1)%D.length][0]); P.tick(); });
$("cSwDns").addEventListener("click", async()=>{ const s=await HDPI.getState(); await HDPI.setDnsEnabled(!s.dns_enabled); P.tick(); });
$("cSwAuto").addEventListener("click", async()=>{ const s=await HDPI.getState(); await HDPI.setAutostart(!s.autostart); P.tick(); });
$("gear").addEventListener("click", ()=>$("cset").classList.add("open"));
$("csetClose").addEventListener("click", ()=>$("cset").classList.remove("open"));
$("cset").addEventListener("click", e=>{ if(e.target.id==="cset") e.target.classList.remove("open"); });
"""
open(os.path.join(UI, "combat.html"), "w", encoding="utf-8").write(page(c, COMBAT_CSS, COMBAT_OVERLAY, COMBAT_WIRE))

print("wrote pf.css + bento.html (live graph + own settings) + combat.html (own settings)")
