# -*- coding: utf-8 -*-
"""Turn the Console artifact (71fd0fd1) into a bridge-driven theme page, EXACT.

Keeps both of Console's own screens: the main terminal screen and Console's own
settings screen (opened by the gear). Only ids + our 5 theme dots are added;
the visual design is untouched.
"""
import re, os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = r"C:\Users\mumin\.claude\projects\C--Users-mumin-henkerdpi-v2\e7b5044d-28e3-4241-a490-349a8ca8ed60\tool-results\artifact-71fd0fd1-1786548420-5a10.html"
UI = os.path.join(HERE, "ui")

html = open(SRC, encoding="utf-8", errors="replace").read()
design = max((s for s in re.findall(r"<style>(.*?)</style>", html, re.S)
             if "color-scheme:light}body{margin:0" not in s), key=len)
open(os.path.join(UI, "console.css"), "w", encoding="utf-8").write(design)

figs = re.findall(r"<figure.*?</figure>", html, re.S)
strip = lambda f: re.sub(r"<figcaption>.*?</figcaption>", "", f, flags=re.S)
main = strip(next(f for f in figs if "KORUMA" in f))
setg = strip(next(f for f in figs if "AYARLAR" in f))

# ---- hooks: main screen ----
main = main.replace('<div class="win">', '<div class="win" id="win">', 1)
main = main.replace('<button class="gear">', '<button class="gear" id="conGear">', 1)
main = main.replace('<div class="s1">KORUMA AKTİF</div>', '<div class="s1" id="conStatus">KORUMA AKTİF</div>', 1)
main = main.replace('<div class="s2">DPI bypass çalışıyor · 12:30</div>', '<div class="s2" id="conSub">DPI bypass çalışıyor · 12:30</div>', 1)
main = main.replace('<button class="pw stop">', '<button class="pw stop" id="conStop">', 1)
main = main.replace('<div class="seg"><span class="on">Tümü</span><span>Seçili</span></div>',
                    '<div class="seg" id="conSeg"><span class="on">Tümü</span><span>Seçili</span></div>', 1)
main = main.replace('<span><b>1284</b> bypass</span>', '<span><b id="conFBypass">1284</b> bypass</span>', 1)
main = main.replace('<span><b>12:30</b> süre</span>', '<span><b id="conFSure">12:30</b> süre</span>', 1)
main = main.replace('<span>dns <b>1.1.1.1</b></span>', '<span>dns <b id="conFDns">1.1.1.1</b></span>', 1)
main = main.replace('<span>mod <b>TÜMÜ</b></span>', '<span>mod <b id="conFMod">TÜMÜ</b></span>', 1)
main = main.replace('<div class="log"><div class="stream">', '<div class="log"><div class="stream" id="conLog">', 1)
main = main.replace('<span class="srch">🔍</span>',
                    '<span class="srch"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20.5 20.5l-4-4"/></svg></span>', 1)

# ---- hooks: Console's own settings screen ----
setg = setg.replace('<span class="back">‹ AYARLAR</span>', '<span class="back" id="conBack">‹ AYARLAR</span>', 1)
setg = setg.replace('<span class="menu">Cloudflare ▾</span><span class="sw on"></span>',
                    '<span class="menu" id="conSetDns">Cloudflare ▾</span><span class="sw on" id="conSwDns"></span>', 1)
setg = setg.replace('<div class="seg2"><span class="on">Tümü</span><span>Seçili</span></div>',
                    '<div class="seg2" id="conSetSeg"><span class="on">Tümü</span><span>Seçili</span></div>', 1)
setg = setg.replace('Windows ile birlikte</small></div><div class="rr"><span class="sw on"></span>',
                    'Windows ile birlikte</small></div><div class="rr"><span class="sw on" id="conSwAuto"></span>', 1)
setg = setg.replace('ISP reset paketlerini düşür</small></div><div class="rr"><span class="sw"></span>',
                    'ISP reset paketlerini düşür</small></div><div class="rr"><span class="sw" id="conSwRst"></span>', 1)
# theme row: swap the 4 decorative dots for our 5 real themes
dots5 = ('<span class="dots" id="conThemeDots">'
         '<i data-k="mevcut" style="background:#4d8bff"></i>'
         '<i data-k="console" class="sel" style="background:#2DD4BF"></i>'
         '<i data-k="bento" style="background:#38bdf8"></i>'
         '<i data-k="arcade" style="background:#ff3d9a"></i>'
         '<i data-k="combat" style="background:#16a34a"></i></span>')
setg = re.sub(r'<span class="dots">.*?</span>', dots5, setg, count=1, flags=re.S)

WIRE = r"""
const $=id=>document.getElementById(id), p2=n=>String(n).padStart(2,'0'), fmt=n=>Number(n).toLocaleString('tr-TR');
const up=s=>p2(Math.floor(s/60))+":"+p2(s%60);
function setTxt(el,t){for(const n of el.childNodes){if(n.nodeType===3&&n.nodeValue.trim()){n.nodeValue=t;return;}}el.appendChild(document.createTextNode(t));}
function syncSeg(el,allOn){ el.querySelectorAll("span").forEach(sp=>sp.classList.toggle("on",(sp.textContent.trim()==="Tümü")===allOn)); }
function render(s){
  const on=s.running;
  $("win").classList.toggle("off",!on);
  $("conStatus").textContent = on?"KORUMA AKTİF":"KORUMA KAPALI";
  $("conSub").textContent = (on?"DPI bypass çalışıyor · ":"Durduruldu · ")+up(s.uptime);
  setTxt($("conStop"), on?"DURDUR":"BAŞLAT");
  $("conFBypass").textContent = on?fmt(s.bypassed):"0";
  $("conFSure").textContent = on?up(s.uptime):"00:00";
  $("conFDns").textContent = s.dns_ip||"1.1.1.1";
  $("conFMod").textContent = s.mode==="all"?"TÜMÜ":"SEÇİLİ";
  syncSeg($("conSeg"), s.mode==="all");
  syncSeg($("conSetSeg"), s.mode==="all");
  $("conSetDns").textContent = (s.dns_name||"Cloudflare")+" ▾";
  $("conSwDns").classList.toggle("on", !!s.dns_enabled);
  $("conSwAuto").classList.toggle("on", !!s.autostart);
  $("conThemeDots").querySelectorAll("i").forEach(i=>i.classList.toggle("sel", i.dataset.k===s.theme));
}
const P=HDPI.poll(render);
$("conStop").addEventListener("click", async()=>{ await HDPI.toggle(); P.tick(); });
function cycleMode(e){ const sp=e.target.closest("span"); if(!sp)return; HDPI.setMode(sp.textContent.trim()==="Tümü"?"all":"selective").then(P.tick); }
$("conSeg").addEventListener("click", cycleMode);
$("conSetSeg").addEventListener("click", cycleMode);
$("conSetDns").addEventListener("click", async()=>{ const D=HDPI.DNS, s=await HDPI.getState(); const i=D.findIndex(d=>d[1]===s.dns_name); await HDPI.setDns(D[(i+1)%D.length][0]); P.tick(); });
$("conSwDns").addEventListener("click", async()=>{ const s=await HDPI.getState(); await HDPI.setDnsEnabled(!s.dns_enabled); P.tick(); });
$("conSwAuto").addEventListener("click", async()=>{ const s=await HDPI.getState(); await HDPI.setAutostart(!s.autostart); P.tick(); });
$("conSwRst").addEventListener("click", e=>e.currentTarget.classList.toggle("on"));
$("conThemeDots").addEventListener("click", e=>{ const i=e.target.closest("i"); if(i&&i.dataset.k) HDPI.nav(i.dataset.k); });
$("conGear").addEventListener("click", ()=>$("conSettings").classList.add("open"));
$("conBack").addEventListener("click", ()=>$("conSettings").classList.remove("open"));
$("conSettings").addEventListener("click", e=>{ if(e.target.id==="conSettings") e.target.classList.remove("open"); });

// ---- live log: REAL domains from the engine (SNI), newest first ----
function esc(x){ return String(x).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function renderLog(list){
  const el=$("conLog"); if(!el) return;
  if(!list||!list.length){ el.innerHTML='<div class="ln" style="opacity:.45">· trafik bekleniyor ·</div>'; return; }
  el.innerHTML = list.map(function(e){
    var cls = e.act==="bypass"?"ok":(e.act==="refuse"?"rf":"");
    var mk  = e.act==="bypass"?"✓":(e.act==="refuse"?"↺":"·");
    var lab = e.act==="bypass"?"bypass":(e.act==="refuse"?"refuse":"pass");
    return '<div class="ln"><span class="t">'+e.t+'</span><span class="'+cls+'">'+lab+'</span> '+esc(e.host)+'<span class="mk">'+mk+'</span></div>';
  }).join("");
}
async function tickLog(){ if(document.hidden) return; try{ renderLog(await HDPI.getLog(20)); }catch(e){} }
HDPI.whenReady(tickLog); setInterval(tickLog, 1000);
document.addEventListener("visibilitychange", function(){ if(!document.hidden) tickLog(); });
"""

page = ('<!doctype html>\n<html lang="tr"><head>\n<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<title>HenkerDPI</title>\n<link rel="stylesheet" href="console.css">\n<style>\n'
        'html,body{height:100%}\n'
        'body{margin:0;display:grid;place-items:center;width:100vw;height:100vh;overflow:hidden;'
        'box-sizing:border-box;padding-top:34px;'
        'background:var(--page,#08080b);user-select:none;-webkit-user-select:none}\n'
        'figure{width:392px;margin:0}\nfigure figcaption{display:none}\n'
        '.win.off .dot{background:#4e7a68;box-shadow:none}\n'
        '#conSub{white-space:nowrap}\n.stream{animation:none!important}\n'
        '.con-ov{position:fixed;inset:0;z-index:60;background:rgba(2,6,5,.62);display:none;'
        'place-items:center;padding:12px}\n.con-ov.open{display:grid}\n'
        '</style>\n</head><body>\n'
        + main
        + '\n<div class="con-ov" id="conSettings">' + setg + '</div>\n'
        + '<script src="bridge.js"></script>\n<script>\n' + WIRE + '\n</script>\n</body></html>\n')

open(os.path.join(UI, "console.html"), "w", encoding="utf-8").write(page)
print("wrote console.css + console.html")
