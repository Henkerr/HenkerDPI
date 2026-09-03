# -*- coding: utf-8 -*-
"""Generate ui/arcade.html from the arcade GAME master (arcade_game_v2_enhanced.html).

The master is a self-contained mockup: an HTML home + settings + a canvas
Space-Invaders game (5 DPI-themed chapters, boss waves, power-ups). This wires
the home + settings to the REAL engine via bridge.js (replacing the master's
mock controller) and drops the game canvas in untouched. "OYUN MODU" on the home
launches the game; the frame recolours per chapter so game mode reads as distinct.
Re-run after editing arcade_game_v2_enhanced.html.
"""
import re, os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "arcade_game_v2_enhanced.html")
OUT = os.path.join(HERE, "ui", "arcade.html")

src = open(SRC, encoding="utf-8").read()
style = re.search(r"<title>HenkerDPI</title>\s*<style>(.*?)</style>", src, re.S).group(1)
after_style = src.split("</style>", 1)[1]
bodyhtml = after_style.split("<script>", 1)[0]
bodyhtml = bodyhtml[bodyhtml.index('<div class="brand"'):]
game = re.findall(r"<script>(.*?)</script>", after_style, re.S)[0]   # the game engine
assert "spawnWave" in game and "CHAPTERS" in game, "game engine not captured"

# The live-engine controller. Replaces the master's mock: the home DPI orb/stats
# and the settings rows now talk to the engine through bridge.js (window.HDPI).
BRIDGE_SCRIPT = r"""
/* --- live-engine wiring: home + settings talk to the real engine via bridge.js;
       the game canvas is self-contained. Replaces the mock screen controller. --- */
let screen='home';
function showScr(id){for(const s of document.querySelectorAll('.screen'))s.classList.add('hidden');document.getElementById(id).classList.remove('hidden');}
function showHome(){ if(gameActive){gameActive=false;} gameChrome(false); screen='home'; showScr('home'); if(window.P)P.tick(); }
function showSettings(){ screen='settings'; showScr('settings'); }
function showGame(){ screen='game'; showScr('game'); gameActive=true; gameChrome(true); if(typeof startGame==='function')startGame(); }
function exitGame(){ gameActive=false; gameChrome(false); screen='home'; showScr('home'); if(window.P)P.tick(); }
function toggleDpi(){ HDPI.toggle().then(()=>{ if(window.P)P.tick(); }); }
// menu<->game chrome: cyan game-mode frame on entry (syncChrome later paints the chapter colour)
function gameChrome(on){ var app=document.querySelector('.app'); if(app){ app.style.borderColor=on?'#22e3ff':''; app.style.boxShadow=on?'0 30px 90px rgba(0,0,0,.6), 0 0 62px rgba(34,227,255,.4)':''; } var g=document.getElementById('gtag'); if(g&&on)g.textContent='OYUN MODU'; }

// --- home render from live engine state ---
function fmtUp(sec){ return Math.floor(sec/60)+':'+String(sec%60).padStart(2,'0'); }
function renderHome(s){
  const on=!!s.running;
  const orb=document.getElementById('orb'),lbl=document.getElementById('dpiLbl'),btn=document.getElementById('dpiBtn'),t=document.getElementById('stTitle'),d=document.getElementById('stDesc');
  if(orb)orb.classList.toggle('on',on);
  if(t){t.textContent=on?'Koruma Aktif':'Koruma Kapalı';t.style.color=on?'#4ade80':'';}
  if(d)d.textContent=on?'DPI bypass çalışıyor':'Korumayı başlatmak için DPI Başlat';
  if(lbl)lbl.textContent=on?'DPI DURDUR':'DPI BAŞLAT';
  if(btn)btn.className='dpibtn '+(on?'on':'off');
  const by=document.getElementById('bypass');if(by)by.textContent=(s.bypassed||0).toLocaleString('tr');
  const up=document.getElementById('uptime');if(up)up.textContent=on?fmtUp(s.uptime||0):'—';
  const mc=document.querySelector('#home .modechip');if(mc)mc.innerHTML='Mod: <b>'+(s.mode==='all'?'Tümü':'Seçili')+'</b> · DNS: <b>'+(s.dns_name||'Cloudflare')+'</b>';
  syncSettings(s);
}

// --- settings screen wired to the engine (rows are in a fixed order) ---
let _sBound=false;
function bindSettings(){
  if(_sBound)return; _sBound=true;
  const rows=[...document.querySelectorAll('#settings .srow')];
  const dnsSw=rows[0]&&rows[0].querySelector('.sw'); if(dnsSw)dnsSw.addEventListener('click',()=>{dnsSw.classList.toggle('on');HDPI.setDnsEnabled(dnsSw.classList.contains('on'));});
  const dnsMenu=rows[1]&&rows[1].querySelector('.menu'); if(dnsMenu)dnsMenu.addEventListener('click',async()=>{const s=await HDPI.getState();const i=HDPI.DNS.findIndex(x=>x[1]===s.dns_name);await HDPI.setDns(HDPI.DNS[(i+1)%HDPI.DNS.length][0]);if(window.P)P.tick();});
  if(rows[2])rows[2].querySelectorAll('.chips span').forEach(sp=>sp.addEventListener('click',()=>{for(const x of sp.parentNode.children)x.classList.remove('on');sp.classList.add('on');HDPI.setMode(sp.textContent.trim()==='Tümü'?'all':'selective');}));
  const autoSw=rows[3]&&rows[3].querySelector('.sw'); if(autoSw)autoSw.addEventListener('click',()=>{autoSw.classList.toggle('on');HDPI.setAutostart(autoSw.classList.contains('on'));});
  const rstSw=rows[4]&&rows[4].querySelector('.sw'); if(rstSw)rstSw.addEventListener('click',()=>rstSw.classList.toggle('on'));
  const dots=rows[5]?[...rows[5].querySelectorAll('.dots i')]:[];
  dots.forEach((dot,i)=>{const k=HDPI.THEMES[i]&&HDPI.THEMES[i][0];if(dot)dot.addEventListener('click',()=>{if(k&&k!=='arcade')HDPI.nav(k);});});
}
function syncSettings(s){
  bindSettings();
  const rows=[...document.querySelectorAll('#settings .srow')];
  const dnsSw=rows[0]&&rows[0].querySelector('.sw'); if(dnsSw)dnsSw.classList.toggle('on',!!s.dns_enabled);
  const dnsMenu=rows[1]&&rows[1].querySelector('.menu'); if(dnsMenu)dnsMenu.textContent=(s.dns_name||'Cloudflare')+' ▾';
  const dnsSub=rows[1]&&rows[1].querySelector('.l small'); if(dnsSub)dnsSub.textContent=s.dns_ip||'1.1.1.1';
  if(rows[2])rows[2].querySelectorAll('.chips span').forEach(sp=>sp.classList.toggle('on',(sp.textContent.trim()==='Tümü')===(s.mode==='all')));
  const autoSw=rows[3]&&rows[3].querySelector('.sw'); if(autoSw)autoSw.classList.toggle('on',!!s.autostart);
  const dots=rows[5]?[...rows[5].querySelectorAll('.dots i')]:[]; dots.forEach((dot,i)=>{const k=HDPI.THEMES[i]&&HDPI.THEMES[i][0];dot.classList.toggle('on',k==='arcade');});
}

const P=HDPI.poll(renderHome); window.P=P;
addEventListener('keydown',e=>{ if(e.key==='Escape'&&screen==='game')exitGame(); });
"""

TWEAK_CSS = "\n/* --- in-app arcade fit: hide the preview brand, clear the injected titlebar --- */\n.brand{display:none}\nbody{padding:0;padding-top:34px;gap:0}\n"

out = ('<!doctype html>\n<html lang="tr"><head>\n'
       '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n'
       '<title>HenkerDPI</title>\n'
       '<style>' + style + TWEAK_CSS + '</style>\n'
       '</head><body>\n'
       + bodyhtml.strip() + '\n'
       + '<script src="bridge.js"></script>\n'
       + '<script>\n' + game + '\n</script>\n'
       + '<script>\n' + BRIDGE_SCRIPT + '\n</script>\n'
       + '</body></html>\n')
open(OUT, "w", encoding="utf-8").write(out)
print("wrote ui/arcade.html", len(out), "bytes")
