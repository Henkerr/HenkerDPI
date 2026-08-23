# -*- coding: utf-8 -*-
"""Wire the pixel-arcade home (arcade_home_v2.html) to the live engine bridge.

The canvas rendering, sprites, starfield, audio and input stay EXACTLY as built.
Only the data source and side effects are redirected: on/bypass/uptime come from
the engine, the settings rows persist to it, and the TEMA row switches between the
5 app themes. bridge.js globals (on, bypass, SET, sure, toggleDpi, changeSetting)
are classic-script globals, so the appended override can reassign them in place.
"""
import re, os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = r"C:\Users\mumin\AppData\Local\Temp\claude\C--Users-mumin-henkerdpi-v2\e7b5044d-28e3-4241-a490-349a8ca8ed60\scratchpad\arcade_home_v2.html"
UI = os.path.join(HERE, "ui")

text = open(SRC, encoding="utf-8").read()
css = re.search(r"<style>(.*?)</style>", text, re.S).group(1)
after = text.split("</style>", 1)[1]
body_html = after.split("<script>", 1)[0].strip()
script = re.search(r"<script>(.*?)</script>", after, re.S).group(1)

# TEMA row + palette now map to the 5 real app themes (arcade = index 3, stays pink)
script = script.replace(
    'const THEME_COLORS=["#ff3d9a","#4d8bff","#6d6af2","#2dd4bf","#e8b25a"];',
    'const THEME_COLORS=["#4d8bff","#2dd4bf","#38bdf8","#ff3d9a","#16a34a"];', 1)
script = script.replace(
    '{label:"TEMA",     opts:["ARCADE","GRAPHITE","IRIS","HALCYON","OBSIDIAN"], i:0},',
    '{label:"TEMA",     opts:["MEVCUT","CONSOLE","BENTO","ARCADE","COMBAT"], i:3},', 1)
assert "MEVCUT" in script and "#16a34a" in script, "arcade patch failed"

OVERRIDE = r"""
/* --- live-engine bridge: redirect data + side effects, leave rendering intact --- */
(function(){
  const THEME_KEYS=["mevcut","console","bento","arcade","combat"];
  let SU=0, SUat=0;                       // uptime baseline for a smooth per-second clock
  sure=function(){ if(!on) return "00:00"; const s=Math.floor(SU+(performance.now()-SUat)/1000);
    return p2(Math.floor(s/60))+":"+p2(s%60); };
  toggleDpi=function(){ on=!on; flash=1; flashCol=on?"94,245,143":"255,61,154";
    beep(on?1100:240, on?.12:.14, on?"square":"sawtooth", .05);
    HDPI.toggle().then(()=>P.tick()); };
  changeSetting=function(dir){ const s=SET[setSel]; if(!s) return; beep(620,.04,"square",.03);
    if(s.label==="TEMA"){ const i=(s.i+dir+THEME_KEYS.length)%THEME_KEYS.length; s.i=i;
      if(THEME_KEYS[i]!=="arcade") HDPI.nav(THEME_KEYS[i]); else applyTheme(); return; }
    s.i=(s.i+dir+s.opts.length)%s.opts.length;
    if(s.label==="MOD") HDPI.setMode(s.i===0?"all":"selective");
    else if(s.label==="DNS") HDPI.setDns(["cloudflare","google","quad9"][s.i]);
    else if(s.label==="OTOMATIK") HDPI.setAutostart(s.i===1); };
  function render(st){
    on=st.running; bypass=st.bypassed; SU=st.uptime; SUat=performance.now();
    SET[0].i = st.mode==="all"?0:1;
    SET[1].i = ({cloudflare:0,google:1,quad9:2})[st.dns] ?? 0;
    SET[2].i = st.autostart?1:0;
    SET[3].i = 3;                          // this page IS the arcade theme → keep it pink + selected
    applyTheme();
  }
  const P=HDPI.poll(render); window.P=P;
})();
"""

page = ('<!doctype html>\n<html lang="tr"><head>\n<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        '<title>HenkerDPI</title>\n<style>' + css + '\nbody{padding-top:40px}\n</style>\n</head><body>\n'
        + body_html + '\n'
        + '<script src="bridge.js"></script>\n'
        + '<script>\n' + script + '\n</script>\n'
        + '<script>\n' + OVERRIDE + '\n</script>\n'
        + '</body></html>\n')

open(os.path.join(UI, "arcade.html"), "w", encoding="utf-8").write(page)
print("wrote arcade.html", len(page), "bytes")
