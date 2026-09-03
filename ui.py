"""HenkerDPI window process.

Loads the HTML UI in a WebView2/WKWebView window and proxies every call the page
makes to the always-on core process (app.py) over the local IPC socket. When the
window closes, webview.start() returns and this process exits fully, so no webview
memory is held while HenkerDPI sits in the tray.

The window is FRAMELESS (no OS titlebar): the page draws its own min/close chrome
(bridge.js) and is dragged via a `pywebview-drag-region` strip. It opens sized to
the saved theme so the app fills its frame with no black surround.
"""
import os, sys, json, socket
import webview

HERE = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(HERE, "ui")
ICON = os.path.join(HERE, "icon.ico")
IPC = ("127.0.0.1", 47654)

# Frameless window size per theme (content == window). Keep in sync with
# THEME_SIZE in ui/bridge.js, which resizes on theme switches.
SIZES = {
    "mevcut": (408, 688), "console": (416, 634), "bento": (384, 616),
    "arcade": (416, 690), "combat": (384, 616),
}
DEFAULT_SIZE = (408, 664)

WIN = None


def _call(method, *args):
    s = socket.create_connection(IPC, timeout=4)
    try:
        s.sendall((json.dumps({"m": method, "a": list(args)}) + "\n").encode("utf-8"))
        line = s.makefile("rb").readline()
        resp = json.loads(line.decode("utf-8"))
        if "e" in resp:
            raise RuntimeError(resp["e"])
        return resp.get("r")
    finally:
        s.close()


class Api:
    """Exposed to the page as window.pywebview.api.*.

    Engine calls forward to the core over IPC; the win_* calls act on THIS window.
    """
    def get_state(self):          return _call("get_state")
    def toggle(self):             return _call("toggle")
    def set_mode(self, m):        return _call("set_mode", m)
    def set_dns(self, d):         return _call("set_dns", d)
    def set_dns_enabled(self, b): return _call("set_dns_enabled", b)
    def set_autostart(self, b):   return _call("set_autostart", b)
    def set_theme(self, tk):      return _call("set_theme", tk)
    def get_log(self, n=20):      return _call("get_log", n)
    def get_update(self):         return _call("get_update")
    def apply_update(self):       return _call("apply_update")

    def win_minimize(self):
        if WIN:
            try: WIN.minimize()
            except Exception: pass

    def win_close(self):
        if WIN:
            try: WIN.destroy()
            except Exception: pass

    def win_resize(self, w, h):
        if WIN:
            try: WIN.resize(int(w), int(h))
            except Exception: pass


def _saved_theme():
    try:
        st = _call("get_state") or {}
        return st.get("theme", "mevcut")
    except Exception:
        return "mevcut"


def main():
    global WIN
    theme = _saved_theme()
    w, h = SIZES.get(theme, DEFAULT_SIZE)
    url = os.path.join(UI_DIR, theme + ".html")
    if not os.path.exists(url):
        url = os.path.join(UI_DIR, "index.html")
    WIN = webview.create_window(
        "HenkerDPI", url=url, js_api=Api(),
        width=w, height=h, min_size=(340, 520),
        resizable=False, frameless=True, easy_drag=False,
        background_color="#0a0b0d",
    )
    # returns when the window closes -> process exits, RAM freed.
    # icon= sets the taskbar icon to the wolf logo; older pywebview lacks the kwarg.
    try:
        webview.start(icon=ICON) if os.path.exists(ICON) else webview.start()
    except TypeError:
        webview.start()


if __name__ == "__main__":
    main()
