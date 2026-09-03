"""HenkerDPI core process: bypass engine + system tray + local IPC.

The window UI is a SEPARATE, on-demand process (ui.py) launched from the tray.
While HenkerDPI sits in the tray, only this process runs (engine + tray, ~35 MB);
no WebView2 is alive. Opening the window spawns ui.py; closing it exits ui.py and
frees all of its memory. ui.py reaches the engine only through the IPC below.

Slice status: Mevcut theme end-to-end (state, toggle, mode, DNS, theme, autostart
mirror). TODO next: schtasks autostart, categories/domains/log methods, the other
four themes, single-instance for ui.py + bring-to-front, PyInstaller packaging.
"""
import sys, os, json, socket, threading, subprocess, time, ctypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if sys.platform == "darwin":
    from macos.engine import BypassEngine, is_admin
else:
    from main import BypassEngine, is_admin
import config
import updater
try:
    from lang import t
except Exception:
    def t(k, *a, **kw): return k

HERE = os.path.dirname(os.path.abspath(__file__))
UI_SCRIPT = os.path.join(HERE, "ui.py")
IPC_HOST, IPC_PORT = "127.0.0.1", 47654


class Core:
    """Owns the bypass engine and the settings the UI reads/writes."""
    def __init__(self):
        self.engine = None
        self.thread = None
        self.running = False
        self.started = 0.0
        self.settings = config.load_settings()
        self._update_info = None          # set by the tray update watcher
        self._update_status = None        # None | "downloading" | "failed" — shown in the window banner
        self._icon = None                 # tray icon, so an IPC apply_update can stop it

    def _run(self):
        try:
            self.engine.start()          # blocks until stop()
        except Exception as e:
            print("[!] engine:", e)
        finally:
            self.running = False

    def start(self):
        if self.running:
            return
        self.engine = BypassEngine(verbose=False)
        self.running = True
        self.started = time.time()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        if self.engine and self.running:
            try:
                self.engine.stop()
            except Exception:
                pass
        self.running = False

    def toggle(self):
        self.stop() if self.running else self.start()

    def _save(self, reload=True):
        config.save_settings(self.settings)
        if reload and self.engine and self.running:
            try:
                self.engine.reload_settings()
            except Exception:
                pass

    def state(self):
        st = self.engine.stats if (self.engine and self.running) else {"bypassed": 0, "passed": 0}
        s = self.settings
        dns = s.get("doh_provider", "cloudflare")
        return {
            "running": self.running,
            "bypassed": st.get("bypassed", 0),
            "passed": st.get("passed", 0),
            "uptime": int(time.time() - self.started) if self.running else 0,
            "mode": s.get("mode", config.MODE_ALL),
            "dns": dns,
            "dns_name": config.DOH_PROVIDERS.get(dns, {}).get("name", "Cloudflare"),
            "dns_ip": config.DOH_PROVIDERS.get(dns, {}).get("ip", "1.1.1.1"),
            "dns_enabled": s.get("doh_enabled", True),
            "autostart": s.get("autostart", False),
            "theme": s.get("theme", "mevcut"),
        }

    def set_mode(self, m):        self.settings["mode"] = m; self._save()
    def set_dns(self, d):         self.settings["doh_provider"] = d; self._save()
    def set_dns_enabled(self, b): self.settings["doh_enabled"] = bool(b); self._save()
    def set_theme(self, tk):      self.settings["theme"] = tk; self._save(reload=False)
    def set_autostart(self, b):
        self.settings["autostart"] = bool(b); self._save(reload=False)
        # TODO: register / unregister the schtasks boot task (reuse gui.py logic).

    def get_log(self, n=20):
        """Recent real ClientHello events (domain + bypass/pass) for the live log."""
        ev = getattr(self.engine, "events", None) if (self.engine and self.running) else None
        if not ev:
            return []
        out = []
        for ts, host, act in list(ev)[-int(n or 20):]:
            lt = time.localtime(ts)
            out.append({"t": "%02d:%02d:%02d" % (lt.tm_hour, lt.tm_min, lt.tm_sec),
                        "host": host, "act": act})
        out.reverse()                 # newest first
        return out


# ---------------------------------------------------------------- IPC (localhost)
def _dispatch(core, msg):
    m, a = msg.get("m"), msg.get("a", [])
    if m == "get_state":        return core.state()
    if m == "toggle":           core.toggle(); return core.state()
    if m == "set_mode":         core.set_mode(*a); return None
    if m == "set_dns":          core.set_dns(*a); return None
    if m == "set_dns_enabled":  core.set_dns_enabled(*a); return None
    if m == "set_autostart":    core.set_autostart(*a); return None
    if m == "set_theme":        core.set_theme(*a); return None
    if m == "get_log":          return core.get_log(*a)
    if m == "get_update":       return _update_dict(core)
    if m == "apply_update":     return _start_apply(core)
    if m == "show_ui":          show_ui(); return None
    if m == "ping":             return "pong"
    raise ValueError("unknown method: %r" % m)


def _handle(conn, core):
    with conn:
        f = conn.makefile("rwb")
        for line in f:
            try:
                resp = {"r": _dispatch(core, json.loads(line.decode("utf-8")))}
            except Exception as e:
                resp = {"e": str(e)}
            try:
                f.write((json.dumps(resp) + "\n").encode("utf-8")); f.flush()
            except Exception:
                break


def ipc_server(core):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((IPC_HOST, IPC_PORT)); srv.listen(8)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=_handle, args=(conn, core), daemon=True).start()


def _ipc_send(msg, timeout=0.6):
    """One-shot call to a running instance. Returns the reply, or None if none answers."""
    try:
        with socket.create_connection((IPC_HOST, IPC_PORT), timeout=timeout) as c:
            f = c.makefile("rwb")
            f.write((json.dumps(msg) + "\n").encode("utf-8")); f.flush()
            return json.loads(f.readline().decode("utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------- tray + UI proc
_ui_proc = None

def show_ui():
    """Open the window process, or no-op if it is already up."""
    global _ui_proc
    if _ui_proc and _ui_proc.poll() is None:
        return  # TODO: signal the running ui.py to focus its window
    creationflags = 0x08000000 if os.name == "nt" else 0   # CREATE_NO_WINDOW
    # Frozen: there is no ui.py on disk to hand the interpreter — re-launch this
    # very exe with --ui so its main() runs the window instead of the core. In a
    # source checkout, run ui.py directly.
    if getattr(sys, "frozen", False):
        args = [sys.executable, "--ui"]
    else:
        args = [sys.executable, UI_SCRIPT]
    # env=child_env(): a onefile exe re-launching itself must NOT pass the
    # PyInstaller _MEI handoff vars, or the window process would share — and then
    # prematurely delete — this core's extraction folder (see config.child_env).
    _ui_proc = subprocess.Popen(args, cwd=HERE, creationflags=creationflags,
                                env=config.child_env())


def _tray_image():
    from PIL import Image
    png = os.path.join(HERE, "icon.png")
    if os.path.exists(png):
        try:
            return Image.open(png)                 # the real HenkerDPI wolf logo
        except Exception:
            pass
    from PIL import ImageDraw                        # fallback mark if the png is missing
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((14, 16, 50, 52), outline=(77, 139, 255, 255), width=5)
    d.rectangle((30, 10, 34, 33), fill=(77, 139, 255, 255))
    return img


def run_tray(core):
    import pystray
    lang = core.settings.get("lang", "tr")

    def toggle(icon, item):
        core.toggle(); icon.update_menu()

    def quit_all(icon, item):
        core.stop()
        global _ui_proc
        if _ui_proc and _ui_proc.poll() is None:
            try: _ui_proc.terminate()
            except Exception: pass
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(t("tray_show", lang), lambda i, it: show_ui(), default=True),
        pystray.MenuItem(lambda it: t("tray_stop", lang) if core.running else t("tray_start", lang), toggle),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(t("tray_quit", lang), quit_all),
    )
    icon = pystray.Icon("HenkerDPI", _tray_image(), "HenkerDPI", menu)
    _wire_updates(core, icon, lang)
    icon.run()


# Windows delivers the tray callback with this lparam when the user CLICKS a
# notification we raised (it lands in the Action Center, so long after).
_NIN_BALLOONUSERCLICK = 0x0400 + 5


def _wire_updates(core, icon, lang):
    """Check GitHub for a newer release, notify via the tray, install on click.

    The always-on core is the one instance that most needs telling — it can sit
    autostarted in the tray for days with no window open. The updater self-limits
    to one real check a day, so the hourly poll is nearly free. A click on the
    notification swaps the exe in place and relaunches. Only meaningful for the
    packaged Windows exe; a source run or macOS bundle cannot swap itself.
    """
    core._icon = icon                     # so an IPC apply_update can stop the tray
    if not updater.can_self_update():
        return

    def check_loop():
        while True:
            try:
                if updater.due_for_check():
                    info = updater.check_for_update()
                    if info and not updater.is_skipped(info.version):
                        core._update_info = info
                        try:
                            icon.notify(
                                t("update_notify", lang).format(version=info.version),
                                "HenkerDPI")
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(3600)

    threading.Thread(target=check_loop, daemon=True).start()

    if os.name != "nt":
        return
    # pystray builds its win32 message map from bound methods in Icon.__init__,
    # so the map entry is what has to be wrapped to see the balloon click. This
    # is private API: any failure stays harmless (the notification still shows,
    # it just stops being clickable).
    try:
        from pystray._util import win32 as _pswin32
        handlers = icon._message_handlers
        original = handlers[_pswin32.WM_NOTIFY]
    except Exception:
        return

    def on_notify(wparam, lparam):
        # Clicking the toast OPENS THE WINDOW rather than silently installing:
        # the window shows an "update ready → Yükle" banner (bridge.js polls
        # get_update), so the update is visible and installs on the user's click
        # even when the flaky Win10/11 toast-click does not reach this handler.
        if lparam == _NIN_BALLOONUSERCLICK and getattr(core, "_update_info", None):
            show_ui()
            return
        return original(wparam, lparam)

    try:
        handlers[_pswin32.WM_NOTIFY] = on_notify
    except Exception:
        pass


def _update_dict(core):
    """The pending update (if any) as a plain dict for the window banner."""
    info = getattr(core, "_update_info", None)
    if not info:
        return None
    return {"version": info.version, "tag": info.tag,
            "notes_url": info.notes_url, "status": getattr(core, "_update_status", None)}


def _start_apply(core):
    """Kick off the download+install in the background (called from the window)."""
    if not getattr(core, "_update_info", None):
        return False
    if getattr(core, "_update_status", None) == "downloading":
        return True                       # already running — don't start twice
    threading.Thread(target=_apply_update, args=(core, getattr(core, "_icon", None)),
                     daemon=True).start()
    return True


def _apply_update(core, icon=None):
    """Download, verify and swap in the update, then relaunch the new exe."""
    info = getattr(core, "_update_info", None)
    if not info:
        return
    core._update_status = "downloading"
    try:
        core.stop()                       # engine down first, so DNS is restored
        path = updater.download_update(info)
        updater.apply_update(path)
    except Exception as e:
        print("[!] update failed:", e)
        core._update_status = "failed"
        return
    global _ui_proc
    if _ui_proc and _ui_proc.poll() is None:
        try:
            _ui_proc.terminate()
        except Exception:
            pass
    if icon:
        try:
            icon.stop()
        except Exception:
            pass
    updater.relaunch()


def ensure_admin():
    if os.name != "nt" or is_admin():
        return
    params = " ".join('"%s"' % a for a in sys.argv[1:])
    # ShellExecute has no environment parameter — the elevated process inherits
    # this one's block as-is. Scrub the PyInstaller _MEI handoff vars first so the
    # elevated copy extracts its own folder instead of reusing (and, once this
    # launcher exits below, losing) ours. See config.scrub_pyi_env.
    config.scrub_pyi_env()
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, '"%s" %s' % (os.path.abspath(__file__), params), None, 1)
    sys.exit(0)


def main():
    # Frozen re-launch as the window process: the core spawns this exe with --ui
    # (there is no ui.py on disk in a onefile build). The window talks to the
    # core over IPC and needs no admin of its own, so this runs before
    # ensure_admin and never touches the single-instance mutex.
    if "--ui" in sys.argv:
        import ui
        ui.main()
        return

    ensure_admin()
    if os.name == "nt":
        ctypes.windll.kernel32.CreateMutexW(None, True, "Global\\HenkerDPI_SingleInstance")
        if ctypes.windll.kernel32.GetLastError() == 183:   # ERROR_ALREADY_EXISTS
            # Mutex is held — but only defer to a LIVE instance. A wedged one (mutex
            # held, IPC dead, e.g. after a crash) must not block a fresh start.
            if _ipc_send({"m": "ping"}) is not None:
                _ipc_send({"m": "show_ui"})          # bring the running window to front
                print("HenkerDPI zaten çalışıyor — pencere açıldı."); return
            print("Önceki örnek yanıt vermiyor; devralınıyor.")

    try:
        from doh import restore_dns_from_journal
        restore_dns_from_journal()
    except Exception:
        pass

    updater.cleanup_old_version()      # delete the exe an earlier update left aside
    # Clear the onefile temp folders past runs left behind (see sweep_stale_mei).
    threading.Thread(target=config.sweep_stale_mei, daemon=True).start()

    core = Core()
    threading.Thread(target=ipc_server, args=(core,), daemon=True).start()

    if "--autostart" in sys.argv or core.settings.get("autostart"):
        core.start()            # boot: run the engine, stay in the tray
    else:
        show_ui()               # normal launch: open the window
    run_tray(core)              # blocks on the main thread


if __name__ == "__main__":
    main()
