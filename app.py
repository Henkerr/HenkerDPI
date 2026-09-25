"""HenkerDPI core process: bypass engine + system tray + local IPC.

The window UI is a SEPARATE, on-demand process (ui.py) launched from the tray.
While HenkerDPI sits in the tray, only this process runs (engine + tray, ~35 MB);
no WebView2 is alive. Opening the window spawns ui.py; closing it exits ui.py and
frees all of its memory. ui.py reaches the engine only through the IPC below.

Open work: categories/domains methods, focusing an already-open ui.py window.
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


LOG_FILE = os.path.join(config.STATE_DIR, "engine.log")
LOG_MAX_BYTES = 1024 * 1024
_log_lock = threading.Lock()


def engine_log(msg):
    """Append one engine line to %LOCALAPPDATA%\\HenkerDPI\\engine.log.

    The packaged app has no console, so without this every "[!]" the engine
    prints is lost — and a user whose connection "drops sometimes" has nothing
    to send. Rotates once at LOG_MAX_BYTES (keeps one old file).
    """
    line = "%s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    with _log_lock:
        try:
            if os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
                os.replace(LOG_FILE, LOG_FILE + ".1")
        except OSError:
            pass
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass
    try:
        print(msg)
    except Exception:
        pass


# If the engine thread exits without the user stopping it, bring it back after
# this long instead of sitting "off" until the app is restarted by hand.
ENGINE_RESTART_DELAY = 5.0


class Core:
    """Owns the bypass engine and the settings the UI reads/writes."""
    def __init__(self):
        self.engine = None
        self.thread = None
        self.running = False
        self.started = 0.0
        self._gen = 0                     # bumps on every start/stop; a stale run loop exits
        self._wake = threading.Event()
        self.settings = config.load_settings()
        self._update_info = None          # set by the tray update watcher
        self._update_status = None        # None | "downloading" | "failed" — shown in the window banner
        self._icon = None                 # tray icon, so an IPC apply_update can stop it

    def _run(self, gen, engine):
        while self._gen == gen:
            try:
                engine.start()           # blocks until stop()
            except Exception as e:
                engine_log("[!] engine: %s" % e)
            if self._gen != gen:
                break
            engine_log("[!] Motor beklenmedik sekilde durdu — %.0f sn sonra "
                       "yeniden baslatiliyor" % ENGINE_RESTART_DELAY)
            self._wake.wait(ENGINE_RESTART_DELAY)
            self._wake.clear()
        if self._gen == gen:
            self.running = False

    def start(self):
        if self.running:
            return
        self._gen += 1
        self._wake.clear()                # a wake left by the last stop() must not cut the delay
        self.engine = BypassEngine(log_callback=engine_log, verbose=False)
        self.running = True
        self.started = time.time()
        self.thread = threading.Thread(target=self._run, args=(self._gen, self.engine),
                                       daemon=True)
        self.thread.start()

    def stop(self):
        self._gen += 1                    # the run loop must not bring it back
        self._wake.set()
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
        b = bool(b)
        if not sync_autostart_task(b) and b:
            return False                  # task could not be made: leave the switch off
        self.settings["autostart"] = b; self._save(reload=False)
        return True

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
    if m == "set_autostart":    return core.set_autostart(*a)
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


# ---------------------------------------------------------------- autostart (Windows)
TASK_NAME = "HenkerDPI"
LEGACY_TASKS = ("HenkerDPI_V2",)
_CF = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Registered from XML rather than `schtasks /sc onlogon`, whose defaults break a
# tray app that must run for as long as the session: a 72-hour execution limit
# (Task Scheduler kills it on day three), no start on battery (a laptop that
# boots unplugged never starts it) and below-normal priority for the packet loop.
_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>HenkerDPI</Description></RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _task_action():
    """(command, arguments) the logon task runs: this exe, or pythonw + app.py."""
    if getattr(sys, "frozen", False):
        return sys.executable, "--autostart"
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pyw):
        exe = pyw                          # no console window flashing at logon
    return exe, '"%s" --autostart' % os.path.abspath(__file__)


def _task_exists(name):
    try:
        return subprocess.run(["schtasks", "/query", "/tn", name],
                              capture_output=True, creationflags=_CF).returncode == 0
    except Exception:
        return False


def had_autostart_task():
    """True if an older build left a logon task — its choice is carried over."""
    return os.name == "nt" and any(_task_exists(n) for n in (TASK_NAME,) + LEGACY_TASKS)


def sync_autostart_task(enabled):
    """Make the logon task match `enabled`. Returns True on success.

    Always rewritten when enabled, so a task left by an older build (wrong path,
    72-hour limit, battery rule) is replaced by the current one. Legacy task
    names are removed either way.
    """
    if os.name != "nt":
        return False
    for legacy in LEGACY_TASKS:
        if _task_exists(legacy):
            subprocess.run(["schtasks", "/delete", "/tn", legacy, "/f"],
                           capture_output=True, creationflags=_CF)
    if not enabled:
        if _task_exists(TASK_NAME):
            subprocess.run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
                           capture_output=True, creationflags=_CF)
        return True
    from xml.sax.saxutils import escape
    command, arguments = _task_action()
    user = "%s\\%s" % (os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", ""))
    xml = _TASK_XML.format(user=escape(user), command=escape(command),
                           arguments=escape(arguments),
                           workdir=escape(os.path.dirname(command)))
    path = os.path.join(config.STATE_DIR, "autostart_task.xml")
    try:
        with open(path, "w", encoding="utf-16") as f:
            f.write(xml)
        r = subprocess.run(["schtasks", "/create", "/tn", TASK_NAME, "/xml", path, "/f"],
                           capture_output=True, text=True, creationflags=_CF)
        if r.returncode != 0:
            engine_log("[!] Acilis gorevi olusturulamadi: %s" % (r.stderr or r.stdout).strip())
        return r.returncode == 0
    except Exception as e:
        engine_log("[!] Acilis gorevi olusturulamadi: %s" % e)
        return False
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _sync_autostart_on_launch(core):
    """Bring the logon task in line with the saved choice on every launch.

    A 3.0.x user who switched autostart on got only a saved setting and no task
    (the switch was a stub); a 2.x user has a task but no setting. Both end up
    with a correct task here. Also repoints the task if the exe was moved.
    """
    try:
        if "autostart" not in core.settings and had_autostart_task():
            core.settings["autostart"] = True
            config.save_settings(core.settings)
        sync_autostart_task(bool(core.settings.get("autostart")))
    except Exception as e:
        engine_log("[!] Acilis gorevi esitlenemedi: %s" % e)


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
    if os.name == "nt":
        threading.Thread(target=_sync_autostart_on_launch, args=(core,),
                         daemon=True).start()

    boot = "--autostart" in sys.argv
    if boot or core.settings.get("autostart"):
        core.start()            # protection on
    if not boot:
        show_ui()               # a launch by hand always opens the window
    run_tray(core)              # blocks on the main thread


if __name__ == "__main__":
    main()
