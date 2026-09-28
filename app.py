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

    "[BYPASS] <host>" lines are never written: on disk they would be a dated
    list of the blocked sites the user opened, in the very file they are asked
    to send for support. They are also the only per-packet lines, so leaving
    them out keeps disk writes off the packet thread.
    """
    try:
        print(msg)
    except Exception:
        pass
    if str(msg).startswith("[BYPASS]"):
        return
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


# If the engine thread exits without the user stopping it, bring it back instead
# of sitting "off" until the app is restarted by hand. The delay doubles while
# runs keep ending quickly (each start pins and restores DNS, so a tight loop
# would flap the resolver), and after ENGINE_MAX_QUICK_FAILS short-lived runs in
# a row the engine is left off so the window shows the real state.
ENGINE_RESTART_DELAY = 5.0
ENGINE_RESTART_MAX_DELAY = 300.0
ENGINE_HEALTHY_RUN = 60.0
ENGINE_MAX_QUICK_FAILS = 5


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
        quick_fails = 0
        while self._gen == gen:
            began = time.time()
            try:
                engine.start()           # blocks until stop()
            except Exception as e:
                engine_log("[!] engine: %s" % e)
            if self._gen != gen:
                break
            if time.time() - began >= ENGINE_HEALTHY_RUN:
                quick_fails = 0
            quick_fails += 1
            if quick_fails > ENGINE_MAX_QUICK_FAILS:
                engine_log("[!] Motor art arda baslayamadi — kapali birakildi")
                break
            delay = min(ENGINE_RESTART_DELAY * 2 ** (quick_fails - 1),
                        ENGINE_RESTART_MAX_DELAY)
            engine_log("[!] Motor beklenmedik sekilde durdu — %.0f sn sonra "
                       "yeniden baslatiliyor" % delay)
            self._wake.wait(delay)
            self._wake.clear()
        if self._gen == gen:
            self.running = False

    def start(self):
        if self.running:
            return
        self._gen += 1
        self._wake.clear()                # a wake left by the last stop() must not cut the delay
        # Windows only: the macOS engine logs visited hosts in lines that do not
        # carry the [BYPASS] prefix engine_log filters, so it keeps printing.
        self.engine = BypassEngine(log_callback=engine_log if os.name == "nt" else None,
                                   verbose=False)
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
            "version": config.APP_VERSION,
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
    if m == "check_update":     return _check_update_now(core)
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


def _check_update_now(core):
    """Force an update check for the settings "check now" button.

    Returns a small status dict the window can show directly:
      {"status": "available", "version": X}  a newer release exists (and is now
                                              stored on the core, so the banner
                                              and apply_update pick it up too)
      {"status": "none",      "version": X}  reached GitHub, already newest
      {"status": "error"}                    could not reach GitHub at all
    check_for_update returns None for BOTH "up to date" and "error", so
    updater.last_check_failed() (set by its own mark_checked) tells them apart.
    """
    try:
        info = updater.check_for_update(force=True)
    except Exception:
        info = None
    if info:
        core._update_info = info
        core._update_status = None
        return {"status": "available", "version": info.version,
                "can_apply": updater.can_self_update(),
                "notes_url": info.notes_url}
    if updater.last_check_failed():
        return {"status": "error"}
    return {"status": "none", "version": config.APP_VERSION}


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


def _current_user():
    """(DOMAIN\\user, SID) of the account this process runs as."""
    name = "%s\\%s" % (os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", ""))
    sid = ""
    try:
        r = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                           capture_output=True, text=True, encoding="oem",
                           errors="replace", creationflags=_CF)
        parts = [p.strip().strip('"') for p in (r.stdout or "").strip().split('","')]
        if len(parts) == 2:
            name, sid = parts[0] or name, parts[1]
    except Exception:
        pass
    return name, sid


def _task_owner(name):
    """None if the task does not exist, "" if it names no user (an any-user
    trigger from an old build), else the account names/SIDs it is bound to."""
    try:
        # Same codec as whoami in _current_user: both console tools write the
        # OEM code page, so a non-ASCII account name compares equal. The SID
        # (always ASCII) is the match that does not depend on it.
        r = subprocess.run(["schtasks", "/query", "/tn", name, "/xml"],
                           capture_output=True, text=True, encoding="oem",
                           errors="replace", creationflags=_CF)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    import re
    return [u.strip().lower() for u in re.findall(r"<UserId>([^<]*)</UserId>", r.stdout or "")]


def _task_is_mine(owner, me=None):
    """The autostart choice is per user, so a task bound to another account on
    the same PC is never adopted, overwritten or deleted.

    A task that names a SID is decided on the SID alone: a bare or full account
    name can match a different account (PC\\ali vs AzureAD\\ali). Without a SID
    only the full DOMAIN\\user counts. A task naming no user at all (an any-user
    trigger from an old build) is adoptable."""
    if owner is None:
        return False
    if not owner:
        return True
    name, sid = me or _current_user()
    sids = [u for u in owner if u.startswith("s-1-")]
    if sids and sid:
        return sid.lower() in sids
    full = name.lower()
    return any(u == full for u in owner if not u.startswith("s-1-"))


def _user_task_name(me):
    """This account's own task name, used when TASK_NAME belongs to another
    account on the same PC, so every account can have autostart. The full SID,
    not just the RID: a local and a domain account can share a RID."""
    import re
    name, sid = me
    tail = sid if sid else re.sub(r"[^A-Za-z0-9_.-]", "_", name.split("\\")[-1])
    return "%s-%s" % (TASK_NAME, tail)


def _task_names(me):
    return (TASK_NAME, _user_task_name(me)) + LEGACY_TASKS


def had_autostart_task():
    """True if an older build left a logon task for this user — its choice is
    carried over."""
    if os.name != "nt":
        return False
    me = _current_user()
    return any(_task_is_mine(_task_owner(n), me) for n in _task_names(me))


def _delete_task(name):
    subprocess.run(["schtasks", "/delete", "/tn", name, "/f"],
                   capture_output=True, creationflags=_CF)


def _register_task(name, me):
    """Register the logon task `name` for this account. Returns True on success.

    This runs elevated, so the XML must not pass through a file an unelevated
    process could swap between the write and schtasks reading it (that would
    register ITS task, elevated). It is written with a random, exclusively
    created name into %SystemRoot%\\Temp: users may create files there but not
    modify or delete another principal's, and the elevated file's owner is
    Administrators. No PowerShell is involved, so no user-writable module path
    is loaded into the elevated process either.
    """
    import tempfile
    from xml.sax.saxutils import escape
    command, arguments = _task_action()
    # The SID when known: whoami's name is decoded through the OEM code page,
    # so an account name outside it (Cyrillic on a Turkish system) would come
    # back as "????" and fail to map. Task Scheduler takes a SID as UserId.
    user = me[1] or "%s\\%s" % (os.environ.get("USERDOMAIN", ""),
                                os.environ.get("USERNAME", ""))
    xml = _TASK_XML.format(user=escape(user), command=escape(command),
                           arguments=escape(arguments),
                           workdir=escape(os.path.dirname(command)))
    path = None
    try:
        # From the API, not the SystemRoot variable: the environment is not
        # the elevated process's to trust for a security-relevant folder.
        buf = ctypes.create_unicode_buffer(260)
        n = ctypes.windll.kernel32.GetSystemWindowsDirectoryW(buf, 260)
        windir = buf.value if 0 < n < 260 else r"C:\Windows"
        fd, path = tempfile.mkstemp(prefix="henkerdpi-task-", suffix=".xml",
                                    dir=os.path.join(windir, "Temp"))
        with os.fdopen(fd, "w", encoding="utf-16") as f:
            f.write(xml)
        r = subprocess.run(["schtasks", "/create", "/tn", name, "/xml", path, "/f"],
                           capture_output=True, text=True, encoding="oem",
                           errors="replace", creationflags=_CF, timeout=60)
        if r.returncode != 0:
            engine_log("[!] Acilis gorevi olusturulamadi: %s"
                       % (r.stderr or r.stdout).strip()[:300])
        return r.returncode == 0
    except Exception as e:
        engine_log("[!] Acilis gorevi olusturulamadi: %s" % e)
        return False
    finally:
        if path:
            try:
                os.remove(path)
            except OSError:
                pass


def sync_autostart_task(enabled):
    """Make this user's logon task match `enabled`. Returns True on success.

    Always rewritten when enabled, so a task left by an older build (wrong path,
    72-hour limit, battery rule) is replaced by the current one. The shared name
    TASK_NAME is used unless another account on this PC owns it, in which case
    this account gets its own name. This user's other task names (legacy ones,
    or the other of the two) are removed only after the new one is registered,
    so a failed registration never costs a working autostart.
    """
    if os.name != "nt":
        return False
    me = _current_user()
    owners = {n: _task_owner(n) for n in _task_names(me)}
    mine = [n for n, o in owners.items() if _task_is_mine(o, me)]
    if not enabled:
        for n in mine:
            _delete_task(n)
        return True
    shared = owners[TASK_NAME]
    target = TASK_NAME if (shared is None or TASK_NAME in mine) else _user_task_name(me)
    if owners.get(target) is not None and target not in mine:
        engine_log("[!] Acilis gorevi adi baska bir hesaba ait — dokunulmadi")
        return False
    if not _register_task(target, me):
        return False
    for n in mine:
        if n != target:
            _delete_task(n)
    return True


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
