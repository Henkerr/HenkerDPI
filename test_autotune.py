"""Line-tuner regression tests. Run before every build:  py test_autotune.py

This exists because the same class of bug has broken this repo repeatedly: a
measurement that can never observe a real success, so it always falls back and
mis-picks the desync strategy — most recently a ClientHello missing the required
TLS 1.3 key_share extension, which made every server answer with a fatal
missing_extension alert (109) instead of a ServerHello. The first test below is
the exact check that would have caught it at build time.

Part live (needs network, no admin), part pure-logic. Non-zero exit on any fail.
"""
import socket
import sys

import autotune

fails = []


def check(name, cond, detail=""):
    print(("PASS" if cond else "FAIL"), "-", name, detail)
    if not cond:
        fails.append(name)


# 1) LIVE — the probe hello must draw a REAL ServerHello (0x16) from a control.
#    Catches any malformed-hello regression (missing key_share, bad lengths, ...).
def first_response_byte(host):
    ip = autotune.resolve(host)
    if not ip:
        return None
    s = None
    try:
        s = socket.create_connection((ip, 443), 4)
        s.settimeout(4)
        s.sendall(autotune._client_hello(host))
        d = s.recv(16)
        return d[0] if d else None
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


if autotune.online():
    got = {h: first_response_byte(h) for h in autotune.CONTROL_TARGETS}
    hello_ok = any(v == 0x16 for v in got.values())
    check("synthetic _client_hello draws a real ServerHello (0x16) from a control",
          hello_ok, "responses=%s (0x15=alert e.g. missing key_share)" % got)
else:
    print("SKIP - live hello check (offline)")

# 2) LOGIC — apparatus guard: a broken hello (never any 0x16) must produce the
#    loud 'arac-bozuk' + documented default, NOT a silent Discord-breaking pick.
_saved = (autotune.tls_reachable, autotune.resolve, autotune.online)
autotune.online = lambda: True
autotune.resolve = lambda h, dl=None: "203.0.113.1"
autotune.tls_reachable = lambda ip, host, timeout=0: False  # nothing ever opens
d, s2, status, _tgt = autotune.choose(lambda *a: None)
check("broken apparatus -> status 'arac-bozuk' + CANDIDATES[0] default",
      status == "arac-bozuk" and (d, s2) == autotune.CANDIDATES[0],
      "got status=%r pair=%r" % (status, (d, s2)))
autotune.tls_reachable, autotune.resolve, autotune.online = _saved

# 3) LOGIC — line-aware fallback picks the pair that fits the line.
_saved_ctrl = autotune._controls_ok
autotune._controls_ok = lambda de, sp, dl: (de == "badsum")   # fixed line: badsum safe
check("fixed line fallback -> badsum/record",
      autotune._nat_safe_fallback(lambda *a: None) == ("badsum", "record"))
autotune._controls_ok = lambda de, sp, dl: False              # NAT line: badsum poisons
check("NAT line fallback -> badseq/record",
      autotune._nat_safe_fallback(lambda *a: None) == autotune.SAFE_FALLBACK)
autotune._controls_ok = _saved_ctrl

# 4) VERSION SYNC — config.APP_VERSION is what updater.py compares against the
#    latest GitHub release tag, but the version ALSO lives in version_info.txt
#    (the Windows file resource) and setup.iss. Keeping them in sync by hand
#    failed: the exe shipped as 2.7.3 while APP_VERSION still said 2.7.0, so the
#    updater judged every release against a version the user was not running —
#    it would offer an already-installed build as an "update". Check it here.
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))


def _version_in(name, pattern):
    try:
        text = open(os.path.join(_HERE, name), encoding="utf-8",
                    errors="replace").read()
    except OSError:
        return None
    m = re.search(pattern, text)
    return m.group(1) if m else None


import config

_app = tuple(int(x) for x in config.APP_VERSION.split(".")[:3])
_res = _version_in("version_info.txt", r"'FileVersion',\s*'([0-9.]+)'")
_iss = _version_in("setup.iss", r"AppVersion=([0-9.]+)")
_res_t = tuple(int(x) for x in _res.split(".")[:3]) if _res else None
_iss_t = tuple(int(x) for x in _iss.split(".")[:3]) if _iss else None

check("config.APP_VERSION matches version_info.txt FileVersion",
      _res_t is not None and _app == _res_t,
      "APP_VERSION=%s version_info=%s" % (config.APP_VERSION, _res))
check("config.APP_VERSION matches setup.iss AppVersion",
      _iss_t is not None and _app == _iss_t,
      "APP_VERSION=%s setup.iss=%s" % (config.APP_VERSION, _iss))

# 5) WINDOWS NOTIFICATION HOOK — a click on the update notification must reach
#    the updater. The hook wraps a PRIVATE pystray structure (Icon builds
#    _message_handlers out of bound methods in __init__, so the dict entry is
#    the only thing that can be wrapped). A pystray upgrade can therefore break
#    it silently: the notification would still appear and simply do nothing.
#    Catch that here instead of in the wild.
if os.name == "nt":
    try:
        import pystray
        from pystray._util import win32 as _pswin32

        import gui
    except Exception as exc:                       # pragma: no cover
        print("SKIP - notification hook check (import failed: %s)" % exc)
    else:
        _fired = []

        class _FakeApp:
            def after(self, _ms, fn):
                _fired.append(fn)

            def _update_from_notification(self):
                pass                    # only the routing is under test here

        _icon = pystray.Icon("selftest", None, "selftest", pystray.Menu())
        _before = _icon._message_handlers[_pswin32.WM_NOTIFY]
        gui.HenkerDPIApp._hook_balloon_click(_FakeApp(), _icon)
        check("balloon-click hook replaced pystray's WM_NOTIFY handler",
              _before is not _icon._message_handlers[_pswin32.WM_NOTIFY])

        _icon._message_handlers[_pswin32.WM_NOTIFY](0, gui.NIN_BALLOONUSERCLICK)
        check("clicking the update notification routes to the updater",
              len(_fired) == 1, "fired=%d" % len(_fired))

        # An ordinary tray click must still reach pystray's own handler,
        # otherwise the hook would break showing/among the menu.
        _delegated = []
        _icon._message_handlers[_pswin32.WM_NOTIFY] = \
            lambda _w, lparam: _delegated.append(lparam)
        gui.HenkerDPIApp._hook_balloon_click(_FakeApp(), _icon)
        _fired.clear()
        _icon._message_handlers[_pswin32.WM_NOTIFY](0, _pswin32.WM_LBUTTONUP)
        check("ordinary tray clicks still reach pystray's own handler",
              _delegated == [_pswin32.WM_LBUTTONUP] and not _fired)
else:
    print("SKIP - notification hook check (not Windows)")

print()
print("ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
