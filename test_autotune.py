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
import time

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

# 3b) PARTIAL CLIENTHELLO — a hello whose SNI fell into a later TCP segment must
#     be recognised (so the engine reshapes it instead of forwarding it clean)
#     and reshaped without a decoy (only its own real bytes reordered, so it can
#     never poison another site). This is the phone-line fix: on a ~1400-byte MSS
#     path Chromium's ~1.8 KB hello puts the SNI in segment 2 about half the time.
import strategies

_first = autotune._client_hello("discord.com")                 # SNI in segment 1
_late = autotune._client_hello("discord.com", sni_last=True)   # SNI in a later segment
check("full hello (SNI early) is not seen as a partial hello",
      not strategies.is_partial_hello(_first))
check("SNI-last hello, truncated to one 1400B segment, IS a partial hello",
      strategies.is_partial_hello(_late[:1400])
      and autotune.extract_sni(_late[:1400]) is None,
      "record spans the segment and no SNI is readable in it")


class _CapW:
    """Captures what fragment_partial_hello would send, without a real handle."""
    def __init__(self):
        self.sent = []

    def send(self, pkt, **_):
        self.sent.append(bytes(pkt.raw))


import pydivert
from pydivert.consts import Direction


def _mk_packet(payload):
    # Minimal outbound IPv4/TCP packet carrying `payload`, for the reshaper.
    ihl, thl = 20, 20
    ip = bytearray(ihl)
    ip[0] = 0x45
    ip[9] = 6                                       # TCP
    ip[12:16] = bytes((10, 0, 0, 1))
    ip[16:20] = bytes((93, 184, 216, 34))
    struct = __import__("struct")
    struct.pack_into("!H", ip, 2, ihl + thl + len(payload))
    tcp = bytearray(thl)
    struct.pack_into("!H", tcp, 0, 51000)           # src port
    struct.pack_into("!H", tcp, 2, 443)             # dst port
    struct.pack_into("!I", tcp, 4, 1000)            # seq
    tcp[12] = (thl // 4) << 4
    return pydivert.Packet(bytes(ip) + bytes(tcp) + payload,
                           interface=(1, 0), direction=Direction.OUTBOUND)


import struct as _struct

_orig = bytes(_late[:1400])
_w = _CapW()
_ok = strategies.fragment_partial_hello(_w, _mk_packet(_orig))
# Two segments out, sent tail-first, together carrying every original byte
# exactly once, with no injected/decoy packet.
check("partial hello is cut into 2 segments, no decoy added",
      _ok and len(_w.sent) == 2, "sent %d packet(s)" % len(_w.sent))
_seqs = [_struct.unpack_from("!I", p, 24)[0] for p in _w.sent]   # TCP seq @ IP20+4
check("segments are sent tail-first (descending sequence numbers)",
      _seqs == sorted(_seqs, reverse=True) and _seqs[0] != _seqs[1],
      "seqs sent in order %r" % _seqs)
# Reassemble by ascending seq and confirm the payload is byte-identical: the
# server sees exactly the original hello, only its segments reordered on the wire.
_by_seq = sorted(_w.sent, key=lambda p: _struct.unpack_from("!I", p, 24)[0])
_reassembled = b"".join(p[40:] for p in _by_seq)                 # strip 20B IP + 20B TCP
check("reordered segments reassemble to the exact original payload",
      _reassembled == _orig, "len %d vs %d" % (len(_reassembled), len(_orig)))

# 3c) IPv6 line detection is a boolean and never raises (drives the IPv6 bypass).
_v6 = autotune.has_ipv6_default()
check("has_ipv6_default() returns a bool", isinstance(_v6, bool), "got %r" % _v6)


# 3d) ENGINE FILTER — the IPv6 clause appears only when the line has IPv6, and
#     uses ipv6.DstAddr (the name WinDivert accepts), never ip6.DstAddr.
import main as _mainmod


class _FiltProbe:
    _ipv6_active = False
    _build_main_filter = _mainmod.BypassEngine._build_main_filter


_fp = _FiltProbe()
_f4 = _fp._build_main_filter()
_fp._ipv6_active = True
_f6 = _fp._build_main_filter()
check("IPv4-only line filter has no IPv6 clause",
      "ipv6" not in _f4 and "ip.DstAddr" in _f4)
check("IPv6 line filter adds an ipv6.DstAddr clause (not ip6.DstAddr)",
      "ipv6.DstAddr" in _f6 and "ip6.DstAddr" not in _f6)

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

# 6) WEBVIEW CORE UPDATE HOOK — the shipped exe is now the WebView app (app.py),
#    so its tray-side updater is release-critical: without it, updating onto the
#    WebView build would lose auto-update. Verify the same balloon-click wiring
#    installs there too.
if os.name == "nt":
    try:
        import pystray
        from pystray._util import win32 as _pswin32

        import app
        import updater
    except Exception as exc:                       # pragma: no cover
        print("SKIP - webview update hook check (import failed: %s)" % exc)
    else:
        updater.can_self_update = lambda: True     # as if frozen, so the hook installs
        updater.due_for_check = lambda force=False: False   # no real network call

        class _FakeCore:
            _update_info = object()
            def stop(self):
                pass

        # Clicking the toast now OPENS THE WINDOW (which shows an install banner)
        # rather than installing silently — robust against the flaky Win10/11
        # toast-click. Verify the handler routes to show_ui, not a silent install.
        _opened6 = []
        app.show_ui = lambda: _opened6.append(1)
        _icon6 = pystray.Icon("selftest6", None, "selftest6", pystray.Menu())
        _before6 = _icon6._message_handlers[_pswin32.WM_NOTIFY]
        app._wire_updates(_FakeCore(), _icon6, "tr")
        check("webview: update wiring replaced the tray WM_NOTIFY handler",
              _before6 is not _icon6._message_handlers[_pswin32.WM_NOTIFY])
        _icon6._message_handlers[_pswin32.WM_NOTIFY](0, app._NIN_BALLOONUSERCLICK)
        check("webview: clicking the update notification opens the window", len(_opened6) == 1)

        # The window's update banner reads/triggers the update over IPC; verify the
        # dispatch routes both methods and no-ops safely when nothing is pending.
        class _NoUpd:
            _update_info = None
        check("webview: get_update IPC is None with no pending release",
              app._dispatch(_NoUpd(), {"m": "get_update"}) is None)
        check("webview: apply_update IPC is a no-op with no pending release",
              app._dispatch(_NoUpd(), {"m": "apply_update"}) is False)
else:
    print("SKIP - webview update hook check (not Windows)")

print()
print("ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
