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

print()
print("ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
sys.exit(1 if fails else 0)
