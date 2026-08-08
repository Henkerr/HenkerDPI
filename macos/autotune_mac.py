"""Measure which framing technique this line actually needs.

Same contract as the Windows autotuner: find a target the line is blocking, try
the candidates against it in order, and reject any candidate that gets the
blocked target through but breaks a site that was never blocked. The user never
picks a technique and never edits a settings file.

The measurement is far cheaper here than on Windows. There the probe had to open
a WinDivert handle to reshape packets the kernel had already sent; here the
prober simply opens the connection itself and frames the ClientHello however it
likes, so a scan is ordinary unprivileged socket work.
"""

import os
import socket
import ssl
import subprocess
import time

import dnsq
from config import STATE_DIR
from tunecache import TuneCache
from . import desync

CACHE = TuneCache(os.path.join(STATE_DIR, "autotune_mac.json"))

# Order matters: the first candidate that clears both bars wins, so the ones
# most likely to work sit at the top. Record fragmentation leads because it is
# what survived every server measured, and because a DPI that reassembles TCP
# fragments — which Iranian and Chinese systems are documented to do — is
# unaffected by segment splitting alone.
CANDIDATES = desync.TECHNIQUES

PROBE_TARGETS = ("discord.com", "gateway.discord.gg", "x.com",
                 "www.instagram.com")
CONTROL_TARGETS = ("www.google.com", "www.cloudflare.com")

PROBE_TIMEOUT = 6.0
TOTAL_BUDGET = 45.0


def _cmd(args, timeout=4):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def network_signature() -> str:
    """Fingerprint of the network we are on. If it changes, re-measure.

    The Windows build reads this from the IP helper API; macOS has no such call
    from Python, but `route` and `arp` between them give the same three facts:
    which interface leaves the machine, which gateway it talks to, and that
    gateway's hardware address. The MAC is what distinguishes two networks that
    both hand out 192.168.1.1.
    """
    iface = gateway = None
    for line in _cmd(["route", "-n", "get", "default"]).splitlines():
        key, _, value = line.strip().partition(":")
        key, value = key.strip(), value.strip()
        if key == "gateway":
            gateway = value
        elif key == "interface":
            iface = value
    if not gateway:
        return "unknown"

    mac = "?"
    for line in _cmd(["arp", "-n", gateway]).splitlines():
        if " at " in line:
            parts = line.split(" at ", 1)[1].split()
            if parts:
                mac = parts[0]
            break
    return "%s|%s|%s" % (iface or "?", gateway, mac)


def online() -> bool:
    """Is there a way out yet? At login the engine can start before the network."""
    for server in dnsq.DEFAULT_RESOLVERS:
        try:
            socket.create_connection((server, 443), 2.0).close()
            return True
        except OSError:
            continue
    return False


def handshake_ok(host: str, technique: str, resolver=None) -> bool:
    """Does a real TLS handshake to `host` complete under this technique?

    A full handshake is the honest test. Merely getting bytes back would count a
    middlebox's own reset page as success, and completing the handshake proves
    the certificate chain came from the real server.
    """
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(inc, out, server_hostname=host)
    sock = None
    try:
        try:
            tls.do_handshake()
        except ssl.SSLWantReadError:
            pass
        sock = desync.connect_desynced(host, 443, out.read(), technique,
                                       resolver=resolver)
        sock.settimeout(PROBE_TIMEOUT)
        deadline = time.time() + PROBE_TIMEOUT
        while time.time() < deadline:
            try:
                tls.do_handshake()
                return True
            except ssl.SSLWantReadError:
                pass
            pending = out.read()
            if pending:
                sock.sendall(pending)
            chunk = sock.recv(65536)
            if not chunk:
                return False
            inc.write(chunk)
        return False
    except (OSError, ssl.SSLError, ValueError):
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _works(host: str, technique: str, resolver) -> bool:
    # One reset can be coincidence; the Windows prober retries for the same
    # reason. Two failures in a row is a property of the line.
    return (handshake_ok(host, technique, resolver) or
            handshake_ok(host, technique, resolver))


def _controls_ok(technique: str, resolver, deadline: float) -> bool:
    """Does this technique leave un-blocked sites alone?

    Record fragmentation is legal but not universally accepted — measurements
    put server support at roughly 92-96% — so a technique can clear the blocked
    target and still break ordinary browsing. This is the check that stops such
    a technique from being selected.
    """
    checked = 0
    for host in CONTROL_TARGETS:
        if time.time() > deadline:
            break
        checked += 1
        if not _works(host, technique, resolver):
            return False
    return checked > 0


def choose(log=print, deadline: float = None, resolver=None):
    """Return (technique, status). Mirrors autotune.choose's status vocabulary."""
    deadline = deadline or (time.time() + TOTAL_BUDGET)
    resolver = resolver or dnsq.DohResolver()
    default = CANDIDATES[0]

    if not online():
        return default, "offline"

    target = None
    for host in PROBE_TARGETS:
        if time.time() > deadline:
            break
        if not handshake_ok(host, "none", resolver):
            target = host
            break

    if not target:
        log("[*] Hatta engel saptanmadi — varsayilan strateji dogrulaniyor")
        # Nothing is blocked, so the only thing that matters is not breaking
        # what already works. "none" is the honest answer if it comes to that.
        for technique in CANDIDATES:
            if time.time() > deadline:
                break
            if _controls_ok(technique, resolver, deadline):
                return technique, "engel-yok"
        return "none", "engel-yok"

    log("[*] Engelli hedef: %s — strateji taraniyor" % target)
    for technique in CANDIDATES:
        if time.time() > deadline:
            log("[!] Tarama suresi doldu")
            break
        if not _works(target, technique, resolver):
            continue
        if not _controls_ok(technique, resolver, deadline):
            log("[!] %s engeli asiyor ama normal siteleri bozuyor — elendi"
                % technique)
            continue
        return technique, "olculdu"

    return default, "asilamadi"


def resolve_technique(settings: dict, log=print, force: bool = False):
    """The technique the engine should use, measuring only when it must."""
    if settings.get("strategy_mode", "auto") != "auto":
        chosen = settings.get("mac_technique", CANDIDATES[0])
        return (chosen if chosen in CANDIDATES else CANDIDATES[0]), "elle"

    signature = network_signature()
    if not force:
        hit = CACHE.get(signature)
        if hit and hit.get("technique") in CANDIDATES:
            return hit["technique"], "onbellek"

    log("[*] Hat taraniyor (ilk kurulum / yeni ag)...")
    started = time.time()
    technique, status = choose(log)

    if status == "offline":
        log("[*] Ag henuz hazir degil — varsayilan strateji ile baslaniyor")
        return technique, "offline"

    if signature != "unknown":
        CACHE.put(signature, {"technique": technique},
                  ok=status != "asilamadi")

    log("[*] Strateji secildi: %s (%.1fs, %s)"
        % (technique, time.time() - started, status))
    if status == "asilamadi":
        log("[!] Bu hatta hicbir strateji engeli asamadi — varsayilan kullaniliyor")
    return technique, status
