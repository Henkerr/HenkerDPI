"""
HenkerDPI V2 - Secure DNS manager
Redirects system DNS to secure resolvers (Cloudflare / Google / Quad9) to
bypass ISP-level DNS blocking/hijacking.

Crash-safety: the ORIGINAL per-interface DNS is written to an on-disk journal
BEFORE any change. If the process is force-killed or crashes (so stop() never
runs), the next launch — or service.py after a taskkill — calls
restore_dns_from_journal() and puts DNS back. This prevents the "DNS left
pinned to 1.1.1.1 forever" failure that made resolution flaky on ISPs that
throttle public resolvers.
"""

import os
import sys
import json
import atexit
import socket
import subprocess
import ctypes

from config import STATE_DIR

# Hide console windows for all subprocess calls
_CF = subprocess.CREATE_NO_WINDOW

# Secure resolvers, IPv4 + IPv6 so dual-stack machines don't leak lookups to
# the ISP resolver over IPv6 (Windows prefers IPv6 by default).
PROVIDERS = {
    "cloudflare": {
        "v4": ("1.1.1.1", "1.0.0.1"),
        "v6": ("2606:4700:4700::1111", "2606:4700:4700::1001"),
    },
    "google": {
        "v4": ("8.8.8.8", "8.8.4.4"),
        "v6": ("2001:4860:4860::8888", "2001:4860:4860::8844"),
    },
    "quad9": {
        "v4": ("9.9.9.9", "149.112.112.112"),
        "v6": ("2620:fe::fe", "2620:fe::9"),
    },
}

def _pid_alive(pid) -> bool:
    """True if a process with this PID is currently running (Windows)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    k = ctypes.windll.kernel32
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return False
    try:
        code = ctypes.c_ulong()
        ok = k.GetExitCodeProcess(h, ctypes.byref(code))
        return bool(ok) and code.value == STILL_ACTIVE
    finally:
        k.CloseHandle(h)


def _pid_image_name(pid):
    """Lowercase basename of the exe backing a live PID, or None.

    Makes journal ownership identity-safe: a bare PID can be reused by an
    unrelated process after a crash, so we confirm the live PID is really our
    program before treating it as a sibling that will restore DNS on its own.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    k = ctypes.windll.kernel32
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_ulong(32768)
        if not k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return None
        return os.path.basename(buf.value).lower()
    finally:
        k.CloseHandle(h)


def _reachable(ip: str, port: int = 53, timeout: float = 1.0) -> bool:
    """Quick TCP connect probe to a resolver IP (no DNS lookup involved).

    Pinning DNS to an UNREACHABLE resolver is a self-inflicted whole-internet
    outage, so start() probes before pinning. Port 53 (DNS over TCP) is answered
    by every bundled provider and is the truest reachability signal.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


_JOURNAL_FILE = os.path.join(STATE_DIR, "dns_backup.json")


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _run(cmd: list, timeout: int = 8) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          creationflags=_CF, timeout=timeout)


def _run_ps(script: str, timeout: int = 12) -> str:
    """Run a PowerShell snippet, return stdout ('' on any failure).

    Force the child's output encoding to UTF-8: on a localized Windows (e.g.
    Turkish, OEM code page 857) a redirected powershell pipe otherwise emits
    non-ASCII adapter names in the OEM code page, which our utf-8 decode would
    mangle — breaking name-based netsh matching for those adapters.
    """
    script = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;" + script
    try:
        r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                 timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def _split_servers(value) -> list:
    """Parse a registry NameServer value into a clean IP list.

    The value is captured verbatim (we do NOT strip addresses that happen to
    match our own providers): a user who deliberately set static 1.1.1.1 must
    have it restored, not silently converted to DHCP. Leftover pins from a
    crashed run are healed via the PID-aware journal, not by filtering here.
    """
    if not value:
        return []
    return [p.strip() for p in str(value).replace(",", " ").split() if p.strip()]


def get_target_interfaces() -> list:
    """Physical, internet-bearing adapters with their ORIGINAL static DNS.

    Only adapters that are Up AND carry an IPv4 default gateway are returned, so
    we never touch VPN/WSL/Hyper-V/virtual adapters. For each we read the
    registry NameServer (locale-independent, unlike netsh's translated labels)
    to learn the true original DNS: an empty list means the interface was on
    DHCP/automatic and must be restored to DHCP, not pinned static.

    "has_v6" reports whether the adapter has a real IPv6 default route. We only
    pin IPv6 DNS on such adapters — forcing an unreachable IPv6 resolver onto an
    IPv4-only box makes Windows try IPv6 DNS first and time out on every lookup,
    which looks like a whole-internet outage.

    Returns: [{"name": str, "v4": [ip...], "v6": [ip...], "has_v6": bool}]
    """
    script = r'''
$out = @()
Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
  Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    $ad = $_
    $cfg = Get-NetIPConfiguration -InterfaceIndex $ad.ifIndex -ErrorAction SilentlyContinue
    $gw = $null; if ($cfg -and $cfg.IPv4DefaultGateway) { $gw = $cfg.IPv4DefaultGateway.NextHop }
    $gw6 = $null; if ($cfg -and $cfg.IPv6DefaultGateway) { $gw6 = $cfg.IPv6DefaultGateway.NextHop }
    if ($gw) {
      $guid = $ad.InterfaceGuid
      $v4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
      $v6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
      $out += [PSCustomObject]@{ name = $ad.Name; v4 = "$v4"; v6 = "$v6"; has6 = [bool]$gw6 }
    }
  }
ConvertTo-Json @($out) -Compress
'''
    raw = _run_ps(script).strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    result = []
    for item in data:
        name = item.get("name")
        if name:
            result.append({"name": name,
                           "v4": _split_servers(item.get("v4")),
                           "v6": _split_servers(item.get("v6")),
                           "has_v6": bool(item.get("has6"))})
    return result


def _set_static(iface: str, family: str, servers) -> bool:
    """Set static DNS on one interface for one family ('ip' or 'ipv6')."""
    if not servers:
        return False
    try:
        r = _run(["netsh", "interface", family, "set", "dns",
                  f"name={iface}", "static", servers[0], "validate=no"])
        if r.returncode != 0:
            return False
        for i, extra in enumerate(servers[1:], start=2):
            _run(["netsh", "interface", family, "add", "dns",
                  f"name={iface}", extra, f"index={i}", "validate=no"])
        return True
    except Exception:
        return False


def _set_dhcp(iface: str, family: str) -> bool:
    """Reset one interface/family back to automatic (DHCP) DNS."""
    try:
        r = _run(["netsh", "interface", family, "set", "dns",
                  f"name={iface}", "dhcp"])
        return r.returncode == 0
    except Exception:
        return False


def _flush_dns() -> None:
    try:
        _run(["ipconfig", "/flushdns"], timeout=5)
    except Exception:
        pass


# === Crash-safe journal ===

def _write_journal(interfaces: dict) -> None:
    tmp = _JOURNAL_FILE + ".tmp"
    payload = {"pid": os.getpid(),
               "exe": os.path.basename(sys.executable).lower(),
               "interfaces": interfaces}
    try:
        with open(tmp, "w") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _JOURNAL_FILE)
    except OSError:
        pass


def _read_journal():
    try:
        with open(_JOURNAL_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _clear_journal() -> None:
    try:
        os.remove(_JOURNAL_FILE)
    except OSError:
        pass


def restore_dns_from_journal(log=print) -> bool:
    """Restore DNS recorded in a LEFTOVER journal, then delete it.

    Survives a force-kill: runs on the next launch and from service.py after a
    taskkill. Two safety rules learned from review:
      * Only heal a journal whose OWNING process is dead. If the owner is still
        running (e.g. a headless engine while the GUI launches), leave its DNS
        override alone so a second process cannot tear it down mid-session.
      * Keep the journal if the restore did not actually apply to any interface
        (adapter transiently absent at early boot), so a later launch retries.
    An interface whose original list is empty is restored to DHCP.
    """
    data = _read_journal()
    if not data:
        return False
    if isinstance(data, dict) and "interfaces" in data:
        owner = data.get("pid")
        owner_exe = data.get("exe")  # None for journals from older builds
        interfaces = data.get("interfaces") or {}
    else:  # legacy flat {iface: {...}} journal
        owner = None
        owner_exe = None
        interfaces = data if isinstance(data, dict) else {}

    if owner and owner != os.getpid() and _pid_alive(owner):
        # A live owner would restore on its own stop() — but a crash can leave a
        # dead owner whose PID Windows has since reused for an UNRELATED process.
        # Only defer to the live PID when we can confirm it is really our program
        # (matching image name); otherwise treat the owner as dead and restore,
        # so a reused PID can never block recovery and leave DNS pinned.
        live_exe = _pid_image_name(owner)
        if not owner_exe or not live_exe or live_exe == owner_exe:
            return False

    ok_any = False
    ok_all = True
    for iface, orig in interfaces.items():
        v4 = orig.get("v4") if isinstance(orig, dict) else orig
        v6 = orig.get("v6") if isinstance(orig, dict) else []
        r4 = _set_static(iface, "ip", v4) if v4 else _set_dhcp(iface, "ip")
        r6 = _set_static(iface, "ipv6", v6) if v6 else _set_dhcp(iface, "ipv6")
        if r4:
            ok_any = True
            log(f"[DNS] {iface} -> restored")
        if not (r4 and r6):
            # Keep the journal if EITHER family failed to revert. v4 can
            # black-hole all resolution; a v6 resolver left pinned is harmless
            # while v6 is up but stalls every lookup if v6 connectivity later
            # drops — and then this journal is the only thing that can heal it.
            ok_all = False
    _flush_dns()
    if ok_all:
        _clear_journal()
    return ok_any


class DohManager:
    """Redirects system DNS to a secure resolver, crash-safely."""

    def __init__(self, provider: str = "cloudflare", log_callback=None):
        self._provider = (provider or "cloudflare").strip().lower()
        self._log = log_callback or print
        self._original = {}       # {iface: {"v4": [...], "v6": [...]}}
        self._active = False
        self._atexit_registered = False

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> bool:
        self._provider = (self._provider or "").strip().lower()
        if self._provider not in PROVIDERS:
            self._log(f"[!] Unknown DNS provider: {self._provider}")
            return False

        # Heal any DNS left pinned by a previously crashed/killed run BEFORE we
        # capture originals — so we never record 1.1.1.1 as the "original".
        restore_dns_from_journal(self._log)

        # If that restore did NOT verifiably clear the journal, a prior override
        # is still in effect. Re-capturing "originals" now could record the
        # public resolver as the original and pin it permanently — the one
        # failure the journal exists to prevent. Bail: DNS stays exactly as-is.
        if os.path.exists(_JOURNAL_FILE):
            self._log("[!] Prior DNS override not verifiably reverted; skipping DNS change")
            return False

        # Reachability + cross-provider failover: pinning an unreachable resolver
        # is a self-inflicted outage. Probe the chosen provider; if the ISP
        # blocks/throttles it, fall back to another. If NONE is reachable, do not
        # pin at all — leave DNS untouched.
        order = [self._provider] + [k for k in PROVIDERS if k != self._provider]
        chosen = next((k for k in order if _reachable(PROVIDERS[k]["v4"][0])), None)
        if chosen is None:
            self._log("[!] No DNS resolver reachable; leaving DNS unchanged")
            return False
        if chosen != self._provider:
            self._log(f"[DNS] {self._provider.title()} unreachable; falling back to {chosen.title()}")
            self._provider = chosen

        prov = PROVIDERS[self._provider]
        targets = get_target_interfaces()
        if not targets:
            self._log("[!] No internet-bearing network interface found")
            return False

        # Capture originals and journal them to disk BEFORE changing anything.
        self._original = {t["name"]: {"v4": t["v4"], "v6": t["v6"]} for t in targets}
        _write_journal(self._original)

        # Register cleanup hooks once (atexit runs on normal interpreter exit;
        # the journal covers force-kill/crash where atexit does not run).
        if not self._atexit_registered:
            try:
                atexit.register(self.stop)
                self._atexit_registered = True
            except Exception:
                pass

        success = False
        for t in targets:
            iface = t["name"]
            ok = _set_static(iface, "ip", list(prov["v4"]))
            # Only pin IPv6 DNS where the adapter actually has an IPv6 default
            # route. On an IPv4-only box, forcing an unreachable IPv6 resolver
            # makes Windows query it first and time out on every lookup — the
            # apparent "whole internet dropped" symptom. Restore still resets
            # IPv6 to the captured original (DHCP) so nothing is left pinned.
            if t.get("has_v6"):
                _set_static(iface, "ipv6", list(prov["v6"]))
            if ok:
                self._log(f"[DNS] {iface} -> {prov['v4'][0]}")
                success = True
            else:
                self._log(f"[!] Failed to set DNS: {iface}")

        if success:
            self._active = True
            _flush_dns()
            self._log(f"[DNS] {self._provider.title()} secure DNS active")
        return success

    def stop(self):
        """Restore original DNS. Idempotent — safe to call twice (stop + atexit).

        Only forget the backup (self._original + on-disk journal) once every
        interface's v4 DNS verifiably reverted. If a netsh restore fails
        (adapter transiently down/renamed, netsh timeout), KEEP both so a later
        stop()/atexit call or the next launch's restore_dns_from_journal can
        retry — deleting the only recovery record here is what could otherwise
        leave DNS pinned to the public resolver with no way back.
        """
        if not self._original:
            self._active = False
            return
        ok_all = True
        for iface, orig in self._original.items():
            v4 = orig.get("v4", [])
            v6 = orig.get("v6", [])
            r4 = _set_static(iface, "ip", v4) if v4 else _set_dhcp(iface, "ip")
            r6 = _set_static(iface, "ipv6", v6) if v6 else _set_dhcp(iface, "ipv6")
            if r4:
                self._log(f"[DNS] {iface} -> original")
            if not (r4 and r6):
                ok_all = False
                self._log(f"[!] DNS restore incomplete, will retry: {iface}")
        _flush_dns()
        self._active = False
        if ok_all:
            self._original = {}
            _clear_journal()
            self._log("[DNS] DNS restored to original settings")
        else:
            self._log("[!] DNS restore incomplete — backup kept for retry")

    def set_provider(self, provider: str):
        """Change provider. Restarts if currently active."""
        was_active = self._active
        if was_active:
            self.stop()
        self._provider = (provider or "").strip().lower()
        if was_active:
            self.start()
