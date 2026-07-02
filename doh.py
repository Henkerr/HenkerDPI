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
import subprocess
import ctypes

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


def _state_dir() -> str:
    """A writable state dir (the frozen exe may live in read-only Program Files)."""
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "HenkerDPI")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        d = os.path.dirname(sys.executable if getattr(sys, "frozen", False)
                            else os.path.abspath(__file__))
    return d


_JOURNAL_FILE = os.path.join(_state_dir(), "dns_backup.json")


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

    Returns: [{"name": str, "v4": [ip...], "v6": [ip...]}]
    """
    script = r'''
$out = @()
Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
  Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    $ad = $_
    $cfg = Get-NetIPConfiguration -InterfaceIndex $ad.ifIndex -ErrorAction SilentlyContinue
    $gw = $null; if ($cfg -and $cfg.IPv4DefaultGateway) { $gw = $cfg.IPv4DefaultGateway.NextHop }
    if ($gw) {
      $guid = $ad.InterfaceGuid
      $v4 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
      $v6 = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$guid" -Name NameServer -ErrorAction SilentlyContinue).NameServer
      $out += [PSCustomObject]@{ name = $ad.Name; v4 = "$v4"; v6 = "$v6" }
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
                           "v6": _split_servers(item.get("v6"))})
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
    payload = {"pid": os.getpid(), "interfaces": interfaces}
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
        interfaces = data.get("interfaces") or {}
    else:  # legacy flat {iface: {...}} journal
        owner = None
        interfaces = data if isinstance(data, dict) else {}

    if owner and owner != os.getpid() and _pid_alive(owner):
        return False  # a live owner will restore on its own stop

    ok_any = False
    for iface, orig in interfaces.items():
        v4 = orig.get("v4") if isinstance(orig, dict) else orig
        v6 = orig.get("v6") if isinstance(orig, dict) else []
        r4 = _set_static(iface, "ip", v4) if v4 else _set_dhcp(iface, "ip")
        r6 = _set_static(iface, "ipv6", v6) if v6 else _set_dhcp(iface, "ipv6")
        if r4 or r6:
            ok_any = True
            log(f"[DNS] {iface} -> restored")
    _flush_dns()
    if ok_any or not interfaces:
        _clear_journal()
    return ok_any


class DohManager:
    """Redirects system DNS to a secure resolver, crash-safely."""

    def __init__(self, provider: str = "cloudflare", log_callback=None):
        self._provider = provider
        self._log = log_callback or print
        self._original = {}       # {iface: {"v4": [...], "v6": [...]}}
        self._active = False
        self._atexit_registered = False

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> bool:
        if self._provider not in PROVIDERS:
            self._log(f"[!] Unknown DNS provider: {self._provider}")
            return False

        # Heal any DNS left pinned by a previously crashed/killed run BEFORE we
        # capture originals — so we never record 1.1.1.1 as the "original".
        restore_dns_from_journal(self._log)

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
        """Restore original DNS. Idempotent — safe to call twice (stop + atexit)."""
        if not self._original:
            self._active = False
            return
        for iface, orig in self._original.items():
            v4 = orig.get("v4", [])
            v6 = orig.get("v6", [])
            if v4:
                _set_static(iface, "ip", v4)
            else:
                _set_dhcp(iface, "ip")
            if v6:
                _set_static(iface, "ipv6", v6)
            else:
                _set_dhcp(iface, "ipv6")
            self._log(f"[DNS] {iface} -> original")
        _flush_dns()
        self._original = {}
        self._active = False
        _clear_journal()
        self._log("[DNS] DNS restored to original settings")

    def set_provider(self, provider: str):
        """Change provider. Restarts if currently active."""
        was_active = self._active
        if was_active:
            self.stop()
        self._provider = provider
        if was_active:
            self.start()
