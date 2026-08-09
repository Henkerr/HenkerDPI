"""Point macOS at the local proxy, and be able to undo it no matter what.

This is the only part of the macOS build that changes state outside the process,
so it is the only part that can strand a user offline. The rules it follows:

  * Read and journal the previous setting for every service BEFORE changing any
    of them, to a file in the user's own directory.
  * Restore from that journal on the next start, so a crash or a SIGKILL costs
    one restart rather than a trip to System Settings.
  * Never assume "Wi-Fi". A Mac can be on Ethernet, a Thunderbolt bridge or an
    iPhone USB tether, and the disabled services in the list are prefixed with
    an asterisk that is not part of the name.

Elevation is requested once, for a single batched script, instead of running the
whole app as root: the proxy itself needs no privileges at all, and an engine
running as root would put the user's own settings under /var/root.
"""

import json
import os
import shlex
import subprocess

from config import STATE_DIR

JOURNAL_FILE = os.path.join(STATE_DIR, "sysproxy_backup.json")

# Traffic that must never be sent to the proxy: loopback, link-local, and the
# .local names Bonjour resolves. Routing those through a userspace hop breaks
# printer discovery and captive portals for no benefit.
BYPASS_DOMAINS = ("*.local", "169.254/16", "localhost", "127.0.0.1")

_GETTERS = {
    "web": "-getwebproxy",
    "secure": "-getsecurewebproxy",
    "socks": "-getsocksfirewallproxy",
}
_SETTERS = {
    "web": ("-setwebproxy", "-setwebproxystate"),
    "secure": ("-setsecurewebproxy", "-setsecurewebproxystate"),
    "socks": ("-setsocksfirewallproxy", "-setsocksfirewallproxystate"),
}


def _run(args, timeout=15):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def list_services() -> list:
    """Every ENABLED network service, in the order macOS prefers them."""
    try:
        out = _run(["networksetup", "-listallnetworkservices"]).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    services = []
    for line in out.splitlines()[1:]:          # first line is a legend
        line = line.strip()
        # A leading asterisk marks a DISABLED service. Configuring one is not
        # an error but it is pointless, and the asterisk is not part of the
        # name, so a naive pass would fail with "service not found" anyway.
        if not line or line.startswith("*"):
            continue
        services.append(line)
    return services


def _parse_proxy(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip().lower()] = value.strip()
    return {
        "enabled": fields.get("enabled", "No").lower() == "yes",
        "server": fields.get("server", ""),
        "port": fields.get("port", "0"),
    }


def _parse_bypass(text: str) -> list:
    """The saved bypass list, or [] when the service has none.

    networksetup answers a service with no list in prose rather than with an
    empty result, and that sentence must not be stored as a domain.
    """
    domains = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("there aren't any"):
            continue
        domains.append(line)
    return domains


def read_state(service: str) -> dict:
    state = {}
    for key, flag in _GETTERS.items():
        try:
            state[key] = _parse_proxy(_run(["networksetup", flag,
                                            service]).stdout)
        except (OSError, subprocess.SubprocessError):
            state[key] = {"enabled": False, "server": "", "port": "0"}
    try:
        fields = {}
        for line in _run(["networksetup", "-getautoproxyurl",
                          service]).stdout.splitlines():
            key, _, value = line.partition(":")
            fields[key.strip().lower()] = value.strip()
        state["auto"] = {"url": fields.get("url", ""),
                         "enabled": fields.get("enabled", "No").lower() == "yes"}
    except (OSError, subprocess.SubprocessError):
        state["auto"] = {"url": "", "enabled": False}
    try:
        state["bypass"] = _parse_bypass(
            _run(["networksetup", "-getproxybypassdomains", service]).stdout)
    except (OSError, subprocess.SubprocessError):
        state["bypass"] = []
    return state


def snapshot() -> dict:
    return {svc: read_state(svc) for svc in list_services()}


def _write_journal(data: dict) -> None:
    tmp = JOURNAL_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, JOURNAL_FILE)


def _read_journal():
    try:
        with open(JOURNAL_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def clear_journal() -> None:
    try:
        os.remove(JOURNAL_FILE)
    except OSError:
        pass


def _apply_script(pac_url: str, services: list) -> str:
    """Point every service at our PAC URL.

    A PAC rather than a fixed proxy, because the two fail differently. macOS
    treats an unreachable PAC as "no proxy" and sends everything DIRECT, so if
    this app crashes the user loses the bypass and keeps the internet. A fixed
    proxy aimed at a port that stopped listening gives Chromium and every
    Electron app ERR_PROXY_CONNECTION_FAILED with no fallback — the user loses
    browsing entirely and has no way to connect the two facts.
    """
    lines = []
    for svc in services:
        q = shlex.quote(svc)
        lines.append("networksetup -setautoproxyurl %s %s"
                     % (q, shlex.quote(pac_url)))
        lines.append("networksetup -setproxybypassdomains %s %s"
                     % (q, " ".join(shlex.quote(d) for d in BYPASS_DOMAINS)))
    return "\n".join(lines)


def _restore_script(saved: dict) -> str:
    """Put every service back exactly as it was found."""
    lines = []
    for svc, state in saved.items():
        q = shlex.quote(svc)
        auto = state.get("auto") or {}
        url = auto.get("url", "")
        if url:
            lines.append("networksetup -setautoproxyurl %s %s"
                         % (q, shlex.quote(url)))
            lines.append("networksetup -setautoproxystate %s %s"
                         % (q, "on" if auto.get("enabled") else "off"))
        else:
            # There is no way to un-set a PAC URL: networksetup rejects an empty
            # one. Turning the state off is the correct restore even though the
            # stale URL stays visible in System Settings.
            lines.append("networksetup -setautoproxystate %s off" % q)

        for kind in ("web", "secure", "socks"):
            prev = state.get(kind) or {}
            setter, state_setter = _SETTERS[kind]
            server, port = prev.get("server", ""), prev.get("port", "0")
            # Put their own proxy back before deciding on/off, so a service
            # that had a configured-but-disabled proxy does not keep ours as
            # its remembered server.
            if server:
                lines.append("networksetup %s %s %s %s"
                             % (setter, q, shlex.quote(server),
                                shlex.quote(str(port))))
            lines.append("networksetup %s %s %s"
                         % (state_setter, q,
                            "on" if prev.get("enabled") else "off"))

        # Bypass domains are REPLACED, not merged, so restoring the saved list
        # matters: overwriting it drops *.local and 169.254/16 and quietly
        # breaks Bonjour, AirPlay and printer discovery.
        previous = state.get("bypass") or []
        lines.append("networksetup -setproxybypassdomains %s %s"
                     % (q, " ".join(shlex.quote(d) for d in previous)
                        if previous else "Empty"))
    return "\n".join(lines)


def _disable_script(services) -> str:
    """Take our PAC off every service without knowing what was there before.

    The last-resort path when the journal is lost: it cannot give the user back
    a proxy they had, but it does guarantee they are not left pointed at ours.
    Same set of commands as packaging/Ag Ayarlarini Geri Yukle.command.
    """
    lines = []
    for svc in services:
        q = shlex.quote(svc)
        lines.append("networksetup -setautoproxystate %s off" % q)
        lines.append("networksetup -setproxybypassdomains %s %s"
                     % (q, " ".join(shlex.quote(d) for d in BYPASS_DOMAINS)))
    return "\n".join(lines)


def run_privileged(script: str, prompt: str) -> tuple:
    """Run a shell script as root, asking the user once via the macOS dialog.

    Returns (ok, message). When already root -- the app was started with sudo --
    the script is run directly and no dialog appears.
    """
    if not script.strip():
        return True, ""
    try:
        if os.geteuid() == 0:
            done = _run(["/bin/sh", "-c", script], timeout=90)
            return done.returncode == 0, (done.stderr or "").strip()
        # osascript takes the script as an AppleScript string literal, so the
        # shell text has to survive one round of AppleScript quoting.
        literal = script.replace("\\", "\\\\").replace('"', '\\"')
        applescript = ('do shell script "%s" with prompt "%s" '
                       'with administrator privileges' % (literal, prompt))
        done = _run(["osascript", "-e", applescript], timeout=180)
        if done.returncode != 0:
            err = (done.stderr or "").strip()
            if "-128" in err:              # the user pressed Cancel
                return False, "cancelled"
            return False, err
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "timed out waiting for authorisation"
    except (OSError, AttributeError) as e:
        return False, str(e)


class SystemProxy:
    """Registers the local listener as the system proxy, reversibly."""

    def __init__(self, log=print):
        self._log = log
        self.active = False

    def restore_from_journal(self) -> bool:
        """Undo a configuration left behind by a run that did not exit cleanly."""
        saved = _read_journal()
        if not saved:
            return False
        self._log("[*] Onceki oturumdan kalan proxy ayari geri aliniyor")
        ok, err = run_privileged(
            _restore_script(saved),
            "HenkerDPI needs to restore your previous proxy settings.")
        if ok:
            clear_journal()
            self._log("[*] Proxy ayarlari geri alindi")
        else:
            self._log("[!] Geri alma basarisiz: %s" % err)
        return ok

    def apply(self, pac_url: str) -> bool:
        services = list_services()
        if not services:
            self._log("[!] Ag servisi bulunamadi")
            return False

        # Journal BEFORE changing anything. A crash between the write and the
        # change costs a harmless no-op restore; a crash the other way round
        # leaves the user proxied at a port that no longer listens.
        #
        # Write it ONCE. reload_settings() re-applies on every mode switch and
        # category toggle, and by then snapshot() reads back our own PAC — a
        # second write would record HenkerDPI's configuration as the user's
        # original settings and every later restore would faithfully reinstall
        # it, losing their real proxy and bypass list for good. An existing
        # journal is likewise left alone: if a restore failed at startup it
        # still holds the only copy of the true pre-HenkerDPI state.
        wrote_journal = False
        if not self.active and not _read_journal():
            try:
                _write_journal(snapshot())
            except OSError as e:
                self._log("[!] Yedek yazilamadi, degisiklik yapilmadi: %s" % e)
                return False
            wrote_journal = True

        ok, err = run_privileged(
            _apply_script(pac_url, services),
            "HenkerDPI needs to route this Mac's traffic through its local "
            "bypass proxy.")
        if not ok:
            if wrote_journal:
                clear_journal()
            self._log("[!] Proxy ayarlanamadi: %s"
                      % ("izin verilmedi" if err == "cancelled" else err))
            return False

        self.active = True
        self._log("[*] Sistem proxy'si acildi: %s (%s)"
                  % (pac_url, ", ".join(services)))
        return True

    def revert(self) -> bool:
        if not self.active:
            # Even so, a journal may exist from a crash earlier in this run.
            return self.restore_from_journal()
        saved = _read_journal()
        if saved:
            script = _restore_script(saved)
        else:
            # The journal is gone or unreadable, so there is nothing to restore
            # TO — but our PAC is still registered on every service and must
            # come off. Without this, _restore_script({}) returns "" and
            # run_privileged() reports success for an empty script, telling the
            # user the proxy was turned off while their Mac stays proxied.
            script = _disable_script(list_services())
            if not script:
                self._log("[!] Geri alinacak ag servisi bulunamadi")
                return False
        ok, err = run_privileged(
            script,
            "HenkerDPI needs to restore your previous proxy settings.")
        if ok:
            clear_journal()
            self.active = False
            self._log("[*] Sistem proxy'si kapatildi")
        else:
            self._log("[!] Proxy geri alinamadi: %s" % err)
        return ok
