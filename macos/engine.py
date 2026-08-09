"""The macOS engine — same contract as main.BypassEngine, different machinery.

gui.py talks to this through start()/stop()/reload_settings()/stats/running, so
the interface has to match the Windows engine even though nothing underneath it
does. What it actually runs is a local proxy, a per-network measurement of how
to reshape the handshake, one privileged call to point macOS at the proxy, and
one unprivileged call publishing it to the login session's environment for the
software that ignores macOS' proxy settings entirely (see macos/sysproxy.py).

Deliberately absent, and not oversights:

  * No system DNS changes. The proxy resolves over DoH in-process, so there is
    no resolver state to restore and the crash that leaves a Mac with no DNS
    cannot happen. This removes the whole doh.py surface from the macOS build.
  * No pf rules. Blocking UDP/443 to force QUIC onto TCP buys nothing here — a
    configured proxy already stops Chromium from trying QUIC — while the pf
    enable-reference is shared machinery that can switch off the user's own
    firewall. The cost is real and the benefit is zero, so it is not shipped.
  * No packet injection. See macos/desync.py.
"""

import atexit
import signal
import socket
import threading
import time

import dnsq
from config import load_settings, get_all_domains, MODE_ALL
from lang import t
from . import autotune_mac
from .proxy import DesyncProxy
from .sysproxy import SystemProxy

NET_WATCH_INTERVAL = 15.0
# Long enough to cover the privileged restore, including a password dialog the
# user takes their time over (run_privileged gives osascript 180s), but bounded
# so a prompt nobody ever answers cannot keep the process alive forever.
CLEANUP_LOCK_TIMEOUT = 200.0


def _still_listening(port: int, timeout: float = 0.35) -> bool:
    """Is something still accepting on this loopback port?"""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout):
            return True
    except OSError:
        return False


def is_admin() -> bool:
    """macOS never needs the app itself to be root.

    Only networksetup does, and that is elevated per-call through osascript, so
    the GUI, the proxy and every socket run as the user. gui.py calls this to
    decide whether to warn; on macOS there is nothing to warn about.
    """
    return True


class BypassEngine:
    """Local desync proxy, registered as the system proxy while it runs."""

    def __init__(self, log_callback=None, verbose: bool = False):
        self._log = log_callback or print
        self._verbose = verbose
        self._stop_event = threading.Event()
        self._retune = threading.Event()
        self._settings = load_settings()
        self._technique = autotune_mac.CANDIDATES[0]
        self._net_sig = None
        self._proxy = None
        self._sysproxy = SystemProxy(log=self._log)
        self._resolver = dnsq.DohResolver()
        self.stats = {"bypassed": 0, "passed": 0}
        self.running = False
        # Reentrant: a signal can land on a thread that is already inside
        # _cleanup, and a plain Lock would deadlock it against itself.
        self._cleaned = threading.RLock()
        self._cleanup_done = False

    # -- settings ----------------------------------------------------------
    def _snapshot(self):
        mode = self._settings.get("mode", MODE_ALL)
        domains = set(get_all_domains(self._settings))
        return mode, domains

    def reload_settings(self):
        self._settings = load_settings()
        mode = self._settings.get("mode", MODE_ALL)
        self._log("[*] Mode: %s" % mode.upper())
        # The PAC encodes the mode and the domain list, so a mode change has to
        # be re-published or the browser keeps sending the old set of hosts.
        if self._proxy is not None and self._sysproxy.active:
            self._sysproxy.apply(self._proxy.pac_url(),
                                 self._proxy.proxy_url())

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        """Run until stop() is called. Intended to be called from a thread."""
        self._stop_event.clear()
        self.stats = {"bypassed": 0, "passed": 0}
        self._settings = load_settings()

        try:
            # Heal a configuration left behind by a run that was killed. This
            # happens before anything else so a broken previous state can never
            # be snapshotted as if it were the user's own.
            self._sysproxy.restore_from_journal()

            self._proxy = DesyncProxy(
                self._resolver,
                technique=lambda: self._technique,
                settings_snapshot=self._snapshot,
                log=self._log)
            port = self._proxy.start()
            self._log("[*] Yerel proxy: 127.0.0.1:%d" % port)

            # Measure BEFORE publishing the PAC. Browsers cache a PAC result per
            # host, so traffic that arrives while the strategy is still the
            # placeholder would be reshaped the wrong way for as long as that
            # cache lives.
            self._apply_strategy()

            if not self._sysproxy.apply(self._proxy.pac_url(),
                                        self._proxy.proxy_url()):
                self._log("[!] Sistem proxy'si ayarlanamadi — motor durduruluyor")
                return

            # Only meaningful once the app is a bundle; harmless otherwise.
            atexit.register(self._cleanup)
            self._install_signal_handlers()

            self.running = True
            self._log(t("engine_active"))
            self._log("[*] Mode: %s"
                      % self._settings.get("mode", MODE_ALL).upper())

            threading.Thread(target=self._net_watch, daemon=True).start()

            while not self._stop_event.is_set():
                self._stop_event.wait(1.0)
                if self._proxy is not None:
                    self.stats["bypassed"] = self._proxy.stats["bypassed"]
                    self.stats["passed"] = self._proxy.stats["passed"]
                if self._retune.is_set():
                    self._retune.clear()
                    self._apply_strategy(force=True)

        except Exception as e:
            if not self._stop_event.is_set():
                self._log("[!] %s" % e)
        finally:
            self._cleanup()
            self.running = False
            self._log("%s | Bypass: %d"
                      % (t("engine_stopped"), self.stats["bypassed"]))

    def stop(self):
        self._stop_event.set()

    def _install_signal_handlers(self):
        """Restore on a polite kill, when we are the ones who can.

        Only ever succeeds for a headless run: signal.signal refuses to register
        from anything but the main thread, and the GUI calls start() on a worker
        — so under gui.py this is a no-op and the except below swallows it. That
        is survivable rather than broken. Cmd-Q and the window button go through
        _quit(), a SIGKILL cannot be caught by anyone, and both leftovers heal:
        the journal is replayed at the next start, and the session's proxy
        variables do not outlive the login.
        """
        def handler(signum, _frame):
            self._stop_event.set()
            self._cleanup()
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError, AttributeError):
                pass          # not on the main thread, or not supported

    def _cleanup(self):
        # Reachable from the engine thread, atexit and a signal handler at once.
        # Waiting here is the whole point. A non-blocking acquire turns "another
        # thread is restoring right now" into "skip the restore", and that is
        # precisely the quit sequence: atexit returned instantly while the
        # engine thread sat in the osascript password prompt, and interpreter
        # shutdown then froze that daemon thread mid-restore. The second caller
        # has to wait for the first to finish instead.
        if not self._cleaned.acquire(timeout=CLEANUP_LOCK_TIMEOUT):
            self._log("[!] Geri alma zaman asimina ugradi")
            return
        try:
            if self._cleanup_done:
                return
            # Order matters: the proxy setting is what takes a user offline if
            # it is left behind, so it goes first and unconditionally.
            reverted = False
            try:
                reverted = self._sysproxy.revert()
            except Exception as e:
                self._log("[!] Proxy geri alinamadi: %s" % e)
            if self._proxy is not None:
                port = self._proxy.port
                try:
                    self._proxy.stop()
                except Exception as e:
                    # Never silent. A listener that outlives the engine is the
                    # port the PAC and the environment still name, so a stop
                    # that leaves one has not stopped anything.
                    self._log("[!] Yerel proxy kapatilamadi: %s" % e)
                self._proxy = None
                if port and _still_listening(port):
                    self._log("[!] Yerel proxy hala dinliyor: %d" % port)
            # Latch only on a restore that actually happened. A cancelled
            # password prompt has to leave the next caller free to try again —
            # the user's network is still pointed at us until one succeeds.
            self._cleanup_done = reverted
        finally:
            self._cleaned.release()

    # -- strategy ----------------------------------------------------------
    def _apply_strategy(self, force: bool = False):
        technique, source = autotune_mac.resolve_technique(
            self._settings, log=self._log, force=force)
        self._technique = technique
        self._net_sig = autotune_mac.network_signature()
        self._log("[*] Strateji: %s (%s)" % (technique, source))

    def _net_watch(self):
        """Re-measure when the network changes.

        Moving between two known networks is free — the measurement is cached
        per network signature — so this only costs a scan the first time a given
        line is seen.
        """
        while not self._stop_event.wait(NET_WATCH_INTERVAL):
            try:
                signature = autotune_mac.network_signature()
            except Exception:
                continue
            if signature != self._net_sig and signature != "unknown":
                self._log("[*] Ag degisti — strateji yeniden secilecek")
                self._net_sig = signature
                self._retune.set()
