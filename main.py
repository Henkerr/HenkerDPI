"""
HenkerDPI V2 - DPI Bypass Engine
General-purpose: all sites or selected categories.
TTL-based fake packet + reverse TCP fragmentation + DoH.
"""

import sys
import threading
import ctypes
import pydivert
from pydivert.consts import Flag, Param
from strategies import (extract_sni, should_bypass_fast, tcp_fragment_and_send,
                        build_icmp_port_unreachable,
                        build_icmpv6_port_unreachable)
from doh import DohManager, restore_dns_from_journal
from config import load_settings, get_all_domains, MODE_ALL
from lang import t


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class BypassEngine:
    """Thread-safe DPI bypass engine — V2."""

    def __init__(self, log_callback=None, verbose: bool = False):
        self._log = log_callback or print
        self._verbose = verbose
        self._stop_event = threading.Event()
        self._rst_drop = None
        self._quic_drop = None
        self._quic_thread = None
        self._main_handle = None
        self._doh = None
        self._settings = load_settings()
        self._mode = MODE_ALL
        self._domain_set = set()
        self._refresh_match_cache()
        self.stats = {"bypassed": 0, "passed": 0}
        self.running = False

    def _refresh_match_cache(self):
        """Precompute (mode, domain_set) so the packet loop does no disk I/O.

        In selective mode the domain set is built once here instead of
        rebuilding the list and re-reading custom_domains.json per packet.
        """
        self._mode = self._settings.get("mode", MODE_ALL)
        if self._mode == MODE_ALL:
            self._domain_set = set()
        else:
            self._domain_set = set(get_all_domains(self._settings))

    def reload_settings(self):
        """Reload settings (called when mode changes from GUI)."""
        self._settings = load_settings()
        self._refresh_match_cache()
        # Keep the QUIC-drop handle in sync with the new mode: switching
        # ALL->SELECTIVE must CLOSE the system-wide UDP/443 drop (else it keeps
        # killing QUIC for traffic we are not bypassing), and SELECTIVE->ALL
        # must OPEN it. Only meaningful while the engine is actually running.
        if self.running:
            self._sync_quic_handle()
        self._log(f"[*] Mode: {self._mode.upper()}")

    def _sync_quic_handle(self):
        """Open or close the QUIC refuser to match the current mode+settings.

        We do NOT silently DROP QUIC anymore: a black-holed UDP/443 makes
        HTTP/3-preferring apps (Chromium, Electron/Discord) wait out a long QUIC
        timeout before falling back to TCP — the ~1-minute Discord-reconnect
        symptom. Instead we intercept only the QUIC Initial (long-header) and
        answer it locally with an ICMP port-unreachable, so the client abandons
        QUIC at once and switches to the TCP path our fragmentation bypasses.
        """
        want = (self._settings.get("quic_drop_enabled", True) and
                (self._mode == MODE_ALL or
                 not self._settings.get("quic_drop_all_mode_only", True)))
        if want and self._quic_drop is None:
            try:
                # Match only long-header QUIC packets (Initial/Handshake — the
                # Header Form bit is set, so the first byte is >= 0x80). 1-RTT
                # data never appears once the Initial is refused, so the
                # userspace refuser sees only a handful of packets. (WinDivert's
                # filter language has no bitwise AND, hence the >= 0x80 form.)
                h = pydivert.WinDivert(
                    "outbound and udp and udp.DstPort == 443 and "
                    "udp.PayloadLength > 0 and udp.Payload[0] >= 0x80",
                    priority=999)
                h.open()
                self._quic_drop = h
                self._quic_thread = threading.Thread(
                    target=self._quic_refuse_loop, args=(h,), daemon=True)
                self._quic_thread.start()
            except Exception:
                self._quic_drop = None
                self._quic_thread = None
        elif not want and self._quic_drop is not None:
            self._close_quic_handle()

    def _close_quic_handle(self):
        """Close the QUIC handle (unblocks recv → the refuser thread exits)."""
        h = self._quic_drop
        self._quic_drop = None
        if h is not None:
            try:
                if h.is_open:
                    h.close()
            except Exception:
                pass
        th = self._quic_thread
        self._quic_thread = None
        if th is not None and th is not threading.current_thread():
            th.join(timeout=2)

    def _quic_refuse_loop(self, handle):
        """Answer each outbound QUIC Initial with a local ICMP port-unreachable.

        The original datagram is not re-injected, so QUIC never leaves the host
        (its SNI is not exposed) and the client falls straight back to TCP.
        Non-IPv4/UDP packets are forwarded untouched; on any error we forward
        rather than black-hole.
        """
        # IPv6 QUIC is only refused when the experimental IPv6 bypass is on;
        # captured once so the default (IPv4-only) path stays byte-for-byte
        # identical to before.
        ipv6_on = self._settings.get("ipv6_bypass_enabled", False)
        while True:
            try:
                pkt = handle.recv()
            except Exception:
                break  # handle closed
            try:
                ver = pkt.raw[0] >> 4
                if ver == 4:
                    icmp = build_icmp_port_unreachable(pkt)
                elif ver == 6 and ipv6_on:
                    icmp = build_icmpv6_port_unreachable(pkt)
                else:
                    icmp = None
                if icmp is not None:
                    handle.send(icmp)   # inbound → local socket sees ECONNREFUSED
                    # original NOT re-sent → QUIC Initial is dropped
                else:
                    handle.send(pkt)    # forwarded untouched
            except Exception:
                try:
                    handle.send(pkt)
                except Exception:
                    pass

    def start(self):
        """Run bypass loop. Call from a separate thread."""
        self._stop_event.clear()
        self.stats = {"bypassed": 0, "passed": 0}
        self._settings = load_settings()
        self._refresh_match_cache()

        mode = self._mode
        self.running = True
        self._log(t("engine_active"))
        self._log(f"[*] Mode: {mode.upper()}")

        # Everything that alters system state is opened INSIDE the try so the
        # finally/_cleanup path always restores it — even if a later open()
        # raises. _cleanup() closes handles AND restores DNS.
        try:
            # Heal any DNS left pinned by a previously crashed/killed run.
            restore_dns_from_journal(self._log)

            # Secure DNS (crash-safe; restored by _cleanup on ANY exit).
            if self._settings.get("doh_enabled", True):
                provider = self._settings.get("doh_provider", "cloudflare")
                self._doh = DohManager(provider=provider, log_callback=self._log)
                self._doh.start()

            # Kernel DROP: DPI-injected RST packets. OFF by default — blanket
            # dropping every inbound RST on 443/80 also swallows LEGITIMATE
            # server/load-balancer resets, leaving half-open sockets that hang
            # until TCP timeout (a cause of the intermittent stalls). Opt-in for
            # users whose DPI relies on RST injection.
            if self._settings.get("rst_drop_enabled", False):
                self._rst_drop = pydivert.WinDivert(
                    "inbound and tcp and tcp.Rst and "
                    "(tcp.SrcPort == 443 or tcp.SrcPort == 80)",
                    priority=1000, flags=Flag.DROP
                )
                self._rst_drop.open()
                self._log("[*] RST drop: ON")

            # QUIC DROP — force TCP fallback so the TLS bypass can act. Only in
            # ALL mode by default; in selective mode a system-wide UDP/443 kill
            # is pure collateral for the traffic we are not bypassing. Opened
            # here and kept in sync with runtime mode changes by reload_settings.
            self._sync_quic_handle()

            # Main filter — kernel-side ClientHello selection. Only TLS
            # handshake ClientHello packets (record type 0x16, handshake type
            # 0x01 at payload offset 5) are diverted to userspace; every other
            # 443 packet stays in the kernel fast-path untouched. This is the
            # key performance/reliability fix: the userspace loop now sees a
            # handful of packets/sec instead of every outbound data packet, so
            # it can no longer fall behind and force silent kernel drops.
            # Locality clause. Default is the proven IPv4-only path. With the
            # experimental IPv6 bypass enabled we ALSO divert IPv6 ClientHellos;
            # the field is `ipv6.DstAddr` (NOT `ip6.DstAddr`, which the WinDivert
            # compiler rejects with ERROR_INVALID_PARAMETER and would abort the
            # handle open, killing engine start).
            if self._settings.get("ipv6_bypass_enabled", False):
                loc = ("((ip and ip.DstAddr != 127.0.0.1) or "
                       "(ipv6 and ipv6.DstAddr != ::1))")
            else:
                loc = "ip.DstAddr != 127.0.0.1"
            main_filter = (
                "outbound and tcp and tcp.DstPort == 443 and "
                "tcp.PayloadLength > 5 and "
                "tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01 and "
                + loc
            )
            self._main_handle = pydivert.WinDivert(main_filter)
            self._main_handle.open()
            # Safety-net queue sizing for ClientHello bursts (a page opening
            # dozens of TLS connections at once). Wrapped so a value the driver
            # rejects can never crash start().
            for _param, _value in ((Param.QUEUE_LEN, 8192),
                                   (Param.QUEUE_TIME, 4000),
                                   (Param.QUEUE_SIZE, 16 * 1024 * 1024)):
                try:
                    self._main_handle.set_param(_param, _value)
                except Exception:
                    pass

            while not self._stop_event.is_set():
                try:
                    packet = self._main_handle.recv()
                except Exception:
                    break  # handle closed

                try:
                    payload = packet.payload
                    if not payload:
                        self._main_handle.send(packet)
                        self.stats["passed"] += 1
                        continue

                    # The kernel filter already guarantees this is a ClientHello
                    # record. extract_sni returns None if the SNI value straddles
                    # a TCP segment boundary (multi-segment ClientHello), so we
                    # forward that segment untouched — a partial handshake is
                    # never split. A large modern ClientHello whose SNI IS present
                    # in this first segment (the common post-quantum-TLS case) is
                    # still fragmented at the SNI; trailing segments flow normally
                    # and the server reassembles correctly.
                    if len(payload) > 5 and payload[0] == 0x16:
                        sni = extract_sni(payload)
                        if sni and should_bypass_fast(sni, self._mode, self._domain_set):
                            if tcp_fragment_and_send(self._main_handle, packet, sni, self._verbose):
                                self.stats["bypassed"] += 1
                                # In ALL mode, log every 50th bypass to reduce noise
                                if self._mode == MODE_ALL:
                                    if self.stats["bypassed"] % 50 == 1:
                                        self._log(f"[BYPASS] {sni} (+{min(self.stats['bypassed'], 50)})")
                                else:
                                    self._log(f"[BYPASS] {sni}")
                                continue

                    self._main_handle.send(packet)
                    self.stats["passed"] += 1
                except Exception:
                    if self._stop_event.is_set():
                        break
                    # Never drop a packet on an unexpected error — forward it
                    # so the connection degrades to passthrough instead of
                    # hanging (the "site won't open sometimes" symptom).
                    try:
                        self._main_handle.send(packet)
                    except Exception:
                        pass

        except Exception as e:
            if not self._stop_event.is_set():
                self._log(f"[!] {e}")
        finally:
            self._cleanup()
            self.running = False
            self._log(f"{t('engine_stopped')} | Bypass: {self.stats['bypassed']}")

    def stop(self):
        """Stop bypass (thread-safe)."""
        self._stop_event.set()
        # Stop DoH — restore original DNS
        if self._doh and self._doh.active:
            self._doh.stop()
            self._doh = None
        # Close handle to break recv() blocking
        if self._main_handle and self._main_handle.is_open:
            try:
                self._main_handle.close()
            except Exception:
                pass

    def _cleanup(self):
        # Close the QUIC refuser first so its worker thread is stopped/joined.
        self._close_quic_handle()
        for handle in (self._main_handle, self._rst_drop):
            if handle:
                try:
                    if handle.is_open:
                        handle.close()
                except Exception:
                    pass
        self._main_handle = None
        self._rst_drop = None
        # Crash-safety: restore DNS on ANY exit from the loop (an internal
        # exception, or the GUI daemon thread dying), not just an explicit
        # stop(). DohManager.stop() is idempotent, so a later stop() is a no-op.
        if self._doh and self._doh.active:
            try:
                self._doh.stop()
            except Exception:
                pass
        self._doh = None


if __name__ == "__main__":
    if not is_admin():
        print(t("admin_required"))
        sys.exit(1)

    # Single-instance guard sharing the GUI's machine-wide mutex name, so a
    # standalone `python main.py` engine cannot run alongside the GUI's engine
    # and race the shared DNS journal. Global\ also blocks another user session.
    _mx = ctypes.windll.kernel32.CreateMutexW(None, True, "Global\\HenkerDPI_V2_SingleInstance")
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        print("HenkerDPI V2 is already running.")
        sys.exit(0)

    # Heal DNS left pinned by a previous crashed/force-killed run before starting.
    restore_dns_from_journal()

    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    engine = BypassEngine(verbose=verbose)

    try:
        engine.start()
    except KeyboardInterrupt:
        engine.stop()
