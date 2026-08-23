"""
HenkerDPI - DPI Bypass Engine
General-purpose: all sites or selected categories.
TTL-based fake packet + reverse TCP fragmentation + DoH.
"""

import sys
import time
import threading
import ctypes
import pydivert
from pydivert.consts import Flag, Param
from strategies import (extract_sni, should_bypass_fast, tcp_fragment_and_send,
                        build_icmp_port_unreachable,
                        build_icmpv6_port_unreachable,
                        DECOY_MODES, SPLIT_MODES)
from doh import DohManager, restore_dns_from_journal
from config import load_settings, get_all_domains, MODE_ALL
from lang import t
import autotune

# How often the engine checks whether it is still on the same network. A laptop
# moving from home Ethernet to a phone hotspot lands on a path whose DPI — and
# whose NAT checksum behaviour — is different, and a strategy that is right on
# one can break every HTTPS site on the other. Re-measuring on that change is
# what makes "install it and forget it" hold.
NET_WATCH_INTERVAL = 15.0


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
        # Strategy measured for the current network by autotune, or None until
        # it has run. Kept separate from the settings values so a GUI mode
        # change (which reloads settings) cannot silently undo the measurement.
        self._tuned = None
        self._retune = threading.Event()
        self._net_sig = None
        self._pending_measure = False
        # Set by the network watcher on a real change/recovery. Tells the next
        # _apply_strategy to re-pin DNS to the now-active adapter AND force a
        # fresh measurement instead of trusting the per-network cache.
        self._force_remeasure = False
        self._refresh_match_cache()
        self.stats = {"bypassed": 0, "passed": 0}
        # Recent per-ClientHello events (time, host, action) for the live UI log.
        from collections import deque
        self.events = deque(maxlen=150)
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
        # Desync knobs are read here too, so the packet loop never touches disk.
        # In the default "auto" mode the measured pair wins over whatever is in
        # settings.json; the manual values are only for a support/debug session.
        # An unknown value falls back to the default instead of silently
        # disabling the bypass.
        if self._settings.get("strategy_mode", "auto") == "auto" and self._tuned:
            decoy, split = self._tuned
        else:
            decoy = self._settings.get("decoy_mode", "badsum")
            split = self._settings.get("split_mode", "record")
        self._decoy_mode = decoy if decoy in DECOY_MODES else "badsum"
        self._split_mode = split if split in SPLIT_MODES else "record"

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
        self.events.clear()
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
                self._doh = DohManager(
                    provider=provider, log_callback=self._log,
                    system_doh=self._settings.get("system_doh_enabled", True))
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
            # Measure the line before touching traffic, then keep watching for a
            # network change. The measurement is cached per network, so this is
            # a one-off cost the first time a given network is seen.
            self._net_sig = autotune.network_signature()
            self._retune.clear()
            threading.Thread(target=self._net_watch, daemon=True).start()

            restarts = 0
            while not self._stop_event.is_set():
                self._apply_strategy()
                self._divert_loop(main_filter)
                if self._stop_event.is_set():
                    break
                if self._retune.is_set():
                    restarts = 0        # deliberate re-open, not a failure
                    continue
                # The loop returned without being asked to, i.e. the handle died
                # under us. Re-open a few times — then stop, rather than spin.
                restarts += 1
                if restarts > 3:
                    self._log("[!] Divert handle kapandi — motor duruyor")
                    break
                self._stop_event.wait(1.0)

        except Exception as e:
            if not self._stop_event.is_set():
                self._log(f"[!] {e}")
        finally:
            self._cleanup()
            self.running = False
            self._log(f"{t('engine_stopped')} | Bypass: {self.stats['bypassed']}")

    def _apply_strategy(self):
        """Pick the desync pair for the network we are on (measuring if needed).

        On the first start the cache is keyed by network, so a known line
        restores its measured pair instantly with no probing. On a real network
        change the watcher sets _force_remeasure, and we then (a) re-pin secure
        DNS to the now-active adapter and (b) force a fresh measurement instead
        of trusting the cache — a wired<->hotspot move lands on a path whose DPI,
        NAT checksum behaviour AND DNS interception all differ, so the strategy
        and the DNS pin both have to be redone. The macOS engine already forces
        the re-measure on retune; Windows now matches it.
        """
        force = self._force_remeasure
        self._force_remeasure = False
        # Consume the retune that brought us here BEFORE measuring. If the
        # network changes again mid-measurement the watcher re-arms both flags,
        # so the divert loop re-enters and re-measures instead of running the
        # strategy we just picked for the network we already left.
        self._retune.clear()
        if force:
            self._reapply_dns()
        try:
            decoy, split, source = autotune.resolve_strategy(
                self._settings, self._log, force=force)
            self._tuned = (decoy, split)
            self._refresh_match_cache()
            # Booting before the link is up is normal for the autostart task:
            # remember that this network was never actually measured, so the
            # watcher can measure it as soon as there is a way out.
            self._pending_measure = (source == "offline")
            if source != "onbellek":
                self._log(f"[*] Strateji: {self._decoy_mode}/{self._split_mode}")
        except Exception as e:
            # A failed measurement must never stop the engine. Only autotune's own
            # fallback can tell a NAT line from a fixed one (it can still reach the
            # control sites); a bare exception here cannot, so it must not hard-pin
            # badseq — that is exactly what leaves a fixed home line unable to open
            # Discord. Fall back to the settings default (badsum/record), which is
            # safe on a fixed line — the common case — and gets corrected by the
            # next network-change re-measure.
            self._tuned = (self._settings.get("decoy_mode", "badsum"),
                           self._settings.get("split_mode", "record"))
            self._refresh_match_cache()
            self._log(f"[!] Otomatik strateji secimi basarisiz ({e}) — varsayilan")

    def _reapply_dns(self):
        """Re-pin secure DNS to the adapter that is now the default route.

        DohManager pins the interfaces it finds when it STARTS; after a
        wired->hotspot switch the new adapter is still on the carrier resolver
        (which on a blocking ISP hijacks the very domains we are bypassing) until
        we redo the setup. stop() restores the old adapter from the journal and
        is idempotent, so at worst this is a no-op — never worse than leaving the
        stale pin on a now-dead adapter.
        """
        if not self._settings.get("doh_enabled", True):
            return
        try:
            if self._doh and self._doh.active:
                self._doh.stop()
            provider = self._settings.get("doh_provider", "cloudflare")
            self._doh = DohManager(
                provider=provider, log_callback=self._log,
                system_doh=self._settings.get("system_doh_enabled", True))
            self._doh.start()
        except Exception as e:
            self._log(f"[!] DNS yeniden uygulanamadi ({e})")

    def _net_watch(self):
        """Notice a network change and force a re-measure.

        Closing the main handle is what unblocks the recv() in the packet loop;
        the loop then falls back to the outer while, re-measures and reopens.
        """
        while not self._stop_event.wait(NET_WATCH_INTERVAL):
            try:
                sig = autotune.network_signature()
            except Exception:
                continue
            changed = sig != "unknown" and sig != self._net_sig
            # The network can come back without its fingerprint changing (link
            # was up, the line was not). Measure as soon as there is a way out.
            recovered = (not changed and self._pending_measure
                         and sig != "unknown" and autotune.online())
            if not changed and not recovered:
                continue
            if changed:
                self._net_sig = sig
                self._log("[*] Ag degisti — DNS ve strateji yeniden uygulaniyor")
            else:
                self._pending_measure = False
                self._log("[*] Baglanti geldi — strateji olculuyor")
            # Re-pin DNS to the new adapter and re-measure from scratch, not from
            # the cache: the pair that is right on the line we just left can be
            # exactly the one that breaks this one.
            self._force_remeasure = True
            self._retune.set()
            handle = self._main_handle
            if handle is not None:
                try:
                    if handle.is_open:
                        handle.close()
                except Exception:
                    pass

    def _divert_loop(self, main_filter: str):
        """Open the main handle and process ClientHellos until stop or re-tune."""
        try:
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

            while not self._stop_event.is_set() and not self._retune.is_set():
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
                            if tcp_fragment_and_send(self._main_handle, packet, sni,
                                                     self._verbose,
                                                     self._decoy_mode,
                                                     self._split_mode):
                                self.stats["bypassed"] += 1
                                self.events.append((time.time(), sni, "bypass"))
                                # In ALL mode, log every 50th bypass to reduce noise
                                if self._mode == MODE_ALL:
                                    if self.stats["bypassed"] % 50 == 1:
                                        self._log(f"[BYPASS] {sni} (+{min(self.stats['bypassed'], 50)})")
                                else:
                                    self._log(f"[BYPASS] {sni}")
                                continue
                        elif sni:
                            self.events.append((time.time(), sni, "pass"))

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
            # A re-tune closes the handle under us on purpose; that is not an
            # error worth showing, and it must not stop the engine.
            if not self._stop_event.is_set() and not self._retune.is_set():
                self._log(f"[!] {e}")
                raise
        finally:
            handle, self._main_handle = self._main_handle, None
            if handle is not None:
                try:
                    if handle.is_open:
                        handle.close()
                except Exception:
                    pass

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
    _mx = ctypes.windll.kernel32.CreateMutexW(None, True, "Global\\HenkerDPI_SingleInstance")
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        print("HenkerDPI is already running.")
        sys.exit(0)

    # Heal DNS left pinned by a previous crashed/force-killed run before starting.
    restore_dns_from_journal()

    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    engine = BypassEngine(verbose=verbose)

    try:
        engine.start()
    except KeyboardInterrupt:
        engine.stop()
