"""
HenkerDPI - DPI Bypass Engine
General-purpose: all sites or selected categories.
TTL-based fake packet + reverse TCP fragmentation + DoH.
"""

import sys
import socket
import time
import threading
import ctypes
import pydivert
from pydivert.consts import Flag, Param
from strategies import (extract_sni, should_bypass_fast, tcp_fragment_and_send,
                        is_partial_hello, fragment_partial_hello,
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

# Health check of the running bypass. A user who sees Discord drop and come back
# only after restarting the app is hitting a state the engine got into and never
# left (a DNS pin lost on a re-pin, a dead refuser thread, a strategy measured
# during a network blip). Every HEALTH_INTERVAL the engine opens a real handshake
# to HEALTH_HOST through itself. Two failed rounds in a row while the line is up
# trigger a heal. The first heal does exactly what a restart does — re-pin DNS
# and reopen the handles, strategy from the cache — so it costs no measurement
# gap. Only if that did not help does the next heal also re-measure the line.
#
# A heal that did not help doubles the wait before the next one, up to
# HEAL_COOLDOWN_MAX. On a line where Discord cannot open for reasons no heal
# fixes (a school firewall, an IP block, a Discord outage) the engine must not
# keep pausing the bypass and churning DNS all day.
HEALTH_INTERVAL = 90.0
HEALTH_FAILS_TO_HEAL = 2
HEAL_COOLDOWN = 600.0
HEAL_COOLDOWN_MAX = 6 * 3600.0
HEALTH_HOST = "discord.com"

# A divert loop that stayed up this long was healthy; its death is a fresh
# incident, not the next strike of the same one.
LOOP_HEALTHY_AFTER = 60.0
# A main handle that has not opened once in this many tries is not a glitch
# (the driver is blocked or missing): stop and let the app show the engine off.
FIRST_OPEN_TRIES = 3


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
        # The QUIC handle is opened/closed from the engine, health and IPC
        # threads; without this two of them could each open one and the
        # untracked handle would outlive stop().
        self._quic_lock = threading.RLock()
        self._main_handle = None
        self._main_opened = False
        self._doh = None
        self._settings = load_settings()
        self._mode = MODE_ALL
        self._domain_set = set()
        # Strategy measured for the current network by autotune, or None until
        # it has run. Kept separate from the settings values so a GUI mode
        # change (which reloads settings) cannot silently undo the measurement.
        self._tuned = None
        # Whether the active line has a global IPv6 egress. When it does, the
        # engine also bypasses IPv6 ClientHellos and refuses IPv6 QUIC, so a
        # dual-stack banned site (which Windows reaches over its preferred IPv6)
        # is handled instead of being left to the DPI. Recomputed on every
        # (re)tune so moving to an IPv6-less line drops back to the IPv4 path.
        self._ipv6_active = False
        self._retune = threading.Event()
        self._net_sig = None
        self._pending_measure = False
        # Set by the network watcher on a real change/recovery, and by a heal.
        # _reset_dns tells the next _apply_strategy to re-pin DNS to the active
        # adapter and reopen the QUIC refuser; _force_remeasure additionally
        # makes it measure instead of trusting the per-network cache.
        self._reset_dns = False
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
        with self._quic_lock:
            # Never (re)open while the engine is stopping or stopped: _cleanup
            # would have already closed the handle it knows about.
            if (want and self._quic_drop is None and self.running and
                    not self._stop_event.is_set()):
                try:
                    # Match only long-header QUIC packets (Initial/Handshake —
                    # the Header Form bit is set, so the first byte is >= 0x80).
                    # 1-RTT data never appears once the Initial is refused, so
                    # the userspace refuser sees only a handful of packets.
                    # (WinDivert's filter language has no bitwise AND, hence
                    # the >= 0x80 form.)
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
                return
        if not want and self._quic_drop is not None:
            self._close_quic_handle()

    def _close_quic_handle(self):
        """Close the QUIC handle (unblocks recv → the refuser thread exits)."""
        with self._quic_lock:
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
        # Joined outside the lock: the exiting refuser takes it too.
        if th is not None and th is not threading.current_thread():
            th.join(timeout=2)

    def _quic_refuse_loop(self, handle):
        """Answer each outbound QUIC Initial with a local ICMP port-unreachable.

        The original datagram is not re-injected, so QUIC never leaves the host
        (its SNI is not exposed) and the client falls straight back to TCP.
        Non-IPv4/UDP packets are forwarded untouched; on any error we forward
        rather than black-hole.
        """
        # IPv6 QUIC is refused only when the IPv6 bypass is active for this line
        # (a global IPv6 egress, or the experimental flag). Refusing it forces
        # HTTP/3-over-IPv6 down to IPv6 TCP, which is where the IPv6 TLS bypass
        # acts; leaving it would let a dual-stack site ride unbypassed QUIC. On
        # an IPv4-only line this stays False and the path is unchanged.
        ipv6_on = self._ipv6_active
        seen = {}                       # dst addr -> last time we logged an engel
        LOG_TTL = 12.0                  # dedup window for the live-log entries
        while True:
            try:
                pkt = handle.recv()
            except Exception:
                # Closed by us (_close_quic_handle clears _quic_drop first), or
                # it died under us. In the latter case the handle may still be
                # diverting QUIC Initials into a queue nobody reads — the silent
                # black-hole that makes Discord wait out a QUIC timeout. Fail
                # open; the health check reopens it.
                with self._quic_lock:
                    died = self._quic_drop is handle
                    if died:
                        self._quic_drop = None
                        self._quic_thread = None
                try:
                    if handle.is_open:
                        handle.close()
                except Exception:
                    pass
                if died and not self._stop_event.is_set():
                    self._log("[!] QUIC yakalayici durdu — kapatildi, yeniden acilacak")
                break
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
                    # Real "engel" event for the live UI: this QUIC attempt was
                    # refused, so the app falls back to the TCP path the bypass
                    # can act on. Deduped per destination — Chromium re-probes
                    # QUIC constantly, and an unthrottled entry per probe would
                    # flood the 150-slot ring and evict the bypass lines.
                    try:
                        dst = pkt.dst_addr
                        now = time.time()
                        if now - seen.get(dst, 0.0) > LOG_TTL:
                            seen[dst] = now
                            self.events.append((now, dst, "block"))
                            if len(seen) > 512:   # bound the dedup table
                                seen = {k: v for k, v in seen.items()
                                        if now - v < LOG_TTL}
                    except Exception:
                        pass
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
        # The watchers belong to THIS run. start() can return without stop()
        # (the driver never opened) and be called again on the same object;
        # a watcher still tied to _stop_event would then outlive its run, keep
        # reopening handles on a stopped engine and double every heal.
        run_over = threading.Event()
        self._reset_dns = self._force_remeasure = False
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
            # Decide IPv6 first so the refuser opened here already knows whether
            # to refuse IPv6 QUIC too (else it would take a retune to catch up).
            self._recompute_ipv6()
            self._sync_quic_handle()

            # Measure the line before touching traffic, then keep watching for a
            # network change. The measurement is cached per network, so this is
            # a one-off cost the first time a given network is seen.
            self._net_sig = autotune.network_signature()
            self._retune.clear()
            threading.Thread(target=self._net_watch, args=(run_over,),
                             daemon=True).start()
            threading.Thread(target=self._health_watch, args=(run_over,),
                             daemon=True).start()

            restarts = 0
            self._main_opened = False
            while not self._stop_event.is_set():
                self._apply_strategy()
                opened = time.time()
                # The filter is rebuilt each iteration from the current line's
                # IPv6 state (set by _apply_strategy): a retune onto a dual-stack
                # line starts diverting IPv6 ClientHellos, and a move back to an
                # IPv4-only line drops the IPv6 clause again.
                self._divert_loop(self._build_main_filter())
                if self._stop_event.is_set():
                    break
                if self._retune.is_set():
                    restarts = 0        # deliberate re-open, not a failure
                    continue
                restarts += 1
                # A handle that never opened in this start is not a glitch: the
                # driver is blocked or missing. Stop, so the app shows the engine
                # off instead of "on" with no bypass.
                if not self._main_opened and restarts >= FIRST_OPEN_TRIES:
                    self._log("[!] Divert handle hic acilamadi — motor duruyor")
                    break
                # The handle died under us after working. Never give up: an
                # engine that stops here leaves the app looking "on" with no
                # bypass until the user restarts it. Back off instead, and treat
                # a loop that ran for a while as healthy so strikes spread over
                # days do not add up.
                if time.time() - opened > LOOP_HEALTHY_AFTER:
                    restarts = 1
                wait = min(30.0, 2.0 ** restarts)
                self._log("[!] Divert handle kapandi — %.0f sn sonra yeniden aciliyor"
                          % wait)
                self._stop_event.wait(wait)

        except Exception as e:
            if not self._stop_event.is_set():
                self._log(f"[!] {e}")
        finally:
            run_over.set()
            # Not running from here on, so nothing reopens a handle that
            # _cleanup is about to close.
            self.running = False
            self._cleanup()
            self._log(f"{t('engine_stopped')} | Bypass: {self.stats['bypassed']}")

    def _recompute_ipv6(self):
        """Set _ipv6_active from the experimental flag OR a real IPv6 egress.

        The explicit `ipv6_bypass_enabled` setting forces it on (support/debug).
        Otherwise it follows the line: a global IPv6 default route means
        dual-stack banned sites would be reached over IPv6, which the IPv4-only
        path never touches, so the engine turns the IPv6 bypass on for that line.
        """
        try:
            want = (self._settings.get("ipv6_bypass_enabled", False)
                    or autotune.has_ipv6_default())
        except Exception:
            want = self._settings.get("ipv6_bypass_enabled", False)
        if want != self._ipv6_active:
            self._ipv6_active = want
            self._log("[*] IPv6 bypass: %s" % ("ON" if want else "OFF"))

    def _build_main_filter(self) -> str:
        """Kernel-side ClientHello selection filter for the current line.

        Only TLS handshake ClientHello packets (record type 0x16, handshake
        type 0x01 at payload offset 5) are diverted to userspace; every other
        443 packet stays in the kernel fast-path untouched — the performance fix
        that keeps the userspace loop seeing a handful of packets/sec.

        The IPv4-only clause is the long-proven path. On a line with IPv6 egress
        we ALSO divert IPv6 ClientHellos; the field is `ipv6.DstAddr` (NOT
        `ip6.DstAddr`, which the WinDivert compiler rejects with
        ERROR_INVALID_PARAMETER, aborting the handle open and killing start()).
        """
        if self._ipv6_active:
            loc = ("((ip and ip.DstAddr != 127.0.0.1) or "
                   "(ipv6 and ipv6.DstAddr != ::1))")
        else:
            loc = "ip.DstAddr != 127.0.0.1"
        return (
            "outbound and tcp and tcp.DstPort == 443 and "
            "tcp.PayloadLength > 5 and "
            "tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01 and "
            + loc
        )

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
        reset = self._reset_dns or force
        self._force_remeasure = False
        self._reset_dns = False
        # Decide IPv6 for the line we are on now, so the filter this iteration
        # builds and the QUIC refuser this reset reopens both match it.
        self._recompute_ipv6()
        # Consume the retune that brought us here BEFORE measuring. If the
        # network changes again mid-measurement the watcher re-arms both flags,
        # so the divert loop re-enters and re-measures instead of running the
        # strategy we just picked for the network we already left.
        self._retune.clear()
        if reset:
            self._reapply_dns()
            # Reopen the QUIC refuser too, so a network change or a heal leaves
            # nothing from the old state behind — the same as a restart would.
            self._close_quic_handle()
            self._sync_quic_handle()
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

    def _net_watch(self, run_over):
        """Notice a network change and force a re-measure."""
        while not run_over.wait(NET_WATCH_INTERVAL):
            try:
                sig = autotune.network_signature()
            except Exception:
                continue
            if run_over.is_set():
                break
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
            if run_over.is_set():       # online() outlived this run
                break
            # Re-pin DNS to the new adapter and re-measure from scratch, not from
            # the cache: the pair that is right on the line we just left can be
            # exactly the one that breaks this one.
            self._request_reset(remeasure=True)

    def _request_reset(self, remeasure: bool):
        """Ask the engine loop to re-pin DNS and reopen its handles, and with
        remeasure=True also to measure the line instead of using the cache.

        Closing the main handle is what unblocks the recv() in the packet loop;
        the loop then falls back to the outer while and runs _apply_strategy.
        """
        self._reset_dns = True
        if remeasure:
            self._force_remeasure = True
        self._retune.set()
        handle = self._main_handle
        if handle is not None:
            try:
                if handle.is_open:
                    handle.close()
            except Exception:
                pass

    def _health_watch(self, run_over):
        """Heal the engine when the bypass stops working while the line is up.

        This does automatically what the user otherwise does by restarting the
        app. It only acts on evidence: HEALTH_HOST must fail through the live
        engine in HEALTH_FAILS_TO_HEAL consecutive rounds while the line itself
        is up, so a real outage is left to the net watcher.

        Heals escalate. The first is a restart's worth (DNS + handles, strategy
        from the cache). If Discord is still down at the next heal, that one
        also re-measures the line. Every heal that did not bring Discord back
        doubles the wait before the next, up to HEAL_COOLDOWN_MAX; one good
        round, or a move to another network, resets all of it.
        """
        fails = 0
        heals = 0                       # heals since Discord last opened
        cooldown = HEAL_COOLDOWN
        next_heal = 0.0
        net = self._net_sig
        while not run_over.wait(HEALTH_INTERVAL):
            if self._net_sig != net:    # a new line gets a fresh, prompt first heal
                net = self._net_sig
                fails, heals, cooldown, next_heal = 0, 0, HEAL_COOLDOWN, 0.0
            try:
                # A refuser that failed open is reopened here, not left off.
                if self._quic_drop is None:
                    self._sync_quic_handle()
                # Measuring / reopening right now, or this host is not one we
                # bypass (selective mode without the Discord category).
                if (self._main_handle is None or self._retune.is_set() or
                        not should_bypass_fast(HEALTH_HOST, self._mode,
                                               self._domain_set)):
                    fails = 0
                    continue
                alive = self._bypass_alive()
            except Exception:
                continue
            if run_over.is_set():       # the probe outlived its run
                break
            if alive is None:           # no internet at all — not ours to fix
                fails = 0
                continue
            if alive:
                if heals:
                    self._log("[*] %s yeniden aciliyor" % HEALTH_HOST)
                fails, heals, cooldown, next_heal = 0, 0, HEAL_COOLDOWN, 0.0
                continue
            fails += 1
            if fails < HEALTH_FAILS_TO_HEAL or time.time() < next_heal:
                continue
            fails = 0
            if heals:                   # the last heal did not help
                cooldown = min(cooldown * 2, HEAL_COOLDOWN_MAX)
            heals += 1
            next_heal = time.time() + cooldown
            remeasure = heals > 1
            self._log("[!] %s motor uzerinden acilmiyor — %s yenileniyor "
                      "(sonraki deneme en erken %.0f dk sonra)"
                      % (HEALTH_HOST,
                         "DNS ve strateji" if remeasure else "DNS ve baglanti",
                         cooldown / 60))
            self._request_reset(remeasure=remeasure)

    def _bypass_alive(self):
        """True if HEALTH_HOST handshakes through the engine, False if it does
        not while the line is up, None if the line itself is down.

        It resolves through the SYSTEM resolver, like the Discord app does, so a
        lost DNS pin shows up here as well as a wrong strategy. Whether the line
        is up is asked with a bare TCP connect (autotune.online), which carries
        no ClientHello and so never passes through the engine's desync: an
        engine state that breaks every HTTPS site must count as ours to heal,
        not as "no internet".
        """
        try:
            ip = socket.getaddrinfo(HEALTH_HOST, 443, socket.AF_INET,
                                    socket.SOCK_STREAM)[0][4][0]
        except Exception:
            ip = None
        if ip and (autotune.tls_reachable(ip, HEALTH_HOST) or
                   autotune.tls_reachable(ip, HEALTH_HOST)):
            return True
        return False if autotune.online() else None

    def _divert_loop(self, main_filter: str):
        """Open the main handle and process ClientHellos until stop or re-tune."""
        try:
            self._main_handle = pydivert.WinDivert(main_filter)
            self._main_handle.open()
            self._main_opened = True
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
                            # IPv6 uses a decoy-FREE record split, never the
                            # IPv4-measured decoy. A decoy is only needed to
                            # poison a DPI that reassembles; on IPv6 the record
                            # split alone gets the SNI past (measured), and a
                            # decoy-free reshape carries no fake packet, so it
                            # cannot be "repaired" into a valid one and break
                            # other sites. That keeps IPv6 safe on any line
                            # without a separate IPv6 measurement.
                            if (packet.raw[0] >> 4) == 6:
                                decoy, split = "off", "record"
                            else:
                                decoy, split = self._decoy_mode, self._split_mode
                            if tcp_fragment_and_send(self._main_handle, packet, sni,
                                                     self._verbose,
                                                     decoy, split):
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
                        elif sni is None and is_partial_hello(payload):
                            # A ClientHello whose SNI fell into a LATER TCP
                            # segment (Chromium's ~1.8 KB post-quantum hello on a
                            # ~1400-byte MSS path lands the hostname in segment 2
                            # about half the time). The kernel filter only hands
                            # us this first segment; forwarded whole, a DPI that
                            # reassembles reads the hostname from the next segment
                            # and resets the flow (measured on a mobile carrier).
                            # We cannot know the hostname to gate on, so this runs
                            # in every mode — but it carries NO decoy and keeps the
                            # original TTL, only reordering this segment's own real
                            # bytes, so the server reassembles them and a
                            # non-bypassed site cannot be harmed.
                            if fragment_partial_hello(self._main_handle, packet):
                                self.stats["bypassed"] += 1
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
            # A re-tune closes the handle under us on purpose; that is not an
            # error worth showing. Anything else (e.g. the handle would not
            # open) is logged and handed back to start(), which retries with
            # backoff — raising here used to stop the engine for good.
            if not self._stop_event.is_set() and not self._retune.is_set():
                self._log(f"[!] {e}")
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
