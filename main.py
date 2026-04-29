"""
HenkerDPI V2 - DPI Bypass Engine
Genel amaçlı: tüm siteler veya seçili kategoriler.
TTL-based fake packet + reverse TCP fragmentation + DoH.
"""

import sys
import threading
import ctypes
import pydivert
from pydivert.consts import Flag
from strategies import extract_sni, should_bypass, tcp_fragment_and_send
from doh import DohManager
from config import load_settings, MODE_ALL
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
        self._main_handle = None
        self._doh = None
        self._settings = load_settings()
        self.stats = {"bypassed": 0, "passed": 0}
        self.running = False

    def reload_settings(self):
        """Ayarları yeniden yükle (GUI'den mode değiştiğinde)."""
        self._settings = load_settings()
        mode = self._settings.get("mode", MODE_ALL)
        self._log(f"[*] Mod: {mode.upper()}")

    def start(self):
        """Bypass loop. Ayrı thread'den çağır."""
        self._stop_event.clear()
        self.stats = {"bypassed": 0, "passed": 0}
        self._settings = load_settings()

        # DoH başlat
        if self._settings.get("doh_enabled", True):
            provider = self._settings.get("doh_provider", "cloudflare")
            self._doh = DohManager(provider=provider, log_callback=self._log)
            self._doh.start()

        # Kernel DROP: DPI RST + QUIC
        self._rst_drop = pydivert.WinDivert(
            "inbound and tcp and tcp.Rst and "
            "(tcp.SrcPort == 443 or tcp.SrcPort == 80)",
            priority=1000, flags=Flag.DROP
        )
        self._rst_drop.open()

        self._quic_drop = pydivert.WinDivert(
            "outbound and udp and udp.DstPort == 443",
            priority=999, flags=Flag.DROP
        )
        self._quic_drop.open()

        # Main filter
        main_filter = (
            "outbound and tcp and "
            "(tcp.DstPort == 443 or tcp.DstPort == 80) and "
            "tcp.PayloadLength > 0"
        )

        mode = self._settings.get("mode", MODE_ALL)
        self.running = True
        self._log(t("engine_active"))
        self._log(f"[*] Mod: {mode.upper()}")

        try:
            self._main_handle = pydivert.WinDivert(main_filter)
            self._main_handle.open()

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

                    # TLS ClientHello check
                    if len(payload) > 5 and payload[0] == 0x16:
                        sni = extract_sni(payload)
                        if sni and should_bypass(sni, self._settings):
                            if tcp_fragment_and_send(self._main_handle, packet, sni, self._verbose):
                                self.stats["bypassed"] += 1
                                if self._verbose:
                                    self._log(f"[BYPASS] {sni}")
                                continue

                    self._main_handle.send(packet)
                    self.stats["passed"] += 1
                except Exception:
                    if self._stop_event.is_set():
                        break

        except Exception as e:
            if not self._stop_event.is_set():
                self._log(f"[!] {e}")
        finally:
            self._cleanup()
            self.running = False
            self._log(f"{t('engine_stopped')} | Bypass: {self.stats['bypassed']}")

    def stop(self):
        """Bypass durdur (thread-safe)."""
        self._stop_event.set()
        # DoH durdur — DNS'i geri al
        if self._doh and self._doh.active:
            self._doh.stop()
            self._doh = None
        # Handle kapat — recv() block'u kır
        if self._main_handle and self._main_handle.is_open:
            try:
                self._main_handle.close()
            except Exception:
                pass

    def _cleanup(self):
        for handle in (self._main_handle, self._rst_drop, self._quic_drop):
            if handle:
                try:
                    if handle.is_open:
                        handle.close()
                except Exception:
                    pass
        self._main_handle = None
        self._rst_drop = None
        self._quic_drop = None


if __name__ == "__main__":
    if not is_admin():
        print(t("admin_required"))
        sys.exit(1)

    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    engine = BypassEngine(verbose=verbose)

    try:
        engine.start()
    except KeyboardInterrupt:
        engine.stop()
