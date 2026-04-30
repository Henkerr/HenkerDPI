"""
HenkerDPI V2 macOS - DPI Bypass Engine
General-purpose: all sites or selected categories.
TTL-based fake packet + reverse TCP fragmentation + DoH.
Uses scapy + pf instead of WinDivert.
"""

import sys
import os
import socket
import struct
import threading
from strategies import extract_sni, should_bypass, tcp_fragment_and_send
from pf_manager import PfManager
from doh import DohManager
from config import load_settings, MODE_ALL
from lang import t

# scapy import — suppress warning banner
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, IP, TCP, Raw, conf


def is_admin() -> bool:
    """Check if running as root (required for raw sockets + pf)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


class BypassEngine:
    """Thread-safe DPI bypass engine — V2 macOS version."""

    def __init__(self, log_callback=None, verbose: bool = False):
        self._log = log_callback or print
        self._verbose = verbose
        self._stop_event = threading.Event()
        self._pf = PfManager(log_callback=self._log)
        self._raw_sock = None
        self._doh = None
        self._settings = load_settings()
        self.stats = {"bypassed": 0, "passed": 0}
        self.running = False

    def reload_settings(self):
        """Reload settings (called when mode changes from GUI)."""
        self._settings = load_settings()
        mode = self._settings.get("mode", MODE_ALL)
        self._log(f"[*] Mode: {mode.upper()}")

    def start(self):
        """Run bypass loop. Call from a separate thread."""
        self._stop_event.clear()
        self.stats = {"bypassed": 0, "passed": 0}
        self._settings = load_settings()

        # Start DoH (secure DNS)
        if self._settings.get("doh_enabled", True):
            provider = self._settings.get("doh_provider", "cloudflare")
            self._doh = DohManager(provider=provider, log_callback=self._log)
            self._doh.start()

        # pf rules: RST drop + QUIC block
        self._pf.install_rules()

        # Raw socket for packet injection
        self._raw_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self._raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        mode = self._settings.get("mode", MODE_ALL)
        self.running = True
        self._log(t("engine_active"))
        self._log(f"[*] Mode: {mode.upper()}")

        try:
            # Scapy sniff — outgoing TLS/HTTP traffic
            sniff(
                filter="tcp dst port 443 or tcp dst port 80",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except Exception as e:
            if not self._stop_event.is_set():
                self._log(f"[!] {e}")
        finally:
            self._cleanup()
            self.running = False
            self._log(f"{t('engine_stopped')} | Bypass: {self.stats['bypassed']}")

    def _process_packet(self, packet):
        """Process each sniffed packet."""
        if self._stop_event.is_set():
            return

        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            self.stats["passed"] += 1
            return

        try:
            payload = bytes(packet[Raw].load)

            # TLS ClientHello check (0x16 = TLS handshake)
            if len(payload) > 5 and payload[0] == 0x16:
                sni = extract_sni(payload)
                if sni and should_bypass(sni, self._settings):
                    ip_layer = packet[IP]
                    tcp_layer = packet[TCP]

                    # TCP flags byte
                    raw_bytes = bytes(packet)
                    ip_hlen = (raw_bytes[0] & 0x0F) * 4
                    tcp_flags = raw_bytes[ip_hlen + 13]

                    if tcp_fragment_and_send(
                        self._raw_sock,
                        ip_layer.src, ip_layer.dst,
                        tcp_layer.sport, tcp_layer.dport,
                        tcp_layer.seq, tcp_layer.ack,
                        tcp_flags, payload, sni,
                        self._verbose,
                    ):
                        self.stats["bypassed"] += 1
                        # In ALL mode, log every 50th bypass to reduce noise
                        mode = self._settings.get("mode", MODE_ALL)
                        if mode == MODE_ALL:
                            if self.stats["bypassed"] % 50 == 1:
                                self._log(f"[BYPASS] {sni} (+{min(self.stats['bypassed'], 50)})")
                        else:
                            self._log(f"[BYPASS] {sni}")
                        return

            self.stats["passed"] += 1
        except Exception:
            if self._stop_event.is_set():
                return

    def stop(self):
        """Stop bypass (thread-safe)."""
        self._stop_event.set()
        # Stop DoH — restore original DNS
        if self._doh and self._doh.active:
            self._doh.stop()
            self._doh = None

    def _cleanup(self):
        """Clean up resources."""
        self._pf.remove_rules()
        if self._raw_sock:
            try:
                self._raw_sock.close()
            except Exception:
                pass
            self._raw_sock = None


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
