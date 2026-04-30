"""
HenkerDPI macOS - pf (Packet Filter) Manager
Manages pf rules for RST drop and QUIC block.
Requires root privileges.
"""

import subprocess
import os
import tempfile

# pf anchor adi — mevcut kurallara dokunmaz
ANCHOR = "henkerdpi"

# RST drop + QUIC block kurallari
RULES = """\
# HenkerDPI - DPI bypass rules
# Drop DPI-injected RST packets on ports 80/443
block in quick proto tcp from any port {80, 443} flags R/R no state
# Block QUIC (UDP 443) - force TCP fallback
block out quick proto udp from any to any port 443 no state
"""

_RULES_FILE = os.path.join(tempfile.gettempdir(), "henkerdpi_pf.conf")


class PfManager:
    """macOS pf rule manager using anchors."""

    def __init__(self, log_callback=None):
        self._log = log_callback or print
        self._installed = False
        self._original_rules = None

    def install_rules(self) -> bool:
        """Install pf rules for RST drop and QUIC block."""
        try:
            # Mevcut kurallari kaydet
            result = subprocess.run(
                ["pfctl", "-sr"],
                capture_output=True, text=True
            )
            self._original_rules = result.stdout

            # Anchor referansi mevcut kurallara ekle
            anchor_line = f'anchor "{ANCHOR}"'
            if anchor_line not in self._original_rules:
                combined = self._original_rules.strip() + f"\n{anchor_line}\n"
                _tmp = _RULES_FILE + ".main"
                with open(_tmp, "w") as f:
                    f.write(combined)
                subprocess.run(
                    ["pfctl", "-f", _tmp],
                    capture_output=True
                )
                os.remove(_tmp)

            # Kurallari anchor'a yukle
            with open(_RULES_FILE, "w") as f:
                f.write(RULES)

            result = subprocess.run(
                ["pfctl", "-a", ANCHOR, "-f", _RULES_FILE],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                self._log(f"[!] pf anchor load failed: {result.stderr.strip()}")
                return False

            # pf'i etkinlestir
            subprocess.run(["pfctl", "-e"], capture_output=True)

            self._installed = True
            self._log("[pf] RST drop + QUIC block active")
            return True

        except FileNotFoundError:
            self._log("[!] pfctl not found — pf rules not installed")
            return False
        except Exception as e:
            self._log(f"[!] pf error: {e}")
            return False

    def remove_rules(self):
        """Remove our pf rules."""
        if not self._installed:
            return

        try:
            # Anchor'daki kurallari temizle
            subprocess.run(
                ["pfctl", "-a", ANCHOR, "-F", "all"],
                capture_output=True
            )

            # Orijinal kurallari geri yukle
            if self._original_rules:
                _tmp = _RULES_FILE + ".restore"
                with open(_tmp, "w") as f:
                    f.write(self._original_rules)
                subprocess.run(["pfctl", "-f", _tmp], capture_output=True)
                os.remove(_tmp)

            self._log("[pf] Rules removed")
        except Exception as e:
            self._log(f"[!] pf cleanup error: {e}")
        finally:
            self._installed = False
            try:
                os.remove(_RULES_FILE)
            except OSError:
                pass
