"""
HenkerDPI V2 - DNS-over-HTTPS (DoH)
Sistem DNS'ini güvenli DNS sunucusuna yönlendir.
ISP'nin DNS seviyesinde engellemesini bypass eder.
"""

import subprocess
import ctypes
import re


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_active_interfaces() -> list[str]:
    """Aktif ağ arayüzlerinin isimlerini al."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        interfaces = []
        for line in result.stdout.strip().split("\n"):
            # "Connected" satırlarını bul
            if "Connected" in line or "Bağlı" in line:
                # Son sütun interface adı
                parts = line.strip().split()
                if len(parts) >= 4:
                    # Son kısım interface adı (boşluklu olabilir)
                    name = " ".join(parts[3:])
                    interfaces.append(name)
        return interfaces
    except Exception:
        return []


def get_current_dns(interface: str) -> list[str]:
    """Bir interface'in mevcut DNS sunucularını al."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "show", "dns", f"name={interface}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
        dns_list = []
        for line in result.stdout.split("\n"):
            # IP adresi pattern'i
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                dns_list.append(match.group(1))
        return dns_list
    except Exception:
        return []


def set_dns(interface: str, primary: str, secondary: str = None) -> bool:
    """Bir interface'in DNS sunucularını ayarla."""
    try:
        # Primary DNS
        result = subprocess.run(
            ["netsh", "interface", "ip", "set", "dns",
             f"name={interface}", "static", primary, "validate=no"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return False

        # Secondary DNS
        if secondary:
            subprocess.run(
                ["netsh", "interface", "ip", "add", "dns",
                 f"name={interface}", secondary, "index=2", "validate=no"],
                capture_output=True, text=True
            )
        return True
    except Exception:
        return False


def set_dns_auto(interface: str) -> bool:
    """DNS'i otomatik (DHCP) moduna geri al."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "set", "dns",
             f"name={interface}", "dhcp"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False


class DohManager:
    """DNS-over-HTTPS yöneticisi. Sistem DNS'ini güvenli sunucuya yönlendirir."""

    # Bilinen DoH-destekli DNS sunucuları
    PROVIDERS = {
        "cloudflare": ("1.1.1.1", "1.0.0.1"),
        "google": ("8.8.8.8", "8.8.4.4"),
        "quad9": ("9.9.9.9", "149.112.112.112"),
    }

    def __init__(self, provider: str = "cloudflare", log_callback=None):
        self._provider = provider
        self._log = log_callback or print
        self._original_dns = {}  # interface → [dns_list] — geri dönüş için
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> bool:
        """Tüm aktif interface'lerde DNS'i güvenli sunucuya çevir."""
        if self._provider not in self.PROVIDERS:
            self._log(f"[!] Bilinmeyen DoH provider: {self._provider}")
            return False

        primary, secondary = self.PROVIDERS[self._provider]
        interfaces = get_active_interfaces()

        if not interfaces:
            self._log("[!] Aktif ağ arayüzü bulunamadı")
            return False

        success = False
        for iface in interfaces:
            # Mevcut DNS'i kaydet (geri dönüş için)
            current = get_current_dns(iface)
            self._original_dns[iface] = current

            if set_dns(iface, primary, secondary):
                self._log(f"[DNS] {iface} → {primary}")
                success = True
            else:
                self._log(f"[!] DNS ayarlanamadı: {iface}")

        if success:
            self._active = True
            self._log(f"[DNS] {self._provider.title()} DNS aktif")

        return success

    def stop(self):
        """DNS'i orijinal ayarlarına geri döndür."""
        for iface, original in self._original_dns.items():
            if original:
                # Orijinal DNS'leri geri yükle
                set_dns(iface, original[0],
                        original[1] if len(original) > 1 else None)
                self._log(f"[DNS] {iface} → orijinal")
            else:
                # DHCP'ye geri dön
                set_dns_auto(iface)
                self._log(f"[DNS] {iface} → DHCP")

        self._original_dns.clear()
        self._active = False
        self._log("[DNS] DNS orijinal ayarlara döndürüldü")

    def set_provider(self, provider: str):
        """Provider değiştir. Aktifse yeniden başlat."""
        was_active = self._active
        if was_active:
            self.stop()
        self._provider = provider
        if was_active:
            self.start()
