"""
HenkerDPI V2 - DNS-over-HTTPS (DoH)
Redirect system DNS to secure DNS servers.
Bypasses ISP-level DNS blocking/hijacking.
"""

import subprocess
import ctypes
import re

# Hide console windows for all subprocess calls
_SW = subprocess.STARTUPINFO()
_SW.dwFlags |= subprocess.STARTF_USESHOWWINDOW
_SW.wShowWindow = 0  # SW_HIDE


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_active_interfaces() -> list[str]:
    """Get names of active network interfaces."""
    interfaces = []

    # Method 1: PowerShell (most reliable, locale-independent)
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", startupinfo=_SW,
            timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                name = line.strip()
                if name:
                    interfaces.append(name)
            if interfaces:
                return interfaces
    except Exception:
        pass

    # Method 2: netsh fallback (locale-dependent but works as backup)
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", startupinfo=_SW,
            timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            lower = line.lower()
            if "connected" in lower:
                parts = line.strip().split()
                if len(parts) >= 4:
                    name = " ".join(parts[3:])
                    interfaces.append(name)
    except Exception:
        pass

    return interfaces


def get_current_dns(interface: str) -> list[str]:
    """Get current DNS servers for an interface."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "show", "dns", f"name={interface}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", startupinfo=_SW
        )
        dns_list = []
        for line in result.stdout.split("\n"):
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                dns_list.append(match.group(1))
        return dns_list
    except Exception:
        return []


def set_dns(interface: str, primary: str, secondary: str = None) -> bool:
    """Set DNS servers for an interface."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "set", "dns",
             f"name={interface}", "static", primary, "validate=no"],
            capture_output=True, text=True, startupinfo=_SW
        )
        if result.returncode != 0:
            return False

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
    """Reset DNS to automatic (DHCP) mode."""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "set", "dns",
             f"name={interface}", "dhcp"],
            capture_output=True, text=True, startupinfo=_SW
        )
        return result.returncode == 0
    except Exception:
        return False


class DohManager:
    """DNS-over-HTTPS manager. Redirects system DNS to secure servers."""

    PROVIDERS = {
        "cloudflare": ("1.1.1.1", "1.0.0.1"),
        "google": ("8.8.8.8", "8.8.4.4"),
        "quad9": ("9.9.9.9", "149.112.112.112"),
    }

    def __init__(self, provider: str = "cloudflare", log_callback=None):
        self._provider = provider
        self._log = log_callback or print
        self._original_dns = {}  # interface -> [dns_list] for rollback
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> bool:
        """Set secure DNS on all active interfaces."""
        if self._provider not in self.PROVIDERS:
            self._log(f"[!] Unknown DoH provider: {self._provider}")
            return False

        primary, secondary = self.PROVIDERS[self._provider]
        interfaces = get_active_interfaces()

        if not interfaces:
            self._log("[!] No active network interfaces found")
            return False

        success = False
        for iface in interfaces:
            # Save current DNS for rollback
            current = get_current_dns(iface)
            self._original_dns[iface] = current

            if set_dns(iface, primary, secondary):
                self._log(f"[DNS] {iface} -> {primary}")
                success = True
            else:
                self._log(f"[!] Failed to set DNS: {iface}")

        if success:
            self._active = True
            self._log(f"[DNS] {self._provider.title()} DNS active")

        return success

    def stop(self):
        """Restore DNS to original settings."""
        for iface, original in self._original_dns.items():
            if original:
                set_dns(iface, original[0],
                        original[1] if len(original) > 1 else None)
                self._log(f"[DNS] {iface} -> original")
            else:
                set_dns_auto(iface)
                self._log(f"[DNS] {iface} -> DHCP")

        self._original_dns.clear()
        self._active = False
        self._log("[DNS] DNS restored to original settings")

    def set_provider(self, provider: str):
        """Change provider. Restarts if currently active."""
        was_active = self._active
        if was_active:
            self.stop()
        self._provider = provider
        if was_active:
            self.start()
