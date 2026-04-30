"""
HenkerDPI V2 macOS - DNS-over-HTTPS (DoH)
Redirect system DNS to secure DNS servers.
Bypasses ISP-level DNS blocking/hijacking.
Uses networksetup instead of netsh/PowerShell.
"""

import subprocess
import os
import re


def is_admin() -> bool:
    """Check if running as root."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def get_active_interfaces() -> list[str]:
    """Get names of active network services (e.g. Wi-Fi, Ethernet)."""
    services = []
    try:
        # networksetup -listallhardwareports gives us service names + devices
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return services

        # Parse output: "Hardware Port: Wi-Fi\nDevice: en0\n..."
        current_service = None
        current_device = None
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_service = line.split(":", 1)[1].strip()
            elif line.startswith("Device:"):
                current_device = line.split(":", 1)[1].strip()
                if current_service and current_device:
                    # Check if device is active via ifconfig
                    try:
                        ifresult = subprocess.run(
                            ["ifconfig", current_device],
                            capture_output=True, text=True, timeout=3
                        )
                        if "status: active" in ifresult.stdout:
                            services.append(current_service)
                    except Exception:
                        pass
                current_service = None
                current_device = None
    except Exception:
        pass

    return services


def get_current_dns(service: str) -> list[str]:
    """Get current DNS servers for a network service."""
    try:
        result = subprocess.run(
            ["networksetup", "-getdnsservers", service],
            capture_output=True, text=True, timeout=5
        )
        dns_list = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            # Skip "There aren't any DNS Servers set" message
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                dns_list.append(line)
        return dns_list
    except Exception:
        return []


def set_dns(service: str, primary: str, secondary: str = None) -> bool:
    """Set DNS servers for a network service."""
    try:
        args = ["networksetup", "-setdnsservers", service, primary]
        if secondary:
            args.append(secondary)
        result = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def set_dns_auto(service: str) -> bool:
    """Reset DNS to automatic (DHCP) mode."""
    try:
        result = subprocess.run(
            ["networksetup", "-setdnsservers", service, "Empty"],
            capture_output=True, text=True, timeout=5
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
        self._original_dns = {}
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
