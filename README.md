<div align="center">

# HenkerDPI V2

**General-purpose DPI bypass — Windows & macOS**

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue?logo=windows)](https://github.com/Henkerr/HenkerDPI-V2)
[![macOS](https://img.shields.io/badge/macOS-12%2B-white?logo=apple)](https://github.com/Henkerr/HenkerDPI-V2/tree/master/macos)
[![Python](https://img.shields.io/badge/python-3.10%2B-yellow?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

A general-purpose DPI (Deep Packet Inspection) bypass tool for **Windows and macOS**. Access any blocked website freely without a VPN.

HenkerDPI works at the packet level — it manipulates TLS handshake packets to prevent ISP-level DPI systems from detecting and blocking your connections. Unlike a VPN, it adds virtually zero latency and doesn't route your traffic through external servers.

## Features

- **Bypass All Mode** — One-click bypass for all HTTPS traffic. No configuration needed.
- **Selective Mode** — Choose which categories of sites to bypass (Social Media, Discord, Video, etc.)
- **8 Preset Categories** — Social Media, Discord, Video/Streaming, Knowledge/Wiki, Developer, News/Media, VPN/Proxy, AI Services
- **DNS-over-HTTPS (DoH)** — Automatically redirects system DNS to Cloudflare, Google, or Quad9 to bypass DNS-level blocking
- **Custom Domains** — Add any domain to the bypass list
- **5 Themes** — Phantom, Ocean, Matrix, Inferno, Obsidian
- **9 Languages** — English, Turkish, Hindi, Japanese, Chinese, Russian, German, Danish + more
- **System Tray** — Minimize to tray, runs silently in background
- **Autostart** — Windows Task Scheduler / macOS LaunchAgent
- **Cross-platform** — Windows 10/11 + macOS 12+

## How It Works

HenkerDPI uses a three-layer bypass strategy:

1. **TTL-based Fake Packet** — Sends a decoy packet with a spoofed SNI and low TTL (3 hops). The DPI system sees the fake domain, but the packet expires before reaching the actual server.

2. **TCP Fragmentation + Disorder** — Splits the real TLS ClientHello at the midpoint of the SNI hostname and sends the fragments out of order. DPI systems can't reassemble out-of-order packets.

3. **RST Injection Protection** — Drops DPI-injected RST packets at the kernel level using WinDivert, preventing connection resets.

Additionally:
- **QUIC Blocking** — Forces browsers to use TCP instead of UDP/QUIC, ensuring the bypass strategy can intercept the handshake
- **Secure DNS** — Redirects DNS queries to encrypted resolvers (1.1.1.1 / 8.8.8.8 / 9.9.9.9) to prevent DNS-level censorship

## Installation

### Windows — Installer (Recommended)

Download the latest `HenkerDPI_V2_Setup.exe` from [Releases](../../releases) and run it.

### Windows — From Source

```bash
git clone https://github.com/Henkerr/HenkerDPI-V2.git
cd HenkerDPI-V2
pip install -r requirements.txt
python gui.py  # Must run as Administrator
```

### macOS

```bash
git clone https://github.com/Henkerr/HenkerDPI-V2.git
cd HenkerDPI-V2/macos
pip3 install -r requirements.txt
sudo python3 gui.py  # Root required for raw sockets + pf
```

> **Note:** Root privileges are required for raw socket injection and pf (packet filter) rules.

### Build EXE (Windows)

```bash
python -m PyInstaller HenkerDPI_V2.spec --clean -y
# Output: dist/HenkerDPI_V2.exe
```

### Build App (macOS)

```bash
cd macos
chmod +x build_mac.sh
./build_mac.sh
# Output: dist/HenkerDPI_V2.app
```

### Build Installer (Windows)

Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php):

```bash
ISCC.exe setup.iss
# Output: installer/HenkerDPI_V2_Setup.exe
```

## Requirements

### Windows
- Windows 10/11 (64-bit)
- Administrator privileges (required for WinDivert)
- Python 3.10+

| Package | Purpose |
|---------|---------|
| `pydivert` | WinDivert wrapper for kernel-level packet interception |
| `customtkinter` | Modern dark-themed GUI framework |
| `Pillow` | Power button rendering with glow animations |
| `pystray` | System tray integration |

### macOS
- macOS 12 Monterey or later
- Root privileges (required for raw sockets + pf)
- Python 3.10+

| Package | Purpose |
|---------|---------|
| `scapy` | Packet sniffing and raw socket injection |
| `customtkinter` | Modern dark-themed GUI framework |
| `Pillow` | Power button rendering with glow animations |
| `pystray` | System tray integration |

## Usage

1. **Launch** the app (right-click > Run as Administrator)
2. **Select mode**:
   - `All Sites` — Bypass everything (recommended)
   - `Selective` — Choose specific categories
3. **Toggle Secure DNS** — Enable DoH to bypass DNS blocking
4. **Click the power button** — Protection starts immediately
5. **Minimize** — App goes to system tray

### CLI Mode

```bash
python main.py           # Start bypass engine (headless)
python main.py -v        # Verbose mode (log every bypass)
python service.py start  # Run as background service
python service.py stop   # Stop background service
```

## Architecture

```
HenkerDPI-V2/
├── gui.py             — CustomTkinter GUI (themes, animations, controls)
├── main.py            — BypassEngine (WinDivert packet interception)
├── strategies.py      — DPI bypass logic (SNI extraction, fragmentation)
├── config.py          — Categories, DoH providers, settings management
├── doh.py             — DNS-over-HTTPS manager (netsh/PowerShell)
├── lang.py            — Multi-language support (9 languages)
├── service.py         — Windows service manager (Task Scheduler)
└── macos/             — macOS version
    ├── gui.py         — macOS GUI (fcntl lock, LaunchAgent)
    ├── main.py        — BypassEngine (scapy + raw sockets)
    ├── strategies.py  — Same bypass logic, raw socket injection
    ├── pf_manager.py  — pf (pfctl) RST drop + QUIC block
    ├── doh.py         — DoH via networksetup
    ├── config.py      — Shared config (platform-independent)
    ├── lang.py        — i18n (9 languages)
    ├── service.py     — LaunchAgent service manager
    └── build_mac.sh   — PyInstaller build script
```

## HenkerDPI V1 vs V2

| Feature | V1 | V2 |
|---------|----|----|
| Scope | Discord only | All websites |
| Modes | Single | All / Selective |
| Categories | None | 8 presets |
| DNS Bypass | None | DoH (Cloudflare/Google/Quad9) |
| Local traffic | Not filtered | Excluded (127.x, 192.168.x) |

## Windows vs macOS

| Component | Windows | macOS |
|-----------|---------|-------|
| Packet interception | WinDivert (pydivert) | scapy sniff + raw sockets |
| RST/QUIC block | Kernel-level WinDivert DROP | pf (pfctl) anchor rules |
| DNS management | netsh / PowerShell | networksetup |
| Auto-start | Task Scheduler (schtasks) | LaunchAgent (launchctl) |
| Single instance | CreateMutexW | fcntl.flock() |
| Admin check | ctypes.windll.IsUserAnAdmin | os.geteuid() == 0 |

The bypass logic (TTL fake packet, SNI fragmentation, disorder) is identical across both platforms.

## License

MIT

## Disclaimer

This tool is intended for educational and research purposes. It helps users access publicly available information on the internet. Users are responsible for complying with applicable laws in their jurisdiction.
