# HenkerDPI V2

A general-purpose DPI (Deep Packet Inspection) bypass tool for Windows. Access any blocked website freely without a VPN.

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
- **Autostart** — Option to start on Windows boot

## How It Works

HenkerDPI uses a three-layer bypass strategy:

1. **TTL-based Fake Packet** — Sends a decoy packet with a spoofed SNI and low TTL (3 hops). The DPI system sees the fake domain, but the packet expires before reaching the actual server.

2. **TCP Fragmentation + Disorder** — Splits the real TLS ClientHello at the midpoint of the SNI hostname and sends the fragments out of order. DPI systems can't reassemble out-of-order packets.

3. **RST Injection Protection** — Drops DPI-injected RST packets at the kernel level using WinDivert, preventing connection resets.

Additionally:
- **QUIC Blocking** — Forces browsers to use TCP instead of UDP/QUIC, ensuring the bypass strategy can intercept the handshake
- **Secure DNS** — Redirects DNS queries to encrypted resolvers (1.1.1.1 / 8.8.8.8 / 9.9.9.9) to prevent DNS-level censorship

## Installation

### Installer (Recommended)

Download the latest `HenkerDPI_V2_Setup.exe` from [Releases](../../releases) and run it.

### From Source

```bash
git clone https://github.com/Henkerr/HenkerDPI-V2.git
cd HenkerDPI-V2
pip install -r requirements.txt
python gui.py  # Must run as Administrator
```

### Build EXE

```bash
python -m PyInstaller HenkerDPI_V2.spec --clean -y
# Output: dist/HenkerDPI_V2.exe
```

### Build Installer

Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php):

```bash
ISCC.exe setup.iss
# Output: installer/HenkerDPI_V2_Setup.exe
```

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges (required for WinDivert packet interception)
- Python 3.10+ (for running from source)

### Dependencies

| Package | Purpose |
|---------|---------|
| `pydivert` | WinDivert wrapper for kernel-level packet interception |
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
gui.py           — CustomTkinter GUI (themes, animations, controls)
main.py          — BypassEngine (packet interception loop)
strategies.py    — DPI bypass logic (SNI extraction, fragmentation, fake packets)
config.py        — Categories, DoH providers, settings management
doh.py           — DNS-over-HTTPS manager (system DNS redirect)
lang.py          — Multi-language support (9 languages)
service.py       — Windows service manager (background mode)
```

## HenkerDPI V1 vs V2

| Feature | V1 | V2 |
|---------|----|----|
| Scope | Discord only | All websites |
| Modes | Single | All / Selective |
| Categories | None | 8 presets |
| DNS Bypass | None | DoH (Cloudflare/Google/Quad9) |
| Local traffic | Not filtered | Excluded (127.x, 192.168.x) |

## License

MIT

## Disclaimer

This tool is intended for educational and research purposes. It helps users access publicly available information on the internet. Users are responsible for complying with applicable laws in their jurisdiction.
