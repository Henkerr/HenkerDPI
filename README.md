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
- **Secure DNS** — Redirects system DNS to Cloudflare, Google, or Quad9 to bypass ISP DNS hijacking/blocking, with automatic cross-provider fallback
- **Custom Domains** — Add any domain to the bypass list
- **4 Themes** — Graphite, Iris, Halcyon, Obsidian (Windows; the macOS build has its own set)
- **8 Languages** — English, Turkish, Hindi, Japanese, Chinese, Russian, German, Danish
- **System Tray** — Minimize to tray, runs silently in background
- **Autostart** — Windows Task Scheduler / macOS LaunchAgent
- **Cross-platform** — Windows 10/11 + macOS 12+

## How It Works

HenkerDPI uses a layered bypass strategy:

1. **Fake ClientHello Decoy** — Sends a decoy packet carrying a spoofed SNI, a deliberately invalid TCP checksum, and a low TTL. The DPI records the fake domain, but the real server drops the decoy (bad checksum / expired TTL) so it never poisons your actual handshake.

2. **TCP Fragmentation + Disorder** — Splits the real TLS ClientHello at the midpoint of the SNI hostname and sends the fragments out of order. DPI systems can't reassemble out-of-order packets.

3. **RST Injection Protection** *(optional, off by default)* — A toggle that drops inbound RST packets on 443/80 at the kernel level using WinDivert. Left off by default so legitimate connection resets are never swallowed; enable it only if your ISP injects RSTs.

Additionally:
- **QUIC Fast-Fallback** — Instead of silently black-holing UDP/QUIC, HenkerDPI answers each QUIC attempt with a locally injected ICMP *port-unreachable*, so the browser falls back to TCP instantly (no timeout wait) without leaking the SNI over UDP.
- **Secure DNS (crash-safe)** — Redirects DNS to secure resolvers (Cloudflare 1.1.1.1 / Google 8.8.8.8 / Quad9 9.9.9.9). This switches your *resolver* to bypass ISP DNS hijacking — it is not DNS-over-HTTPS encryption. Your original DNS is journaled to disk before any change and restored on the next launch even after a force-kill or crash. The chosen resolver is probed first: if it is unreachable, HenkerDPI falls back to another provider instead of pinning DNS to a dead server. IPv6 DNS is only pinned on adapters that actually have IPv6 connectivity.

## IPv6 Bypass (experimental, opt-in)

By default HenkerDPI bypasses **IPv4 traffic only** — the proven, drop-free path. On a dual-stack network a site reachable over IPv6 may otherwise connect without the bypass applied, so if a blocked site opens inconsistently you have two options:

- **Simplest:** force the IPv4 route (or disable IPv6 on the adapter) so the bypass always takes effect.
- **Experimental IPv6 bypass:** set `"ipv6_bypass_enabled": true` in `settings.json` (created next to the exe on first run), then restart the app. This also diverts IPv6 TCP/443 ClientHellos and refuses IPv6 QUIC. It is **off by default** and kept experimental because the IPv4 path is the one validated to be drop-free; enable it only if you specifically need IPv6-only sites bypassed.

## Installation

### Windows — Download (Recommended)

Download the latest **`HenkerDPI_V2.exe`** from [Releases](../../releases) and run it **as Administrator** (right-click → *Run as administrator*). It is a single portable executable — no installation required; the WinDivert driver is bundled inside.

> **SmartScreen & Antivirus:** the exe is unsigned and injects packets via a kernel driver, so Windows SmartScreen may show *"Windows protected your PC"* on first run — click **More info → Run anyway**. Some antivirus engines also flag DPI-bypass tools as potentially unwanted; this is a false positive. If you prefer, build it yourself from source (below) or scan the exe on [VirusTotal](https://www.virustotal.com).

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
pip install -r requirements.txt -r requirements-build.txt
python -m PyInstaller HenkerDPI_V2.spec --clean -y
# Output: dist/HenkerDPI_V2.exe (FileVersion 2.2.0.0, admin-manifested, WinDivert bundled)
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
python main.py           # Start bypass engine (headless), run as Administrator
python main.py -v        # Verbose mode (log every bypass)
```

> Autostart is handled by the in-app toggle (a silent, elevated Task Scheduler task) — there is no separate Windows background service to run.

## Uninstall

**Installer build:** uninstall from *Settings → Apps* (or *Add/Remove Programs*). This stops the app, removes the autostart task, and deletes its settings.

**Portable / source:**
1. Turn autostart off in the app (or run `schtasks /delete /tn HenkerDPI_V2 /f` as Administrator).
2. Close the app — it restores your original DNS on exit.
3. Delete the exe / repo folder and the DNS journal folder at `%LOCALAPPDATA%\HenkerDPI\`.

## Troubleshooting

- **Must run as Administrator.** WinDivert needs an elevated process; the app exits with an "admin required" message otherwise.
- **A site opens inconsistently on a dual-stack connection.** It is likely connecting over IPv6, which is not bypassed by default — see [IPv6 Bypass](#ipv6-bypass-experimental-opt-in).
- **DNS didn't come back after a crash.** It self-heals — the original DNS is restored automatically on the next launch. You can also toggle Secure DNS off and on.
- **DPI still blocks a site.** If your ISP relies on RST injection, enable the RST-drop toggle (off by default so it never swallows legitimate resets).

## Architecture

```
HenkerDPI-V2/
├── gui.py             — CustomTkinter GUI (themes, animations, controls)
├── main.py            — BypassEngine (WinDivert packet interception)
├── strategies.py      — DPI bypass logic (SNI extraction, fragmentation)
├── config.py          — Categories, DoH providers, settings management
├── doh.py             — DNS-over-HTTPS manager (netsh/PowerShell)
├── lang.py            — Multi-language support (8 languages)
├── service.py         — Legacy CLI service manager (used by the macOS build; not needed on Windows)
└── macos/             — macOS version
    ├── gui.py         — macOS GUI (fcntl lock, LaunchAgent)
    ├── main.py        — BypassEngine (scapy + raw sockets)
    ├── strategies.py  — Same bypass logic, raw socket injection
    ├── pf_manager.py  — pf (pfctl) RST drop + QUIC block
    ├── doh.py         — DoH via networksetup
    ├── config.py      — Shared config (platform-independent)
    ├── lang.py        — i18n (8 languages)
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

MIT — see [LICENSE](LICENSE). Bundled third-party components (WinDivert, pydivert, and others) retain their own licenses; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Disclaimer

This tool is intended for educational and research purposes. It helps users access publicly available information on the internet. Users are responsible for complying with applicable laws in their jurisdiction.
