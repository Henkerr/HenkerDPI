<div align="center">

<img src="icon.png" width="128" alt="HenkerDPI">

# HenkerDPI

**General-purpose DPI bypass for Windows and macOS**

[![Windows](https://img.shields.io/badge/Windows-10%2F11-blue?logo=windows)](https://github.com/Henkerr/HenkerDPI)
[![macOS](https://img.shields.io/badge/macOS-11%2B-black?logo=apple)](https://github.com/Henkerr/HenkerDPI)
[![Python](https://img.shields.io/badge/python-3.10%2B-yellow?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

### [⬇ Download HenkerDPI](https://github.com/Henkerr/HenkerDPI/releases/latest)

<sub>Windows 10/11 64-bit · macOS 11+ on Apple Silicon or Intel</sub>

<sub>Pick your file from the assets on that page — `HenkerDPI.exe` for Windows,
`HenkerDPI-macOS-arm64.dmg` or `-x86_64.dmg` for a Mac. Every release publishes its SHA-256.</sub>

</div>

A general-purpose DPI (Deep Packet Inspection) bypass tool for **Windows** and **macOS**. Access any blocked website freely without a VPN.

HenkerDPI manipulates the TLS handshake so ISP-level DPI systems cannot detect and block your connections. Unlike a VPN, it adds virtually zero latency and doesn't route your traffic through external servers.

The two builds reach that same result differently, because the platforms allow different things. On Windows it works at the packet level, rewriting handshake packets in flight through a kernel driver. macOS has no equivalent hook — there is no WinDivert, and its firewall cannot hand an outbound connection to a local program — so the Mac build runs a small bypass proxy on your own machine and points macOS at it. Nothing leaves your computer either way.

## Features

- **Bypass All Mode** — One-click bypass for all HTTPS traffic. No configuration needed.
- **Selective Mode** — Choose which categories of sites to bypass (Social Media, Discord, Video, etc.)
- **8 Preset Categories** — Social Media, Discord, Video/Streaming, Knowledge/Wiki, Developer, News/Media, VPN/Proxy, AI Services
- **Secure DNS** — Redirects system DNS to Cloudflare, Google, or Quad9 to bypass ISP DNS hijacking/blocking, with automatic cross-provider fallback
- **Custom Domains** — Add any domain to the bypass list
- **4 Themes** — Graphite, Iris, Halcyon, Obsidian
- **8 Languages** — English, Turkish, Hindi, Japanese, Chinese, Russian, German, Danish
- **System Tray** — Minimize to tray, runs silently in background
- **Autostart** — Silent, elevated Windows Task Scheduler task

## How It Works

HenkerDPI uses a layered bypass strategy:

0. **It measures your line and configures itself.** There is no single desync that beats every ISP — the combination that gets Discord through one Turkish fixed line is the one that breaks *every* HTTPS site on an iPhone USB hotspot, because the hotspot's NAT repairs the decoy the fixed line needs to be broken. So on the first run on a given network HenkerDPI finds a site your line actually blocks, tries its strategies against it through the same code path it uses in production, and keeps the first one that both defeats the block **and** leaves normal sites working. The result is cached per network (interface + gateway + gateway MAC), so later starts are instant, and it re-measures on its own when you move to a different network. **There is nothing to configure.**

1. **Fake ClientHello Decoy** — Sends a decoy packet carrying a spoofed SNI and a low TTL, made unusable by the destination either through a deliberately invalid TCP checksum or an out-of-window sequence number. The DPI records the fake domain; the real server drops the decoy so it never poisons your actual handshake. Which of the two defences applies is part of what step 0 measures — a wrong checksum is what fools a DPI that reassembles the flow, while a wrong sequence number is what survives a NAT that would otherwise repair the decoy.

2. **TCP Fragmentation + Disorder** — Splits the real TLS ClientHello and sends the fragments out of order, so a DPI that does not buffer out-of-order data never sees the hostname in one piece. Where the cut falls (at the TLS record header, in the middle of the SNI, both, or not at all) is also measured per network.

3. **RST Injection Protection** *(optional, off by default)* — A toggle that drops inbound RST packets on 443/80 at the kernel level using WinDivert. Left off by default so legitimate connection resets are never swallowed; enable it only if your ISP injects RSTs.

Additionally:
- **QUIC Fast-Fallback** — Instead of silently black-holing UDP/QUIC, HenkerDPI answers each QUIC attempt with a locally injected ICMP *port-unreachable*, so the browser falls back to TCP instantly (no timeout wait) without leaking the SNI over UDP.
- **Secure DNS (crash-safe)** — Redirects DNS to secure resolvers (Cloudflare 1.1.1.1 / Google 8.8.8.8 / Quad9 9.9.9.9). This switches your *resolver* to bypass ISP DNS hijacking — it is not DNS-over-HTTPS encryption. Your original DNS is journaled to disk before any change and restored on the next launch even after a force-kill or crash. The chosen resolver is probed first: if it is unreachable, HenkerDPI falls back to another provider instead of pinning DNS to a dead server. IPv6 DNS is only pinned on adapters that actually have IPv6 connectivity.

## If a site still will not open

The bypass configures itself, so the first thing to try is forcing a fresh measurement: close HenkerDPI, delete `%LOCALAPPDATA%\HenkerDPI\autotune.json`, and start it again. The app re-measures your line from scratch and logs which strategy it picked.

The measurement is cached per network, and it re-runs by itself when you connect to a different one. If you want to pin a strategy by hand (support and debugging only), set `"strategy_mode": "manual"` in `%LOCALAPPDATA%\HenkerDPI\settings.json` and the `decoy_mode` / `split_mode` values there are used instead.

## IPv6 Bypass (experimental, opt-in)

By default HenkerDPI bypasses **IPv4 traffic only** — the proven, drop-free path. On a dual-stack network a site reachable over IPv6 may otherwise connect without the bypass applied, so if a blocked site opens inconsistently you have two options:

- **Simplest:** force the IPv4 route (or disable IPv6 on the adapter) so the bypass always takes effect.
- **Experimental IPv6 bypass:** set `"ipv6_bypass_enabled": true` in `%LOCALAPPDATA%\HenkerDPI\settings.json` (created on first run), then restart the app. This also diverts IPv6 TCP/443 ClientHellos and refuses IPv6 QUIC. It is **off by default** and kept experimental because the IPv4 path is the one validated to be drop-free; enable it only if you specifically need IPv6-only sites bypassed.

## Installation

### Portable (Recommended right now)

Download **`HenkerDPI.exe`** from [Releases](../../releases) and run it **as Administrator** (right-click → *Run as administrator*). A single file, no installation; the WinDivert driver is bundled inside.

### Installer

**Not published for the current release — use the portable download above.**

An installer (`HenkerDPI_Setup.exe`, built from `setup.iss`) installs to Program Files, creates
Start-menu and desktop shortcuts and launches the app, so there is no "run as administrator" step
to remember. Releases up to 2.4.0 shipped one and you can still build it yourself (see *Building
from source*), but no installer is attached to 2.7.0.

> **Why.** Defender's machine-learning heuristic flagged the 2.4.0 installer as
> `Trojan:Win32/Wacatac.B!ml` on 2026-08-05 and deleted it on download — a false positive on the
> unsigned Inno Setup wrapper, not on the application inside, which scanned clean throughout.
> Microsoft has since cleared it: the same asset now downloads and scans clean. The verdict is
> per-binary though, so a freshly built installer is a new file that can be flagged again. Until
> the project is code-signed, releases ship the portable executable only — it has never been
> flagged.

### Updates

Both builds check GitHub once a day and show a banner when a newer release exists.

On **Windows**, from 2.4.0 on, one click finishes the job: it downloads the new exe, verifies its SHA-256 against the digest GitHub publishes for the asset, swaps the executable and restarts. Turn it off with `"update_check_enabled": false` in `%LOCALAPPDATA%\HenkerDPI\settings.json`.

On **macOS** the banner takes you to the release page and you install the new DMG yourself. An `.app` is a signed bundle, not a single file, so replacing it from inside itself would break its signature and leave an app that will not launch. The setting lives in `~/Library/Application Support/HenkerDPI/settings.json`.

> **SmartScreen & Antivirus:** the exe is unsigned and injects packets via a kernel driver, so Windows SmartScreen may show *"Windows protected your PC"* on first run — click **More info → Run anyway**. Some antivirus engines also flag DPI-bypass tools as potentially unwanted; this is a false positive. If you prefer, build it yourself from source (below) or scan the exe on [VirusTotal](https://www.virustotal.com).

### Windows — From Source

```bash
git clone https://github.com/Henkerr/HenkerDPI.git
cd HenkerDPI
pip install -r requirements.txt
python gui.py  # Must run as Administrator
```

### Build EXE (Windows)

```bash
pip install -r requirements.txt -r requirements-build.txt
python -m PyInstaller HenkerDPI.spec --clean -y
# Output: dist/HenkerDPI.exe (version from version_info.txt, admin-manifested, WinDivert bundled)
```

### Build Installer (Windows)

Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php):

```bash
ISCC.exe setup.iss
# Output: installer/HenkerDPI_Setup.exe
```

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges (required for WinDivert)
- Python 3.10+ (only to run or build from source)

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
3. **Toggle Secure DNS** — Repoint your resolver to Cloudflare/Google/Quad9 to bypass ISP DNS blocking (this changes *which* resolver you use; it does not encrypt your DNS queries)
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
1. Turn autostart off in the app (or run `schtasks /delete /tn HenkerDPI /f` as Administrator).
2. Close the app — it restores your original DNS on exit.
3. Delete the exe / repo folder and the DNS journal folder at `%LOCALAPPDATA%\HenkerDPI\`.

## Troubleshooting

- **Must run as Administrator.** WinDivert needs an elevated process; the app exits with an "admin required" message otherwise.
- **A site opens inconsistently on a dual-stack connection.** It is likely connecting over IPv6, which is not bypassed by default — see [IPv6 Bypass](#ipv6-bypass-experimental-opt-in).
- **DNS didn't come back after a crash.** It self-heals — the original DNS is restored automatically on the next launch. You can also toggle Secure DNS off and on.
- **DPI still blocks a site.** If your ISP relies on RST injection, enable the RST-drop toggle (off by default so it never swallows legitimate resets).

## Architecture

```
HenkerDPI/
├── gui.py             — CustomTkinter GUI, shared; picks the engine per platform
├── config.py          — Categories, resolvers, settings + state-dir management
├── lang.py            — Multi-language support (8 languages)
├── sni.py             — ClientHello parsing + bypass scope (shared, no platform deps)
├── dnsq.py            — DNS-over-HTTPS resolver with a TTL cache (shared)
├── tunecache.py       — Per-network memory of the measured strategy (shared)
├── updater.py         — GitHub release check, verified download, in-place swap
│
├── main.py            — Windows BypassEngine (WinDivert packet interception)
├── strategies.py      — Windows packet surgery (decoy, fragmentation)
├── autotune.py        — Windows per-line strategy measurement
├── doh.py             — Windows secure DNS: crash-safe resolver switching
│
├── macos/             — the macOS half; imports the shared modules, copies none
│   ├── engine.py      — BypassEngine with the same interface as main.py's
│   ├── proxy.py       — local listener: PAC + HTTP CONNECT + SOCKS5
│   ├── desync.py      — handshake reshaping (TLS records, segments, disorder)
│   ├── sysproxy.py    — networksetup with a crash-safe restore journal
│   ├── autotune_mac.py— per-line measurement of the framing technique
│   └── selftest.py    — offline wiring checks, run against the built .app
│
├── launch.bat         — run from source, self-elevating (dev convenience)
├── HenkerDPI.spec     — PyInstaller build definition (Windows)
├── HenkerDPI-macos.spec — PyInstaller build definition (macOS .app)
├── packaging/         — the manual network-restore script shipped in the DMG
├── setup.iss          — Inno Setup installer script
├── licenses/          — LGPL/GPL texts for the bundled third-party components
├── docs/              — the download page at henkerr.github.io/HenkerDPI
├── assets/            — GitHub social-preview card
└── tools/             — scripts that regenerate the logo and the social card
```

Preferences (`settings.json`, `custom_domains.json`, `lang_pref.json`,
`theme_pref.json`) and the crash-safe restore journal live in
`%LOCALAPPDATA%\HenkerDPI\` on Windows and
`~/Library/Application Support/HenkerDPI/` on macOS. The macOS path resolves to
the logged-in user's home even when the app is elevated, so an admin prompt
never strands settings under `/var/root`.

## HenkerDPI V1 vs V2

| Feature | V1 | V2 |
|---------|----|----|
| Scope | Discord only | All websites |
| Modes | Single | All / Selective |
| Categories | None | 8 presets |
| DNS Bypass | None | Secure DNS (Cloudflare/Google/Quad9) |
| Local traffic | Not filtered | Excluded (loopback, RFC1918, link-local, CGNAT) |

## macOS

Download the DMG for your Mac from [Releases](../../releases) — `arm64` for Apple
Silicon, `x86_64` for Intel — and drag the app to Applications.

The app is not signed by Apple, so the first launch is refused. Open **System
Settings → Privacy & Security**, scroll to the bottom, and click **Open Anyway**
next to HenkerDPI. On macOS 14 and earlier you can right-click the app and choose
**Open** instead; macOS 15 removed that shortcut, which is why the longer path is
the one written here.

Start it and approve the macOS password prompt once. That prompt points your
network at HenkerDPI's own local proxy; quitting the app puts the setting back.

### It is not the Windows engine recompiled

macOS has no equivalent of WinDivert, and its `pf` is a fork of OpenBSD pf 4.1
with no `divert-to`, so the Windows approach — intercept the outbound
ClientHello in the kernel and inject a decoy packet beside it — has nothing to
build on. The macOS build works a different way: it runs a proxy on `127.0.0.1`,
registers it with macOS as a proxy auto-config (PAC) URL, and reshapes each TLS
handshake as it forwards it. Traffic still never leaves your machine for anyone
else's server.

**What that costs, stated plainly:**

- **The decoy packet does not exist on macOS.** The Windows engine's strongest
  move sends a fake ClientHello carrying the *same* TCP sequence number as the
  real one, so the decoy occupies no sequence space. From an ordinary socket
  that is impossible, and macOS has no `TCP_REPAIR` to rewind the sequence
  number with. The macOS build therefore relies on reshaping the handshake:
  splitting the ClientHello across TLS records, across TCP segments, or sending
  the first segment with a hop limit too low to reach the server so the DPI sees
  the pieces out of order.
- **Coverage is browsers and Electron apps.** Safari, Chrome, Firefox, Edge and
  apps like Discord follow the system proxy. `curl`, `git`, `npm`, `brew` and
  `ssh` read `http_proxy` instead and are untouched. Discord *voice* is raw UDP
  and never passes through the proxy.
- **A third-party VPN takes precedence.** When a VPN's `utun` interface becomes
  primary, macOS scopes proxy settings to it and HenkerDPI is bypassed.
- **No DNS changes at all.** The proxy resolves over DNS-over-HTTPS in-process,
  so unlike the Windows build there is no system resolver to switch and nothing
  to restore. This is deliberate: it removes the failure that leaves a machine
  with no working DNS.

### If your network settings ever look wrong

They should not — the app restores them on quit, and because it registers a PAC
rather than a fixed proxy, macOS falls back to a direct connection whenever the
app is not running. If you want to reset by hand anyway, the DMG contains
**`Ag Ayarlarini Geri Yukle.command`**; double-click it and enter your password.

### macOS — From Source

```bash
pip install customtkinter Pillow pyinstaller
python tools/selftest_macos.py          # offline wiring checks

# The .icns is generated, not committed. No 64 in the list: iconutil validates
# every name against Apple's iconset table, which has no icon_64x64 entry, and
# one unrecognized name aborts the conversion. The 64px image still gets made,
# as icon_32x32@2x.png.
mkdir -p icon.iconset
for size in 16 32 128 256 512; do
  sips -z $size $size icon.png --out icon.iconset/icon_${size}x${size}.png
  sips -z $((size*2)) $((size*2)) icon.png --out icon.iconset/icon_${size}x${size}@2x.png
done
iconutil -c icns icon.iconset -o icon.icns

python -m PyInstaller HenkerDPI-macos.spec --clean -y
codesign --force --deep --sign - dist/HenkerDPI.app
# Output: dist/HenkerDPI.app
```

Ad-hoc signing is not cosmetic on Apple Silicon: an unsigned bundle is killed at
exec rather than merely warned about. Releases are built by
[`.github/workflows/build-macos.yml`](.github/workflows/build-macos.yml) on real
macOS runners, one per architecture.

The abandoned first attempt on the
[`macos-experimental`](https://github.com/Henkerr/HenkerDPI/tree/macos-experimental)
branch is superseded and should not be used. It sniffed packets with scapy,
which cannot reshape a handshake that has already been sent, and it duplicated
`config.py`, `lang.py`, `gui.py` and `strategies.py` into its own directory —
copies that were seventeen commits stale by the time it was dropped. The current
port shares those modules instead of copying them.

## Changelog

Version history is in [CHANGELOG.md](CHANGELOG.md); each release also publishes the SHA-256 of its assets.

## License

MIT — see [LICENSE](LICENSE). Bundled third-party components (WinDivert, pydivert, and others) retain their own licenses; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Disclaimer

This tool is intended for educational and research purposes. It helps users access publicly available information on the internet. Users are responsible for complying with applicable laws in their jurisdiction.
