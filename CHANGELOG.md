# Changelog

All notable changes to HenkerDPI. Versions follow [semantic versioning](https://semver.org).

Downloads for every release are on the [releases page](https://github.com/Henkerr/HenkerDPI/releases);
each one publishes the SHA-256 of its assets.

---

## 2.4.0 — 2026-08-04

### Added
- **Self-updater.** The app checks GitHub once a day and offers the new version in a banner.
  One click downloads it, verifies it and restarts. The download is fetched over HTTPS from a
  github.com host only, and its SHA-256 must match the digest GitHub computed for the asset —
  a release without a digest is treated as not installable. Downgrades are refused. The bypass
  engine is stopped before the executable is swapped, so DNS is restored first; if the swap
  fails the working executable is put back.
  Disable with `"update_check_enabled": false` in `settings.json`.
- **Installer.** `HenkerDPI_Setup.exe` is now the recommended download. It installs to Program
  Files, creates shortcuts, and needs no manual "run as administrator".
- **Download page** at [henkerr.github.io/HenkerDPI](https://henkerr.github.io/HenkerDPI/),
  available in the same eight languages as the app.

### Changed
- **Renamed from "HenkerDPI V2" to "HenkerDPI"** — executable, installer, scheduled task and
  every UI string. The pre-rename `HenkerDPI_V2` logon task is migrated automatically, so
  "start on boot" survives the upgrade.
- The repository moved to `github.com/Henkerr/HenkerDPI`. The old address redirects permanently.
- New application icon.

### Note
Auto-updating starts *with* this version. 2.3.0 and earlier cannot update themselves — this is
the last manual install.

---

## 2.3.0 — 2026-08-04

First public release of the source. Prepared by an audit before the repository was opened; no
bypass behaviour changed.

### Fixed
- **The app never spoke DNS-over-HTTPS, but the README, the config and all eight translations
  said it did.** What it actually does is repoint the system resolver to Cloudflare/Google/Quad9
  over plain DNS. That defeats ISP DNS blocking but does **not** encrypt your queries. Every
  user-facing string now says so.
- Preferences were written next to the executable, which put them in Program Files for installed
  copies — machine-wide instead of per-user, and refusable by Controlled Folder Access. They now
  live in `%LOCALAPPDATA%\HenkerDPI` alongside the DNS journal, and existing files are migrated
  on first run.
- Turkish UI strings had no diacritics ("Baslatmak icin butona tiklayin"). Rewritten properly.
- Link-local (`169.254/16`) and carrier-grade NAT (`100.64/10`) ranges are excluded from the
  bypass. CGNAT is common on mobile networks, where fragmenting toward an internal host is
  pointless.
- The autostart toggle now verifies the scheduled task's target path. Moving the executable used
  to leave the toggle reading "on" while autostart silently failed every logon.

### Added
- LGPL v3 / GPL v2 / GPL v3 license texts, shipped with the binary. LGPL requires the text to
  travel with the distribution — a link in the repository is not sufficient.

### Removed
- Dead code: `find_sni_offset`, `should_bypass`, `extract_http_host`, and an unused `service.py`.
- The macOS port moved to the [`macos-experimental`](https://github.com/Henkerr/HenkerDPI/tree/macos-experimental)
  branch and is no longer advertised as supported. None of the 2.1.0/2.2.0 reliability fixes were
  ever backported to it, so it still carries the intermittent-disconnect bug those releases fixed
  on Windows.

---

## 2.2.0 — 2026-07-06

### Added
- **Experimental IPv6 bypass**, off by default (`"ipv6_bypass_enabled": true`). Also fragments
  IPv6 TLS ClientHellos and refuses IPv6 QUIC. Kept experimental because the IPv4 path is the
  validated, drop-free one.
- **Resolver reachability probe with cross-provider fallback.** If the chosen resolver is blocked
  by the ISP, the app switches to another instead of pinning DNS to a dead server. If none is
  reachable it leaves DNS alone.

### Fixed
- Journal ownership is authenticated by PID *and* executable name, so a PID reused after a crash
  can no longer block DNS recovery.
- The app no longer records a public resolver as the "original" DNS when a previous override was
  not verifiably reverted.
- Theme and language preferences stopped resetting on every launch of the packaged build.
- The single-instance lock became machine-wide (`Global\`), blocking a second elevated instance
  in another session.

### Changed
- UPX compression disabled — reproducible builds and fewer antivirus false positives.
- Dependencies pinned to exact versions; build tooling split into `requirements-build.txt`.
- Removed a conflicting HKLM autostart entry from the installer; autostart is owned solely by the
  in-app toggle.

---

## 2.1.0 — 2026-07-02

Never shipped as a standalone release; these fixes reached users inside 2.2.0.

### Fixed
- **Decoy ClientHello was poisoning real handshakes.** The fake packet carried the real sequence
  number and valid checksums, relying only on a low TTL. Any server within six hops — most CDNs,
  Cloudflare, the Discord edge — accepted it as the genuine ClientHello, discarded the real
  fragments as duplicates, and completed TLS with the spoofed name. This was the main cause of
  the intermittent disconnects. The decoy now carries a deliberately invalid TCP checksum, so
  the server drops it while DPI, which does not verify L4 checksums, is still misled.
- **QUIC is refused instead of black-holed.** Silently dropping UDP/443 made HTTP/3-first apps
  wait out a long timeout before falling back to TCP — the roughly one-minute Discord reconnect.
  Each QUIC Initial is now answered locally with an ICMP port-unreachable, so the client drops to
  TCP at once.
- Crash-safe DNS journal: the original resolver is written to disk before any change and restored
  on the next launch, even after a force-kill.
- IPv6 DNS is only pinned on adapters that actually have IPv6 connectivity.

### Changed
- RST-drop protection now defaults to **off**. Dropping every inbound RST on 443/80 also swallows
  legitimate resets, leaving half-open sockets that hang until TCP times out.

---

## 2.0.0 — 2026-06-26

First V2 release. Where V1 handled Discord only, V2 is general purpose.

### Added
- Bypass-all and selective modes, with eight preset categories and custom domains.
- Secure DNS (Cloudflare / Google / Quad9).
- Four themes, eight languages, system tray, autostart via Task Scheduler.
- Local and private address ranges excluded from the bypass.
