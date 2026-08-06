# Changelog

All notable changes to HenkerDPI. Versions follow [semantic versioning](https://semver.org).

Downloads for every release are on the [releases page](https://github.com/Henkerr/HenkerDPI/releases);
each one publishes the SHA-256 of its assets.

---

## 2.7.0 — 2026-08-06

The app no longer ships a guess about which desync beats your ISP. It measures your line and
picks for you.

### Fixed
- **The default decoy was invisible to exactly the kind of DPI it exists to fool.** Since 2.5.0
  the decoy carried both a wrong checksum *and* a wrong sequence number. The wrong sequence
  number was added so that a NAT (iPhone USB tethering) recomputing checksums could not repair
  the decoy into a valid ClientHello. But a DPI that reassembles a TCP flow discards an
  out-of-window segment outright — so the spoofed hostname never entered its buffer and the
  decoy did nothing at all. On the fixed line measured today that left Discord unreachable under
  every split variant; switching the decoy back to a correct sequence number with a wrong
  checksum opened it on the first try. Both behaviours are still available — which one is right
  is now measured per network instead of hard-coded.
- **Correction to the 2.6.0 note below:** its claim that `record` "worked on both" networks was
  based on a diagnostic that resolved its targets over plain DNS on a line where plain DNS is
  intercepted, so the "discord" column was measuring the ISP's block-page server, not Discord.
  The diagnostic now resolves over HTTPS. Re-measured, no split setting works on that line
  without a correct-sequence decoy.

### Added
- **Automatic strategy selection (`autotune.py`) — no settings to edit, ever.** On the first run
  on a given network the engine finds a target the line actually blocks, tries the known
  strategies against it using the very same code path the engine uses in production, and keeps
  the first one that both defeats the block *and* leaves normal sites working. The winner is
  cached per network — fingerprinted by interface, gateway and gateway MAC — so later starts are
  instant.
- **Re-measures when the network changes.** Moving between a home line and a phone hotspot
  switches strategy on its own, which matters because the pair that is correct on one can break
  every HTTPS site on the other. Returning to a known network restores its cached pair with no
  probing.
- **A control check that can veto a strategy.** A candidate that opens the blocked site but
  breaks `google.com`/`cloudflare.com` is rejected. That is precisely the failure that broke every
  HTTPS site on tethering in 2.5.0, and it can no longer be selected.
- `split_mode: "none"` — no cut at all, decoy only. Measured to work where cutting does not.

### Changed
- `strategy_mode` in `settings.json` (default `"auto"`). Set it to `"manual"` to force the
  `decoy_mode`/`split_mode` values instead; for support and debugging only.
- The fallback pair, used only when a measurement cannot run at all, is now `badsum`/`record`.
- Deleting `%LOCALAPPDATA%\HenkerDPI\autotune.json` forces a fresh measurement.

---

## 2.6.0 — 2026-08-06

Measured on a second Turkish network, a fixed line where the app had never worked at all.

### Fixed
- **On an ISP that intercepts port 53, the DNS feature did nothing — silently.** Pointing the
  system resolver at Cloudflare only helps against an ISP that answers for its *own* resolver.
  This one answers for every resolver: `1.1.1.1`, `8.8.8.8` and `208.67.222.222` all returned the
  block-page address for `discord.com`. The app reported "secure DNS active" while resolving
  nothing correctly, so blocked sites stayed blocked no matter how well the DPI bypass worked.
  The app now switches on Windows' built-in DNS-over-HTTPS client for the resolver it pins, so
  queries leave the machine encrypted and cannot be answered by anyone else. Undone on stop.
- **The app never checked that the resolver it pinned was telling the truth.** The existing probe
  only asked "is it reachable" — an intercepted resolver is perfectly reachable, it just lies.
  Startup now resolves a probe domain twice, once over plain DNS and once over HTTPS to the same
  resolver, and compares. Interception is reported in the log instead of passing as success.

### Changed
- **Default `split_mode` is now `record`** (cut once, at the TLS record header). Two independent
  networks were measured: `sni` failed on both, `record` worked on both, `record+sni` worked only
  on the mobile one. More cuts turned out to be worse, not safer — on the fixed line every
  variant producing three or more segments was blocked and every two-segment variant got through.

### Added
- `system_doh_enabled` in `settings.json` (default `true`) to leave Windows' encrypted-DNS
  settings alone.
- `tools/teshis.py` + `teshis.spec` build a standalone diagnostic that measures which strategy
  beats the user's ISP and writes a report to their Desktop. It resolves targets over HTTPS and
  connects by IP, so its results measure the DPI block alone and are not confounded by DNS
  interception. It refuses to run while HenkerDPI is open, which would invalidate every reading.

---

## 2.5.0 — 2026-08-05

Both changes come from one live session on a Turkish mobile carrier (iPhone USB tethering), where
the app broke every HTTPS site while failing to bypass anything.

### Fixed
- **The decoy packet could take down every HTTPS site on a mobile connection.** The spoofed-SNI
  decoy is meant to be unusable by the server, and since 2.2.0 that was guaranteed by giving it a
  deliberately wrong TCP checksum. A NAT — a phone's tethering stack, a carrier's CGNAT — rewrites
  the source address on the way out and recomputes that checksum, which *repairs* the decoy. The
  server then accepts the fake ClientHello, discards the real fragments as duplicates, and the
  handshake transcript no longer matches: every site fails with "the message received was
  unexpected or badly formatted", including sites that were never blocked. Measured directly —
  Discord answered the repaired decoy with a TLS `handshake_failure` for the spoofed hostname.
  The decoy now also carries a sequence number far outside the receive window, which no NAT can
  repair, so all three defences (wrong seq, wrong checksum, low TTL) have to fail before a decoy
  can poison a handshake.

### Changed
- **The ClientHello is now cut at the TLS record header as well as inside the SNI.** A DPI that
  reassembles the flow still sees the whole hostname after an SNI-midpoint cut. On the mobile
  carrier tested, splitting mid-SNI was blocked on every attempt while splitting after the first
  byte got through on every attempt; cutting at both positions covers reassembling and
  non-reassembling DPI with a single strategy.

### Added
- `decoy_mode` and `split_mode` in `settings.json` for networks the defaults do not beat.
  `decoy_mode` is `both` (default), `badseq`, `badsum` or `off`; `split_mode` is `record+sni`
  (default), `record` or `sni` — `sni` restores the pre-2.5 cut.

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
