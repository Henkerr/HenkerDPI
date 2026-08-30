# Changelog

All notable changes to HenkerDPI. Versions follow [semantic versioning](https://semver.org).

Downloads for every release are on the [releases page](https://github.com/Henkerr/HenkerDPI/releases);
each one publishes the SHA-256 of its assets.

---

## 3.0.1 — 2026-08-31

A crash fix for the 3.0.0 WebView build.

### Fixed
- **3.0.0 could fail to start with "No module named 'unicodedata'" or "name
  'base_events' is not defined" (and "Failed to start embedded python
  interpreter").** The onefile exe opens its window and self-elevates by
  re-launching itself, and each re-launched copy inherited the PyInstaller
  bootloader's temp-folder handoff variables. So the window process and the
  engine process shared one `%TEMP%\_MEIxxxx` unpack folder, and whichever
  exited first deleted it out from under the other — which then crashed on its
  next import. Each re-launch now unpacks and owns a private folder. The bundle
  itself was always complete; nothing was missing from it.

A new interface: the window is now a WebView app with five selectable themes and
live switching between them, replacing the single Tk window.

### Added
- **Five-theme WebView UI** (Mevcut, Console, Bento, Arcade, Combat). An
  always-on engine/tray core keeps protecting while the window runs as a separate
  WebView process, so no browser engine is resident when the app sits in the
  tray; opening the window spawns it, closing it frees its memory. Each theme is
  a self-contained page and switching is live.
- The self-updater and its clickable tray notification now run in the WebView
  core too, so a copy sitting autostarted in the tray still learns about and
  installs a new release.

### Changed
- The shipped Windows exe is now built from the WebView app (`app.py`) rather
  than the Tk window (`gui.py`); the Tk build stays in the tree as a fallback.

### Known gaps
- Toggling "start on boot" and a few settings controls in the new UI are not
  wired yet. Anyone who already had autostart keeps it (the existing boot task is
  untouched); a fresh install's toggle is a no-op until a follow-up.

## 2.9.0 — 2026-08-28

Reliability and the update pipeline. The shipping app is still the Windows
desktop (Tk) build; the WebView UI listed under groundwork is not yet packaged.

### Added
- **A clickable Windows notification when an update is waiting.** The update
  banner only existed inside the window, so a copy launched by the boot task and
  left in the tray never told the user. A real notification is raised now and
  clicking it installs the update.
- **Automated Windows build (`.github/workflows/build-windows.yml`).** Builds the
  onefile exe on a Windows runner and attaches `HenkerDPI.exe` + its SHA-256 to
  the release on a tag, so the self-updater finally has an asset to find — until
  now only the macOS DMGs were ever published.

### Groundwork (not yet user-facing)
- **On-demand WebView UI (first slice).** An always-on engine/tray core with the
  window as a separate WebView process, so no browser engine is resident while
  the app sits in the tray. Console theme wired end-to-end with a live, flowing
  event log and working Bypass/Engel filters — not yet packaged into a build.
- The engine now records QUIC refusals as an "engel" event for that live log, so
  its QUIC→TCP downgrades are visible rather than silent.

### Fixed
- **Windows: a wired→phone-hotspot switch stopped bypassing blocked sites, and restarting did not
  reliably fix it.** Four separate gaps, all worse on mobile, broke the "measures every line and
  self-configures" promise:
  - **The measurement counted a TLS alert as a working handshake, so it selected the very strategy
    that breaks the line.** `tls_reachable` treated a first response byte of `0x16` (ServerHello)
    *or* `0x15` (a TLS **alert**) as "opened". On an iPhone-USB line the NAT repairs the `badsum`
    decoy, the server then rejects the poisoned handshake with an alert — and the probe read that
    `0x15` as success. So `badsum`/`record` looked like it opened Discord *and* passed the
    google/cloudflare control check, was cached as a winner (`ok:true`), and then corrupted every
    IPv4 handshake in production. Only sites reachable over IPv6 (which the IPv4-only engine never
    touches) kept working, which is exactly why it looked like "just the blocked sites broke". A
    real ServerHello (`0x16`) is now the only success, so a handshake-poisoning strategy can neither
    be selected nor pass the control check. This was the root cause on the line measured live.
  - **Secure DNS was pinned only to the adapter present at engine start.** When the active network
    changed, only the desync strategy was re-measured; the new adapter kept the carrier's resolver,
    which on a blocking ISP hijacks the very domains being bypassed — so blocked sites stayed
    blocked while everything else worked. DNS is now re-pinned to the now-active adapter on a
    network change (the old adapter is restored from the journal first).
  - **A network change did not force a re-measurement.** The per-network cache was read with
    `force=False`, so a moved-to line was served a stale entry rather than measured (macOS already
    forced it; Windows now matches). A false "no block detected" is also no longer pinned for seven
    days — it keeps a short TTL, so a line mis-measured once (e.g. because DNS interception or mobile
    latency fooled the probe) re-measures on the next start or network change instead of being stuck
    doing nothing for a week.
  - **The unmeasurable-line fallback was the one pair that breaks over tethering.** When a
    measurement could not run (offline, or no candidate beat the block), the engine fell back to
    `badsum`/`record`. On an iPhone/carrier NAT the bad checksum is repaired in transit, the decoy
    then reaches the server as a valid ClientHello, and *every* HTTPS site breaks. The fallback is
    now the NAT-safe `badseq`/`record`: its decoy sits outside the receive window, so the server
    always drops it and no handshake is ever poisoned.

- **The build's version drifted out of sync.** `config.APP_VERSION` is what the
  updater compares against the latest release, but it lived in three hand-synced
  places (config.py, version_info.txt, setup.iss) and had fallen behind the
  shipped exe, so the updater judged releases against a version nobody was
  running. A test now fails the build when the three disagree.

## 2.8.0 — 2026-08-09

macOS is supported again, as a real build rather than an experiment.

### Added
- **macOS 11+ on Apple Silicon and Intel.** It is not the Windows engine recompiled. macOS has no
  WinDivert and its `pf` is a fork of OpenBSD pf 4.1 with no `divert-to`, so there is nothing to
  intercept an outbound ClientHello with. The Mac build instead runs a desync proxy on `127.0.0.1`
  and registers it with macOS as a proxy auto-config (PAC) URL, reshaping each TLS handshake as it
  forwards it. Traffic still never leaves the machine for anyone else's server.
- A PAC rather than a fixed proxy setting, deliberately: macOS treats an unreachable PAC as "no
  proxy", so a crash costs the bypass and nothing else. Every `PROXY` decision the PAC returns also
  carries a `DIRECT` fallback, which covers the case a browser has already cached the PAC body and
  the listener behind it is gone.
- `.github/workflows/build-macos.yml` builds and attaches an arm64 and an x86_64 DMG on a real
  macOS runner, since the bundle cannot be cross-built from Windows.
- Recovery script shipped in the DMG (`Ag Ayarlarini Geri Yukle.command`) that clears every proxy
  mechanism per network service, for the case the app never got to undo its own change.
- **The proxy is published to the login session's environment as well as the PAC.** A PAC only
  reaches software that implements PAC, and Discord's updater does not: it is a Rust binary whose
  HTTP client reads the *fixed* proxy keys only. Measured on a Turkish line, it saw no proxy at all,
  connected directly, and the DPI reset every handshake — `hyper::Error(Connect, code: -9806)` every
  30 seconds — so Discord never got past its update screen on the one service this tool exists for.
  Setting the fixed system proxy instead would have fixed that and broken something worse: Chromium
  reads the PAC and the fixed rules into one config and falls back to the fixed rules when the PAC
  cannot be fetched, so a HenkerDPI that died would take every browser down with
  `ERR_PROXY_CONNECTION_FAILED` — exactly the failure the PAC was chosen to rule out. The session
  environment reaches the same programs (reqwest, Go, curl, git, npm) while Chromium and CFNetwork
  ignore it, needs no privileges, and does not survive a logout, so the worst a force-kill can leave
  behind expires by itself. Software that reads neither the PAC nor the environment is still not
  covered; nothing available to an unprivileged process on macOS reaches it.

- **A menu-bar item, and a login item.** Closing the window no longer quits the app on a Mac: it
  leaves an icon in the menu bar, left-click to bring the window back, right-click for start/stop and
  quit. The window is only ever hidden once that icon actually exists — withdrawing it without one
  would leave the app running, invisible, with the single-instance lock refusing a relaunch. Clicking
  the Dock icon restores it too. Start-at-login installs a LaunchAgent in the user's own directory
  and needs no privileges; a separate switch decides whether it also turns the bypass on, off by
  default because that step needs an administrator prompt and one that appears by itself at every
  login is worse than one click.
- The macOS build now ships the same Tcl/Tk the app is developed against. CI used to build against
  Tk 8.6, whose aqua port has no `tk systray` at all, so the menu-bar item would have worked in
  development and been silently missing from every DMG. The workflow fails the build if the version
  ever drops back.

### Fixed
- The menu-bar icon was scaled with Tk's `subsample`, which is nearest-neighbour: from 512 to 22 it
  keeps one pixel in 23 and discards the rest, turning a detailed mark into noise at exactly the size
  where detail is all there is. It is resampled properly now.
- The app icon is still mastered at 512 px while macOS' iconset table asks for 1024, so the build
  enlarges it and a Retina Mac shows it slightly soft in the Dock and in Finder. Sharpening it needs
  the original artwork at a higher resolution: `tools/make_wolf_mark.py` is an unused alternative
  mark — its own docstring says so — and regenerating from it replaces the logo rather than sharpens
  it.
- **Re-applying the proxy overwrote the record of the user's original settings.** Switching mode or
  toggling a category re-applies while the engine is running, and the snapshot taken at that moment
  reads back HenkerDPI's own PAC. It was then written down as what to restore to, so quitting
  reinstalled a dead PAC and the user's real proxy and bypass-domain list were gone for good. The
  record is now written once.
- Quitting reported "proxy off" without turning it off when that record was missing: the restore
  script came out empty and an empty script was read as success. The Mac now falls back to clearing
  the PAC from every service.
- Quitting could skip the restore entirely. Cleanup ran under a non-blocking lock, so the exit
  handler returned immediately while the engine thread was still inside the password prompt, and
  interpreter shutdown then froze that thread mid-restore.
- **Cmd-Q and Dock ▸ Quit skipped the restore.** Tk turns the Quit Apple Event straight into
  `Tcl_Exit` unless `::tk::mac::Quit` is defined, so neither ever reached `_quit()` or the
  engine-thread join behind it — the two most natural ways to close a Mac app were the two that left
  it pointed at a proxy that was gone.
- **`(null)` was written into System Settings as a PAC URL.** `networksetup -getautoproxyurl`
  reports a service with no URL as the literal string `(null)`, which is truthy, so the restore ran
  `-setautoproxyurl <service> '(null)'` and left that permanently visible in the user's network
  settings. Cleaned on the way in and on the way out, because journals written by the earlier build
  already contain it and those are the ones a restore has to heal.
- The tray is switched off on macOS rather than left to chance. pystray drives an `NSStatusItem`,
  AppKit allows that only from the main thread, and tkinter's event loop owns it — so on a
  from-source install that happened to have pystray, closing the window withdrew it and left the
  user no way to get it back. It is no longer a dependency there either.
- `pip install -r requirements.txt` could not complete on macOS: `pydivert` ships the Windows packet
  driver and is unconditional. It and `pystray` now carry `sys_platform == "win32"` markers, so the
  documented from-source path works on both platforms.

### Changed
- The updater tells a Mac about a new version and opens the release page instead of installing it.
  An `.app` is a signed bundle, not a single file: swapping it from inside itself would invalidate
  its signature and leave an app that cannot launch at all.
- Download page and README no longer promise self-installing updates on both platforms, and the
  macOS first-run instructions now use **System Settings → Privacy & Security → Open Anyway**.
  macOS 15 removed the right-click-Open shortcut the old instructions relied on.

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
