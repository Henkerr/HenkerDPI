"""
HenkerDPI - Configuration
General-purpose DPI bypass. All sites or category-based filtering.
"""

import json
import os
import sys

# Single source of truth for the running build's version. Keep in sync with
# version_info.txt (FileVersion) and setup.iss (AppVersion) when releasing —
# updater.py compares this against the latest GitHub release tag.
APP_VERSION = "2.7.0"

# Repository the updater queries. Both are validated at download time so a
# tampered API response cannot point the downloader at an arbitrary host.
GITHUB_REPO = "Henkerr/HenkerDPI"
RELEASE_ASSET_NAME = "HenkerDPI.exe"

# PyInstaller onefile: __file__ points inside the ephemeral _MEIxxxx temp dir
# Windows deletes on exit, so the exe's own directory is the pre-2.3 anchor.
if getattr(sys, 'frozen', False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))


def state_dir() -> str:
    """Per-user writable directory for preferences and the DNS journal.

    An installed build lives under Program Files, where writing next to the exe
    requires admin, makes preferences machine-wide instead of per-user, and can
    be refused outright by Controlled Folder Access. %LOCALAPPDATA% is the right
    home for both; fall back to the app dir only if it cannot be created.
    """
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "HenkerDPI")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        return _APP_DIR
    return d


STATE_DIR = state_dir()


def resolve_pref(filename: str) -> str:
    """Path for a preference file, migrating a pre-2.3 copy left beside the exe.

    Builds up to 2.2 wrote preferences next to the executable. Move such a file
    on first run of 2.3 so upgrading users keep their mode, theme and language
    instead of silently reverting to defaults.
    """
    new = os.path.join(STATE_DIR, filename)
    old = os.path.join(_APP_DIR, filename)
    if old != new and not os.path.exists(new) and os.path.exists(old):
        try:
            os.replace(old, new)
        except OSError:
            try:
                with open(old, "rb") as src, open(new, "wb") as dst:
                    dst.write(src.read())
            except OSError:
                return old
    return new


SETTINGS_FILE = resolve_pref("settings.json")
CUSTOM_DOMAINS_FILE = resolve_pref("custom_domains.json")

# === Bypass Modes ===
# "all"        — Bypass all HTTPS traffic (like Warp/VPN)
# "selective"  — Only bypass selected categories + custom domains
MODE_ALL = "all"
MODE_SELECTIVE = "selective"

# === Preset Categories ===
# Commonly blocked or restricted websites by region
CATEGORIES = {
    "social": {
        "name": "Social Media",
        "icon": "social",
        "domains": [
            "twitter.com", "x.com", "abs.twimg.com", "pbs.twimg.com",
            "t.co", "twimg.com",
            "instagram.com", "cdninstagram.com", "fbcdn.net",
            "facebook.com", "fbcdn.com", "fb.com",
            "tiktok.com", "tiktokcdn.com", "musical.ly",
            "snapchat.com", "sc-cdn.net",
            "linkedin.com", "licdn.com",
            "pinterest.com", "pinimg.com",
            "threads.net",
        ],
    },
    "discord": {
        "name": "Discord",
        "icon": "discord",
        "domains": [
            "discord.com", "discordapp.com", "discord.gg",
            "discord.media", "discordapp.net", "discord.new",
            "dis.gd", "gateway.discord.gg", "cdn.discordapp.com",
            "media.discordapp.net", "images-ext-1.discordapp.net",
            "images-ext-2.discordapp.net", "dl.discordapp.net",
            "status.discord.com", "updates.discord.com",
            "latency.discord.media", "router.discordapp.net",
        ],
    },
    "video": {
        "name": "Video / Streaming",
        "icon": "video",
        "domains": [
            "youtube.com", "youtu.be", "googlevideo.com",
            "ytimg.com", "yt3.ggpht.com", "youtube-nocookie.com",
            "twitch.tv", "jtvnw.net", "ttvnw.net",
            "vimeo.com", "vimeocdn.com",
            "dailymotion.com",
        ],
    },
    "wiki": {
        "name": "Knowledge / Wiki",
        "icon": "wiki",
        "domains": [
            "wikipedia.org", "wikimedia.org", "wikidata.org",
            "mediawiki.org", "wikimediafoundation.org",
            "reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
            "medium.com",
            "archive.org", "web.archive.org",
            "quora.com",
        ],
    },
    "dev": {
        "name": "Developer",
        "icon": "dev",
        "domains": [
            "github.com", "githubusercontent.com", "githubassets.com",
            "gitlab.com",
            "stackoverflow.com", "stackexchange.com",
            "npmjs.com", "pypi.org",
            "pastebin.com", "hastebin.com",
            "codepen.io", "jsfiddle.net",
        ],
    },
    "media": {
        "name": "News / Media",
        "icon": "media",
        "domains": [
            "bbc.com", "bbc.co.uk",
            "dw.com",
            "voanews.com",
            "nytimes.com",
            "theguardian.com",
            "reuters.com",
            "aljazeera.com",
        ],
    },
    "vpn": {
        "name": "VPN / Proxy",
        "icon": "vpn",
        "domains": [
            "nordvpn.com", "expressvpn.com", "surfshark.com",
            "protonvpn.com", "proton.me",
            "windscribe.com", "mullvad.net",
            "torproject.org",
            "1.1.1.1", "one.one.one.one",
            "cloudflare-dns.com",
        ],
    },
    "ai": {
        "name": "AI Services",
        "icon": "ai",
        "domains": [
            "openai.com", "chat.openai.com", "chatgpt.com",
            "anthropic.com", "claude.ai",
            "gemini.google.com", "bard.google.com",
            "perplexity.ai",
            "huggingface.co",
        ],
    },
}

# === Secure DNS resolvers (GUI labels) ===
# The app repoints the system resolver to one of these public servers, and
# since 2.6.0 also switches on Windows' built-in DNS-over-HTTPS client for it
# (doh.enable_system_doh) so the queries actually leave the machine encrypted —
# required against an ISP that intercepts port 53 for every resolver, where
# changing the address alone does nothing. Set "system_doh_enabled": false to
# repoint the resolver only, leaving Windows' encrypted-DNS settings untouched.
# The actual resolver addresses (v4 + v6) live in doh.py PROVIDERS — these
# entries only supply the display name and the IP shown in the UI.
DOH_PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare",
        "ip": "1.1.1.1",
    },
    "google": {
        "name": "Google",
        "ip": "8.8.8.8",
    },
    "quad9": {
        "name": "Quad9",
        "ip": "9.9.9.9",
    },
}

# Ports
TARGET_PORTS = [443, 80]

# DPI bypass parameters
FAKE_TTL = 6

# Logging
VERBOSE = False


# === Settings Load/Save ===

def _default_settings():
    return {
        "mode": MODE_ALL,
        "enabled_categories": list(CATEGORIES.keys()),
        "doh_enabled": True,
        "doh_provider": "cloudflare",
        # Kernel DROP knobs. RST-drop is OFF by default: fragmentation is the
        # primary bypass and works without it, while blanket-dropping every
        # inbound RST on 443/80 also kills LEGITIMATE server resets and leaves
        # half-open sockets (a cause of intermittent hangs). QUIC-drop stays on
        # but only in ALL mode — in selective mode a system-wide UDP/443 kill is
        # pure collateral for traffic we are not bypassing.
        "rst_drop_enabled": False,
        "quic_drop_enabled": True,
        "quic_drop_all_mode_only": True,
        # EXPERIMENTAL, default OFF. When True the engine also diverts IPv6
        # TCP/443 ClientHellos and refuses IPv6 QUIC so DPI is bypassed on
        # dual-stack sites too. Off by default because the IPv4 path is the
        # proven, drop-free one; enable only if IPv6-reachable sites open
        # inconsistently. Toggle by editing settings.json (no GUI switch).
        "ipv6_bypass_enabled": False,
        # Desync tuning. Which combination beats a DPI — and which one BREAKS
        # every HTTPS site because a NAT on the path repairs the decoy — differs
        # per network, so there is no single correct default to ship. In "auto"
        # (the default) the app measures its own line on first use of a network,
        # caches the winner per network and re-checks when the network changes;
        # the user never picks anything. Set "strategy_mode" to "manual" to force
        # the decoy_mode/split_mode below instead (support/debug only).
        "strategy_mode": "auto",
        # Used when strategy_mode == "manual", and as the fallback if a
        # measurement cannot run at all. This pair is the longest-standing
        # confirmed one: right sequence number so a reassembling DPI swallows the
        # decoy, wrong checksum so the server never does.
        "decoy_mode": "badsum",
        "split_mode": "record",
        # Turn on Windows' built-in DNS-over-HTTPS client for the resolver this
        # app pins. Required on ISPs that intercept port 53 for every resolver,
        # where changing the DNS server address alone does nothing. Set False to
        # leave Windows' encrypted-DNS settings untouched.
        "system_doh_enabled": True,
        # Ask GitHub once a day whether a newer release exists. Set False to
        # stop the app making any outbound request of its own.
        "update_check_enabled": True,
    }


def _atomic_write_json(path: str, data) -> None:
    """Write JSON atomically: temp file + fsync + os.replace.

    A crash or force-kill mid-write can never leave a truncated/corrupt file
    (which the loaders would otherwise silently treat as "missing" and reset
    the user's config back to defaults).
    """
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_settings_file(path: str) -> dict:
    """Load one settings file merged onto defaults. Raises if missing/corrupt.

    Rejects valid-JSON-but-non-object content (a list/number/string) so a
    dict.update() TypeError can never escape and crash startup.
    """
    with open(path, "r") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("settings file is not a JSON object")
    merged = _default_settings()
    merged.update(data)
    return merged


def load_settings() -> dict:
    # Try the live file, then the rolling backup (covers the brief window during
    # save where the live file has been renamed to .bak but not yet rewritten),
    # then fall back to defaults. Any missing/corrupt/non-object file is skipped.
    for path in (SETTINGS_FILE, SETTINGS_FILE + ".bak"):
        try:
            return _read_settings_file(path)
        except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
            continue
    return _default_settings()


def save_settings(settings: dict):
    # Keep a rolling backup of the last known-good file, then write atomically.
    try:
        if os.path.exists(SETTINGS_FILE):
            os.replace(SETTINGS_FILE, SETTINGS_FILE + ".bak")
    except OSError:
        pass
    _atomic_write_json(SETTINGS_FILE, settings)


# === Custom Domains ===

def load_custom_domains() -> list[str]:
    try:
        with open(CUSTOM_DOMAINS_FILE, "r") as f:
            domains = json.load(f)
            if isinstance(domains, list):
                return [d.strip().lower() for d in domains if d.strip()]
    except Exception:
        pass
    return []


def save_custom_domains(domains: list[str]):
    _atomic_write_json(CUSTOM_DOMAINS_FILE, domains)


def get_category_domains(enabled_categories: list[str]) -> list[str]:
    """Collect all domains from enabled categories."""
    domains = []
    for cat_key in enabled_categories:
        if cat_key in CATEGORIES:
            domains.extend(CATEGORIES[cat_key]["domains"])
    return domains


def get_all_domains(settings: dict = None) -> list[str]:
    """Return domain list based on current mode."""
    if settings is None:
        settings = load_settings()
    cats = get_category_domains(settings.get("enabled_categories", []))
    customs = load_custom_domains()
    return cats + customs
