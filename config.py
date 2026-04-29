"""
HenkerDPI V2 - Configuration
Genel amaçlı DPI bypass. Tüm siteler veya kategori bazlı.
"""

import json
import os
import sys

# PyInstaller onefile: exe'nin yanına yaz
if getattr(sys, 'frozen', False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))

SETTINGS_FILE = os.path.join(_APP_DIR, "settings.json")
CUSTOM_DOMAINS_FILE = os.path.join(_APP_DIR, "custom_domains.json")

# === Bypass Modları ===
# "all"        — Tüm HTTPS trafiğini bypass et (Warp gibi)
# "selective"  — Sadece seçili kategoriler + custom domainler
MODE_ALL = "all"
MODE_SELECTIVE = "selective"

# === Preset Kategoriler ===
# Türkiye'de engelli veya zaman zaman engellenen siteler
CATEGORIES = {
    "social": {
        "name": "Sosyal Medya",
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
        "name": "Bilgi / Wiki",
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
        "name": "Geliştirici",
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
        "name": "Medya / Haber",
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
        "name": "AI Servisleri",
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

# === DNS-over-HTTPS Providers ===
DOH_PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare",
        "url": "https://cloudflare-dns.com/dns-query",
        "ip": "1.1.1.1",
    },
    "google": {
        "name": "Google",
        "url": "https://dns.google/dns-query",
        "ip": "8.8.8.8",
    },
    "quad9": {
        "name": "Quad9",
        "url": "https://dns.quad9.net/dns-query",
        "ip": "9.9.9.9",
    },
}

# Ports
TARGET_PORTS = [443, 80]

# DPI bypass parametreleri
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
    }


def load_settings() -> dict:
    try:
        with open(SETTINGS_FILE, "r") as f:
            data = json.load(f)
            defaults = _default_settings()
            defaults.update(data)
            return defaults
    except Exception:
        return _default_settings()


def save_settings(settings: dict):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


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
    with open(CUSTOM_DOMAINS_FILE, "w") as f:
        json.dump(domains, f, indent=2)


def get_category_domains(enabled_categories: list[str]) -> list[str]:
    """Aktif kategorilerdeki tüm domainleri topla."""
    domains = []
    for cat_key in enabled_categories:
        if cat_key in CATEGORIES:
            domains.extend(CATEGORIES[cat_key]["domains"])
    return domains


def get_all_domains(settings: dict = None) -> list[str]:
    """Mode'a göre domain listesi döndür."""
    if settings is None:
        settings = load_settings()
    cats = get_category_domains(settings.get("enabled_categories", []))
    customs = load_custom_domains()
    return cats + customs
