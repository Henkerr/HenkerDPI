"""ClientHello parsing and bypass-scope policy — no platform dependencies.

These four decisions ("what hostname is this connection for, and is it ours to
touch?") are identical on every platform, but they used to live in strategies.py
next to the WinDivert packet builders. That module cannot even be imported
without pydivert, so the first macOS port copied all of it — and the copy went
17 commits stale before it was abandoned. Keeping the shared half here is what
lets the macOS engine reuse this logic instead of forking it again.
"""

import struct

from config import MODE_ALL

# Local/private IP ranges that should never be bypassed.
# 169.254/16 is link-local (APIPA); 100.64/10 is carrier-grade NAT, which many
# mobile ISPs hand out — fragmenting a handshake to a CGNAT-internal host is
# pointless and can break captive portals.
_SKIP_PREFIXES = (
    "127.", "10.", "0.", "169.254.",
    "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
) + tuple(f"100.{n}." for n in range(64, 128))
_SKIP_SNIS = {"localhost", "localhost.localdomain", "wpad"}


def extract_sni(data: bytes) -> str | None:
    """Extract SNI hostname from TLS ClientHello packet."""
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        offset = 5
        if data[offset] != 0x01:
            return None
        offset += 4 + 2 + 32
        session_id_len = data[offset]
        offset += 1 + session_id_len
        cipher_suites_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2 + cipher_suites_len
        comp_methods_len = data[offset]
        offset += 1 + comp_methods_len
        if offset + 2 > len(data):
            return None
        extensions_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        end = offset + extensions_len
        while offset + 4 <= end:
            ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == 0x0000:
                if offset + 5 > len(data):
                    return None
                sni_len = struct.unpack("!H", data[offset + 3:offset + 5])[0]
                # If the SNI value straddles the TCP segment boundary, the
                # ClientHello is split across packets — return None so the
                # caller forwards this segment untouched rather than reading a
                # truncated hostname or fragmenting a partial handshake.
                if offset + 5 + sni_len > len(data):
                    return None
                return data[offset + 5:offset + 5 + sni_len].decode("ascii")
            offset += ext_len
    except (IndexError, struct.error, UnicodeDecodeError):
        pass
    return None


def _is_local_sni(sni: str) -> bool:
    """Exclude local/private network addresses from bypass."""
    if sni in _SKIP_SNIS:
        return True
    # Check if it's a local IP address
    if sni[0].isdigit():
        return sni.startswith(_SKIP_PREFIXES)
    # Local domain suffixes
    if sni.endswith((".local", ".internal", ".lan", ".home")):
        return True
    return False


def domain_matches(sni: str, domain_set: set) -> bool:
    """O(label) suffix match against a precomputed domain set.

    Matches the host itself and every parent domain, e.g.
    cdn.media.discordapp.net -> media.discordapp.net -> discordapp.net -> net.
    """
    if sni in domain_set:
        return True
    idx = sni.find(".")
    while idx != -1:
        if sni[idx + 1:] in domain_set:
            return True
        idx = sni.find(".", idx + 1)
    return False


def should_bypass_fast(sni: str | None, mode: str, domain_set: set) -> bool:
    """Hot-path bypass decision using a cached (mode, domain_set).

    Does NO disk I/O and rebuilds no list per packet — the engine precomputes
    the domain set once on start/reload.
    """
    if not sni:
        return False
    if _is_local_sni(sni):
        return False
    if mode == MODE_ALL:
        return True
    return domain_matches(sni, domain_set)
