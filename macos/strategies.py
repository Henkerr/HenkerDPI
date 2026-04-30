"""
HenkerDPI V2 macOS - DPI Bypass Strategies
TTL-based fake packet + reverse TCP fragmentation.
General-purpose — all sites or selected domains.
Uses raw sockets instead of WinDivert.
"""

import struct
import socket
from config import get_all_domains, load_settings, MODE_ALL

FAKE_TTL = 6  # DPI'ya ulasir ama sunucuya ulasmadan olur

# Local/private IP ranges that should never be bypassed
_SKIP_PREFIXES = (
    "127.", "10.", "0.",
    "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.",
)
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
        while offset + 4 < end:
            ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == 0x0000:
                sni_len = struct.unpack("!H", data[offset + 3:offset + 5])[0]
                return data[offset + 5:offset + 5 + sni_len].decode("ascii")
            offset += ext_len
    except (IndexError, struct.error):
        pass
    return None


def find_sni_offset(data: bytes) -> int | None:
    """Find the byte offset where SNI hostname starts in TLS ClientHello."""
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
        while offset + 4 < end:
            ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
            ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == 0x0000:
                return offset + 5
            offset += ext_len
    except (IndexError, struct.error):
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


def should_bypass(sni: str | None, settings: dict = None) -> bool:
    """
    Decide whether to bypass based on mode:
    - "all": Every TLS ClientHello is bypassed (except local)
    - "selective": Only enabled categories + custom domains
    """
    if sni is None:
        return False

    # Never bypass local/private addresses
    if _is_local_sni(sni):
        return False

    if settings is None:
        settings = load_settings()

    # ALL mode: bypass everything
    if settings.get("mode") == MODE_ALL:
        return True

    # SELECTIVE mode: check domain list
    domains = get_all_domains(settings)
    return any(sni == domain or sni.endswith("." + domain) for domain in domains)


def _checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_and_send(raw_sock, src_ip, dst_ip, sport, dport,
                    seq, ack, flags, payload, ttl=64):
    """Build a complete IP+TCP packet and send via raw socket."""
    # TCP header (20 bytes, no options)
    data_offset = 5 << 4
    window = 65535
    tcp_header = struct.pack("!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        data_offset, flags, window, 0, 0)

    # TCP checksum (pseudo header)
    pseudo = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, len(tcp_header) + len(payload))
    tcp_cksum = _checksum(pseudo + tcp_header + payload)
    tcp_header = struct.pack("!HHIIBBHHH",
        sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        data_offset, flags, window, tcp_cksum, 0)

    # IP header (20 bytes)
    total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0x4000,
        ttl, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_cksum = _checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0x4000,
        ttl, 6, ip_cksum,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    packet = ip_header + tcp_header + payload
    try:
        raw_sock.sendto(packet, (dst_ip, 0))
    except Exception:
        pass


def tcp_fragment_and_send(raw_sock, src_ip, dst_ip, sport, dport,
                          seq, ack, flags, payload, sni,
                          verbose=False) -> bool:
    """
    macOS DPI bypass: SNI-midpoint fragmentation + disorder.
    1) Fake packet with low TTL + spoofed SNI (confuses DPI state)
    2) Send fragment 2 first (out-of-order — DPI can't reassemble)
    3) Send fragment 1 last (contains first half of real SNI)
    Note: Original packet is NOT dropped on macOS (scapy sniff limitation).
    """
    if len(payload) < 10:
        return False

    sni_bytes = sni.encode("ascii")
    sni_pos = payload.find(sni_bytes)
    if sni_pos != -1:
        split_pos = sni_pos + len(sni_bytes) // 2
    else:
        split_pos = len(payload) // 3

    split_pos = max(1, min(split_pos, len(payload) - 1))

    # Fake payload with spoofed SNI
    if sni_pos != -1:
        fake_domain = ("www.w3.org" + "w" * len(sni))[:len(sni)]
        fake_payload = (payload[:sni_pos]
                        + fake_domain.encode("ascii")
                        + payload[sni_pos + len(sni_bytes):])
    else:
        fake_payload = payload

    # === 1) FAKE: low TTL + spoofed SNI ===
    _build_and_send(raw_sock, src_ip, dst_ip, sport, dport,
                    seq, ack, flags, fake_payload, ttl=FAKE_TTL)

    # === 2) FRAGMENT 2 FIRST (disorder) ===
    _build_and_send(raw_sock, src_ip, dst_ip, sport, dport,
                    seq + split_pos, ack, flags, payload[split_pos:])

    # === 3) FRAGMENT 1 ===
    _build_and_send(raw_sock, src_ip, dst_ip, sport, dport,
                    seq, ack, flags, payload[:split_pos])

    return True


def extract_http_host(data: bytes) -> str | None:
    """Extract HTTP Host header from plaintext HTTP request."""
    try:
        text = data.decode("ascii", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None
