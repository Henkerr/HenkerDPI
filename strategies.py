"""
HenkerDPI V2 - DPI Bypass Strategies
TTL-based fake packet + reverse TCP fragmentation.
General-purpose — all sites or selected domains.
"""

import struct
import socket
import pydivert
from config import get_all_domains, load_settings, MODE_ALL

FAKE_TTL = 5  # Reaches DPI but expires before reaching the server

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
    """Find the byte offset where SNI hostname starts in payload."""
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


def _build_packet(headers: bytes, payload_data: bytes, ip_hlen: int,
                  seq: int, ack: int, interface, direction, ttl: int = 0):
    """Build a standalone TCP packet. ttl=0 keeps original TTL."""
    raw = bytearray(headers) + bytearray(payload_data)
    struct.pack_into("!H", raw, 2, len(raw))  # IP total length
    struct.pack_into("!I", raw, ip_hlen + 4, seq & 0xFFFFFFFF)  # TCP seq
    struct.pack_into("!I", raw, ip_hlen + 8, ack & 0xFFFFFFFF)  # TCP ack
    if ttl > 0:
        raw[8] = ttl  # IP TTL
    struct.pack_into("!H", raw, 10, 0)  # IP checksum -> 0
    struct.pack_into("!H", raw, ip_hlen + 16, 0)  # TCP checksum -> 0
    return pydivert.Packet(raw, interface=interface, direction=direction)


def tcp_fragment_and_send(w, packet, sni: str, verbose: bool = False) -> bool:
    """
    DPI bypass via SNI-midpoint fragmentation + disorder:
    1) Fake packet with low TTL + spoofed SNI (confuses DPI state)
    2) Send fragment 2 first (out-of-order — DPI can't reassemble)
    3) Send fragment 1 last (contains first half of real SNI)
    Original packet is NOT sent — caller must drop it.
    """
    payload = bytes(packet.payload)
    if len(payload) < 10:
        return False

    orig_raw = bytes(packet.raw)
    ip_hlen = (orig_raw[0] & 0x0F) * 4
    tcp_hlen = ((orig_raw[ip_hlen + 12] >> 4) & 0xF) * 4
    headers = orig_raw[:ip_hlen + tcp_hlen]

    orig_seq = struct.unpack_from("!I", orig_raw, ip_hlen + 4)[0]
    orig_ack = struct.unpack_from("!I", orig_raw, ip_hlen + 8)[0]

    iface = packet.interface
    direction = packet.direction

    # Find where SNI hostname sits in the payload and split there
    sni_bytes = sni.encode("ascii")
    sni_pos = payload.find(sni_bytes)
    if sni_pos != -1:
        # Split right in the middle of the SNI hostname
        split_pos = sni_pos + len(sni_bytes) // 2
    else:
        # Fallback: split at 1/3 of payload
        split_pos = len(payload) // 3

    split_pos = max(1, min(split_pos, len(payload) - 1))

    # Build fake payload with spoofed SNI
    if sni_pos != -1:
        fake_domain = ("www.w3.org" + "w" * len(sni))[:len(sni)]
        fake_payload = (payload[:sni_pos]
                        + fake_domain.encode("ascii")
                        + payload[sni_pos + len(sni_bytes):])
    else:
        fake_payload = payload

    # 1) FAKE: low TTL + spoofed SNI — reaches DPI but expires before server
    fake = _build_packet(headers, fake_payload, ip_hlen,
                         orig_seq, orig_ack,
                         iface, direction, ttl=FAKE_TTL)
    w.send(fake)

    # 2) FRAGMENT 2 FIRST (disorder — DPI can't reassemble out-of-order)
    frag2 = _build_packet(headers, payload[split_pos:], ip_hlen,
                          orig_seq + split_pos, orig_ack,
                          iface, direction)
    w.send(frag2)

    # 3) FRAGMENT 1 (contains first half of real SNI)
    frag1 = _build_packet(headers, payload[:split_pos], ip_hlen,
                          orig_seq, orig_ack,
                          iface, direction)
    w.send(frag1)

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
