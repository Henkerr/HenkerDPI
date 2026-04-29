"""
HenkerDPI V2 - DPI Bypass Strategies
TTL-based fake packet + reverse TCP fragmentation.
Genel amaçlı — tüm siteler veya seçili domainler.
"""

import struct
import pydivert
from config import get_all_domains, load_settings, MODE_ALL

FAKE_TTL = 6  # DPI'ya ulaşır ama sunucuya ulaşmadan ölür


def extract_sni(data: bytes) -> str | None:
    """TLS ClientHello paketinden SNI hostname çıkar."""
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
    """SNI hostname'in payload içindeki byte offset'ini bul."""
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


def should_bypass(sni: str | None, settings: dict = None) -> bool:
    """
    Mode'a göre bypass kararı ver:
    - "all": Her TLS ClientHello bypass edilir
    - "selective": Sadece aktif kategoriler + custom domainler
    """
    if sni is None:
        return False
    if settings is None:
        settings = load_settings()

    # ALL modu: her şeyi bypass et
    if settings.get("mode") == MODE_ALL:
        return True

    # SELECTIVE modu: domain listesini kontrol et
    domains = get_all_domains(settings)
    return any(sni == domain or sni.endswith("." + domain) for domain in domains)


def _build_packet(headers: bytes, payload_data: bytes, ip_hlen: int,
                  seq: int, ack: int, interface, direction, ttl: int = 0):
    """TCP paketi oluştur. ttl=0 orijinal TTL'yi korur."""
    raw = bytearray(headers) + bytearray(payload_data)
    struct.pack_into("!H", raw, 2, len(raw))  # IP total length
    struct.pack_into("!I", raw, ip_hlen + 4, seq & 0xFFFFFFFF)  # TCP seq
    struct.pack_into("!I", raw, ip_hlen + 8, ack & 0xFFFFFFFF)  # TCP ack
    if ttl > 0:
        raw[8] = ttl  # IP TTL
    struct.pack_into("!H", raw, 10, 0)  # IP checksum → 0
    struct.pack_into("!H", raw, ip_hlen + 16, 0)  # TCP checksum → 0
    return pydivert.Packet(raw, interface=interface, direction=direction)


def tcp_fragment_and_send(w, packet, sni: str, verbose: bool = False) -> bool:
    """
    DPI bypass: SNI ortasından fragmentation + disorder
    1) Fake packet (düşük TTL + sahte SNI) — DPI'yı yanıltır
    2) Fragment 2 önce gönder (disorder — DPI reassemble edemez)
    3) Fragment 1 sonra gönder (gerçek SNI)
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

    # SNI hostname'in payload içindeki konumunu bul
    sni_bytes = sni.encode("ascii")
    sni_pos = payload.find(sni_bytes)
    if sni_pos != -1:
        split_pos = sni_pos + len(sni_bytes) // 2
    else:
        split_pos = len(payload) // 3

    split_pos = max(1, min(split_pos, len(payload) - 1))

    # Sahte SNI ile fake payload oluştur
    if sni_pos != -1:
        fake_domain = ("www.w3.org" + "w" * len(sni))[:len(sni)]
        fake_payload = (payload[:sni_pos]
                        + fake_domain.encode("ascii")
                        + payload[sni_pos + len(sni_bytes):])
    else:
        fake_payload = payload

    # 1) FAKE: düşük TTL + sahte SNI
    fake = _build_packet(headers, fake_payload, ip_hlen,
                         orig_seq, orig_ack,
                         iface, direction, ttl=FAKE_TTL)
    w.send(fake)

    # 2) FRAGMENT 2 ÖNCE (disorder)
    frag2 = _build_packet(headers, payload[split_pos:], ip_hlen,
                          orig_seq + split_pos, orig_ack,
                          iface, direction)
    w.send(frag2)

    # 3) FRAGMENT 1 (gerçek SNI'nin ilk yarısı)
    frag1 = _build_packet(headers, payload[:split_pos], ip_hlen,
                          orig_seq, orig_ack,
                          iface, direction)
    w.send(frag1)

    return True


def extract_http_host(data: bytes) -> str | None:
    """HTTP Host header'ını çıkar."""
    try:
        text = data.decode("ascii", errors="ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None
