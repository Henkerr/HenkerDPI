"""
HenkerDPI - DPI Bypass Strategies
TTL-based fake packet + reverse TCP fragmentation.
General-purpose — all sites or selected domains.
"""

import struct
import pydivert
from pydivert.consts import Direction

# ClientHello parsing and the bypass-scope decision are platform-neutral and
# live in sni.py so the macOS engine can share them. Re-exported here because
# main.py and autotune.py have always imported them from this module.
from sni import (extract_sni, domain_matches, should_bypass_fast,  # noqa: F401
                 _is_local_sni, _SKIP_PREFIXES, _SKIP_SNIS)

FAKE_TTL = 6  # Exact V1 value — proven to work

# How far back the decoy's sequence number is moved when the "badseq" defense is
# active. Far outside any plausible receive window, so a server that does get the
# decoy discards it as an old duplicate instead of accepting it as the real
# ClientHello. Unlike a wrong checksum, a wrong seq survives every NAT, tethering
# driver and TCP normaliser on the path — none of them can "repair" it.
FAKE_SEQ_BACKOFF = 0x10000

# Ways to make the decoy un-acceptable to the destination while a DPI box still
# parses its spoofed SNI. These are NOT stacking defences — they trade off:
#   "badsum" — right seq, wrong checksum. A DPI that reassembles the flow takes
#              the decoy as the real ClientHello (right seq = right slot in its
#              buffer) and later sees the true bytes as a retransmission, so the
#              spoofed hostname is what it judges. The destination drops it on
#              the checksum. This is the one that beats a reassembling DPI.
#   "badseq" — wrong seq. Survives a NAT/tethering stack that recomputes (and so
#              REPAIRS) checksums, which is the only way to stay safe on such a
#              path. But a reassembling DPI discards the decoy as out-of-window,
#              i.e. it makes the decoy invisible to the very box it targets.
#   "both"   — wrong on both counts: NAT-safe, but inherits badseq's blindness.
#   "off"    — no decoy; the fragmentation alone has to do it.
# Because the right answer depends on the path, autotune.py measures it per
# network rather than shipping one default and hoping.
DECOY_MODES = ("both", "badseq", "badsum", "off")

# Where the ClientHello is cut into TCP segments:
#   "record"     — cut after byte 1, splitting the TLS record header (default)
#   "record+sni" — also cut at the middle of the SNI (3 segments)
#   "sni"        — cut at the middle of the SNI only (the pre-2.5 behaviour)
#   "none"       — no cut; the decoy alone does the work
# Which one wins depends on the DPI, so the app measures it per network instead
# of shipping a guess (see autotune.py). Measured examples: on a fixed line that
# REASSEMBLES the flow no cut helps on its own — the decoy has to be the thing
# that poisons it; on a mobile carrier the record-header cut alone gets through.
SPLIT_MODES = ("record", "record+sni", "sni", "none")


def _build_packet(headers: bytes, payload_data: bytes, l4_off: int,
                  seq: int, ack: int, interface, direction, ttl: int = 0,
                  ver: int = 4):
    """Build a standalone TCP packet. ttl=0 keeps the original TTL/hop-limit.

    l4_off is the byte offset where the TCP header starts (IPv4 IHL, or 40+ for
    IPv6). The IP-layer writes differ by version: IPv4 has a 16-bit total-length
    at offset 2, TTL at byte 8 and a header checksum at offset 10; IPv6 has a
    16-bit payload-length at offset 4, hop-limit at byte 7 and NO header
    checksum. The TCP seq/ack/checksum offsets are identical for both.
    """
    raw = bytearray(headers) + bytearray(payload_data)
    struct.pack_into("!I", raw, l4_off + 4, seq & 0xFFFFFFFF)  # TCP seq
    struct.pack_into("!I", raw, l4_off + 8, ack & 0xFFFFFFFF)  # TCP ack
    struct.pack_into("!H", raw, l4_off + 16, 0)  # TCP checksum -> 0
    if ver == 6:
        struct.pack_into("!H", raw, 4, len(raw) - 40)  # IPv6 payload length
        if ttl > 0:
            raw[7] = ttl  # IPv6 hop limit
        # IPv6 base header carries no checksum
    else:
        struct.pack_into("!H", raw, 2, len(raw))  # IPv4 total length
        if ttl > 0:
            raw[8] = ttl  # IPv4 TTL
        struct.pack_into("!H", raw, 10, 0)  # IPv4 header checksum -> 0
    return pydivert.Packet(raw, interface=interface, direction=direction)


def _corrupt_tcp_checksum(pkt, ip_hlen: int):
    """Return a copy of pkt with a VALID IP checksum but an INVALID TCP checksum.

    Used only for the decoy/fake packet: the IP checksum stays correct so
    routers forward it and the DPI inspects the spoofed SNI, but the wrong TCP
    checksum makes the destination host silently drop it. DPI middleboxes do
    not verify L4 checksums, so the decoy still does its job — while the server
    can no longer mistake it for the real ClientHello. This is what stops the
    fake from poisoning handshakes to nearby servers.
    """
    pkt.recalculate_checksums()  # fills valid IP + TCP checksums (both were 0)
    raw = bytearray(pkt.raw)
    off = ip_hlen + 16  # TCP checksum field
    csum = struct.unpack_from("!H", raw, off)[0]
    struct.pack_into("!H", raw, off, csum ^ 0x0040)  # single-bit flip => invalid
    return pydivert.Packet(bytes(raw), interface=pkt.interface,
                           direction=pkt.direction)


def build_icmp_port_unreachable(pkt):
    """Build an INBOUND ICMPv4 Type 3 Code 3 (port unreachable) for an outbound
    UDP datagram.

    Injecting this back at the local stack makes a connected UDP socket
    (Chromium/Electron QUIC, e.g. Discord) surface ECONNREFUSED, so the app
    abandons QUIC on the very first Initial and falls back to TCP immediately —
    instead of stalling for tens of seconds on a silent black-hole. The original
    datagram is not re-injected by the caller, so the QUIC SNI never leaves the
    host. Returns a pydivert.Packet (direction=inbound), or None for anything
    that is not IPv4/UDP. Checksums are left zero and recomputed on send.
    """
    raw = bytes(pkt.raw)
    if len(raw) < 20 or (raw[0] >> 4) != 4:          # IPv4 only
        return None
    ip_hlen = (raw[0] & 0x0F) * 4
    if raw[9] != 17 or len(raw) < ip_hlen + 8:       # protocol must be UDP
        return None
    src_ip = raw[12:16]                              # local host
    dst_ip = raw[16:20]                              # remote server
    quoted = raw[:ip_hlen + 8]                       # orig IP header + 8B UDP header
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + 8 + len(quoted))  # IP total length
    ip[8] = 64                                       # TTL
    ip[9] = 1                                        # protocol = ICMP
    ip[12:16] = dst_ip                               # ICMP src = the server
    ip[16:20] = src_ip                               # ICMP dst = local host
    icmp = bytearray(8)                              # type, code, checksum(0), unused(0)
    icmp[0] = 3                                      # Destination Unreachable
    icmp[1] = 3                                      # Port Unreachable
    return pydivert.Packet(bytes(ip) + bytes(icmp) + quoted,
                           interface=pkt.interface, direction=Direction.INBOUND)


def build_icmpv6_port_unreachable(pkt):
    """IPv6 analogue of build_icmp_port_unreachable.

    Builds an INBOUND ICMPv6 Type 1 Code 4 (Destination Unreachable / Port
    Unreachable) for an outbound IPv6/UDP QUIC Initial, so the local QUIC socket
    sees ECONNREFUSED and falls straight back to TCP instead of stalling on a
    silent black-hole. Returns a pydivert.Packet (inbound) or None for anything
    that is not plain IPv6/UDP (extension headers unsupported). The ICMPv6
    checksum is left zero and filled by WinDivert on send.
    """
    raw = bytes(pkt.raw)
    if len(raw) < 48 or (raw[0] >> 4) != 6:          # IPv6 base header + 8B UDP
        return None
    if raw[6] != 17:                                 # Next Header must be UDP (no ext hdrs)
        return None
    src_ip = raw[8:24]                               # local host
    dst_ip = raw[24:40]                              # remote server
    # Quote the invoking datagram, capped so the whole ICMPv6 error stays within
    # the 1280-byte IPv6 minimum MTU: 40 (IPv6) + 8 (ICMPv6) + quoted.
    quoted = raw[:1280 - 40 - 8]
    ip = bytearray(40)
    ip[0] = 0x60                                     # version 6
    struct.pack_into("!H", ip, 4, 8 + len(quoted))   # payload length (ICMPv6 hdr + quoted)
    ip[6] = 58                                       # Next Header = ICMPv6
    ip[7] = 64                                       # hop limit
    ip[8:24] = dst_ip                                # ICMPv6 src = the server
    ip[24:40] = src_ip                               # ICMPv6 dst = local host
    icmp = bytearray(8)                              # type, code, checksum(0), unused(0)
    icmp[0] = 1                                      # Destination Unreachable
    icmp[1] = 4                                      # Port Unreachable
    return pydivert.Packet(bytes(ip) + bytes(icmp) + quoted,
                           interface=pkt.interface, direction=Direction.INBOUND)


def tcp_fragment_and_send(w, packet, sni: str, verbose: bool = False,
                          decoy: str = "both", split: str = "record") -> bool:
    """
    DPI bypass via ClientHello fragmentation + disorder:
    1) Fake packet with low TTL + spoofed SNI (confuses DPI state)
    2) Send the fragments last-to-first (out-of-order — DPI can't reassemble)
    Original packet is NOT sent — caller must drop it.

    `decoy` selects how step 1's packet is made unusable by the destination:
    "both" (wrong checksum + wrong seq), "badseq", "badsum", or "off" to skip the
    decoy entirely and rely on fragmentation alone. See DECOY_MODES — a decoy the
    server accepts poisons the handshake transcript and breaks every HTTPS site,
    so on a path that repairs one defence the others still have to hold.

    `split` selects where the ClientHello is cut. See SPLIT_MODES.
    """
    payload = bytes(packet.payload)
    if len(payload) < 10:
        return False

    orig_raw = bytes(packet.raw)
    ver = orig_raw[0] >> 4
    # L4 start offset. pydivert.protocol[1] is the TCP header start walking any
    # IPv6 extension headers; fall back to the fixed sizes if it's unavailable.
    try:
        _pstart = packet.protocol[1]
    except Exception:
        _pstart = None
    if ver == 4:
        l4_off = _pstart if _pstart else (orig_raw[0] & 0x0F) * 4
    elif ver == 6:
        l4_off = _pstart if _pstart else 40
    else:
        return False
    tcp_hlen = ((orig_raw[l4_off + 12] >> 4) & 0xF) * 4
    headers = orig_raw[:l4_off + tcp_hlen]

    orig_seq = struct.unpack_from("!I", orig_raw, l4_off + 4)[0]
    orig_ack = struct.unpack_from("!I", orig_raw, l4_off + 8)[0]

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

    # Cut positions, ascending. Byte 1 splits the TLS record header across two
    # segments; the SNI-midpoint cut splits the hostname itself. "none" makes no
    # cut at all — the decoy alone carries the bypass, which is what works on a
    # DPI that reassembles the flow but takes the first copy of a segment.
    cuts = set()
    if split in ("record+sni", "sni"):
        cuts.add(split_pos)
    if split in ("record+sni", "record"):
        cuts.add(1)
    cuts = sorted(c for c in cuts if 0 < c < len(payload))
    if not cuts and split != "none":
        cuts = [split_pos]
    # Nothing to do: no cut and no decoy would re-send the original unchanged,
    # so tell the caller to forward it instead of rebuilding it.
    if not cuts and decoy == "off":
        return False

    # Build fake payload with spoofed SNI
    if sni_pos != -1:
        fake_domain = ("www.w3.org" + "w" * len(sni))[:len(sni)]
        fake_payload = (payload[:sni_pos]
                        + fake_domain.encode("ascii")
                        + payload[sni_pos + len(sni_bytes):])
    else:
        fake_payload = payload

    # Build every packet BEFORE sending any. If construction fails
    # (malformed packet), return False so the caller forwards the original
    # untouched — never leave a connection with a half-sent burst.
    try:
        # 1) FAKE: spoofed SNI, made UN-PROCESSABLE BY THE SERVER via a wrong
        #    TCP checksum (the DPI ignores L4 checksums, so it is still fooled).
        #    Previously the fake carried the real seq + valid checksums and
        #    relied ONLY on TTL=6; for any server <=6 hops away (most CDNs,
        #    Cloudflare, Discord edge) it was accepted as the real ClientHello,
        #    the real fragments were discarded as duplicates, and the server did
        #    TLS with the fake SNI -> handshake_failure/RST/hang. That poisoning
        #    is the primary cause of the intermittent connection drops. Low TTL
        #    is kept as a secondary defense.
        #    A NAT, a USB-tethering driver or a carrier TCP normaliser rewrites
        #    the source address and recomputes the L4 checksum on the way out,
        #    which REPAIRS the deliberate corruption — observed live on iPhone
        #    USB tethering, where every HTTPS site broke because the repaired
        #    decoy reached the server. A wrong sequence number cannot be
        #    repaired that way, so it is the default second defence.
        fake_badsum = decoy in ("both", "badsum")
        fake_seq = orig_seq
        if decoy in ("both", "badseq"):
            fake_seq = (orig_seq - FAKE_SEQ_BACKOFF) & 0xFFFFFFFF
        fake = _build_packet(headers, fake_payload, l4_off,
                             fake_seq, orig_ack,
                             iface, direction, ttl=FAKE_TTL, ver=ver)
        if fake_badsum:
            fake = _corrupt_tcp_checksum(fake, l4_off)
        # 2) The real ClientHello, cut into segments and sent LAST-TO-FIRST so a
        #    DPI that does not buffer out-of-order data never sees the hostname
        #    in one piece.
        bounds = [0] + cuts + [len(payload)]
        frags = [
            _build_packet(headers, payload[a:b], l4_off,
                          orig_seq + a, orig_ack, iface, direction, ver=ver)
            for a, b in zip(bounds, bounds[1:])
        ]
    except (IndexError, struct.error):
        return False

    # Send phase: original was already dropped by the caller, so a transient
    # send error here can't be recovered by re-sending the original (would
    # duplicate seq). Swallow it — TCP will retransmit the real ClientHello.
    # A badsum fake keeps its deliberately-wrong TCP checksum
    # (recalculate_checksum=False); every other packet gets correct checksums
    # recomputed by WinDivert — _build_packet leaves them zeroed.
    try:
        if decoy != "off":
            w.send(fake, recalculate_checksum=not fake_badsum)
        for frag in reversed(frags):
            w.send(frag)
    except Exception:
        if verbose:
            print("[!] fragment send failed")
    return True
