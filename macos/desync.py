"""Userspace DPI desync: reshape the ClientHello on its way out of a socket.

macOS has no WinDivert, and its pf is a fork of OpenBSD pf 4.1 with no
`divert-to`, so the Windows engine's core move — inject a decoy packet carrying
the SAME sequence number as the real ClientHello but a corrupt checksum — cannot
be reproduced. A decoy sent through an ordinary socket would occupy sequence
space the server never receives, and the connection would stall forever waiting
for bytes that expired in transit. So the decoy does not port, and this module
does not pretend otherwise.

What does port is control over framing, because the proxy owns the connection to
the server and therefore decides exactly how the handshake is cut up:

  tlsrec  — re-frame the ClientHello into two TLS records, split inside the SNI.
            A DPI that reads one record and judges the hostname never sees the
            name whole. Verified against Google, Cloudflare, Discord, Wikipedia,
            X and GitHub: all complete a full certificate-verified TLS 1.3
            handshake, because RFC 8446 explicitly allows a handshake message to
            span records.
  split   — cut the ClientHello across TCP segments. Cheaper, and on some lines
            enough on its own, but it is NOT free: on the line this was written
            on, a segmented ClientHello to discord.com and gateway.discord.gg
            drew a deterministic RST (0 of 6 attempts survived) while the same
            request unsegmented and the tlsrec variants succeeded 6 of 6. That
            is exactly why the technique is measured per line instead of picked.

Nothing here is macOS-specific — it is plain sockets — which is what makes it
testable off a Mac.
"""

import socket
import struct
import time

from sni import extract_sni

# Techniques in the order autotune tries them. tlsrec leads because it is the
# one that survived every server tested; "none" is last but still a legitimate
# answer, since on a line with no DPI the safest thing is to touch nothing.
TECHNIQUES = (
    "tlsrec",
    "tlsrec+split",
    "split:sni",
    "split:record",
    "disorder",
    "none",
)

# Gap between segments. Long enough that the pieces are not coalesced into one
# packet by the local stack, short enough to stay invisible next to the
# handshake's own round-trip.
SEGMENT_DELAY = 0.02

# Hop limit for the first segment under "disorder". It has to expire before the
# DPI to be useful and the right value is per-line, so autotune searches it and
# this is only the starting point.
DISORDER_TTL = 3

CONNECT_TIMEOUT = 10.0


def _record_bounds(data: bytes):
    """(payload_start, payload_end) of the leading TLS record, or None."""
    if len(data) < 5 or data[0] != 0x16:
        return None
    end = 5 + struct.unpack("!H", data[3:5])[0]
    if end > len(data):
        return None                      # record not fully buffered yet
    return 5, end


def reframe_tls_records(data: bytes, cut: int) -> bytes | None:
    """Split the leading handshake record into two records at `cut`.

    `cut` is an offset into the handshake message, not into `data`. Anything
    following the first record is passed through untouched.
    """
    bounds = _record_bounds(data)
    if not bounds:
        return None
    start, end = bounds
    hs = data[start:end]
    if not 0 < cut < len(hs):
        return None
    ver = data[1:3]
    return (b"\x16" + ver + struct.pack("!H", cut) + hs[:cut] +
            b"\x16" + ver + struct.pack("!H", len(hs) - cut) + hs[cut:] +
            data[end:])


def _sni_offset(data: bytes, host: str) -> int:
    """A cut position inside the SNI hostname, in handshake-message space."""
    if host:
        # The SNI travels as ASCII/IDNA on the wire, which is exactly what
        # extract_sni handed back, so match on those bytes directly.
        at = data.find(host.encode("ascii", "ignore"))
        if at != -1:
            return max(1, at + len(host) // 2 - 5)
    # No hostname to aim at: a third of the way in still lands inside the
    # extension block for any browser-sized hello.
    return max(1, (len(data) - 5) // 3)


def _set_ttl(sock: socket.socket, ttl: int) -> None:
    if sock.family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
    else:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)


def _send_disordered(sock: socket.socket, data: bytes, cut: int,
                     ttl: int = DISORDER_TTL) -> None:
    """Send the first segment with a hop limit too low to reach the server.

    The DPI sees the tail of the ClientHello before the head, which is enough to
    defeat one that judges the flow in arrival order. The server is unaffected:
    the segment it never received is retransmitted by the kernel a moment later,
    at the socket's restored hop limit, and the handshake completes.

    This is only safe because the bytes are REAL. The same trick with a spoofed
    payload is the trap that looks like the Windows decoy and is not: the kernel
    retransmits whatever was queued, so the server would eventually accept the
    fake ClientHello as the true one and the handshake would fail. macOS has no
    TCP_REPAIR to rewind the sequence number with, so there is no way to make a
    fake packet not count. Never put fake bytes through this path.

    Costs roughly one retransmission timeout on every connection that uses it,
    which is why autotune prefers a cheaper technique whenever one also works.
    """
    cut = max(1, min(cut, len(data) - 1))
    try:
        _set_ttl(sock, ttl)
        sock.sendall(data[:cut])
    finally:
        _set_ttl(sock, 64)
    time.sleep(SEGMENT_DELAY)
    sock.sendall(data[cut:])


def _http_host_offset(data: bytes) -> int:
    """A cut position inside a plain-HTTP Host header value, or 0 if absent."""
    at = data.lower().find(b"\r\nhost:")
    if at == -1:
        return 0
    value = at + len(b"\r\nhost:")
    end = data.find(b"\r\n", value)
    if end == -1:
        return 0
    return value + max(1, (end - value) // 2)


def send_first_flush(sock: socket.socket, data: bytes, technique: str,
                     host: str = "") -> None:
    """Write the client's first bytes, reshaped by `technique`."""

    def segments(buf: bytes, cuts):
        bounds = [0] + sorted(c for c in cuts if 0 < c < len(buf)) + [len(buf)]
        for a, b in zip(bounds, bounds[1:]):
            sock.sendall(buf[a:b])
            if b < len(buf):
                time.sleep(SEGMENT_DELAY)

    if technique == "none" or not data:
        sock.sendall(data)
        return

    # Plain HTTP on port 80 is inspected by Host header, not by SNI, and there
    # is no TLS record to re-frame. Cutting the header value across segments is
    # the equivalent move; a technique with no split leaves it alone.
    if data[:1] != b"\x16":
        cut = _http_host_offset(data) if "split" in technique else 0
        if cut:
            segments(data, [cut])
        else:
            sock.sendall(data)
        return

    mid = _sni_offset(data, host)

    if technique == "split:record":
        segments(data, [1])
    elif technique == "split:sni":
        segments(data, [mid + 5])
    elif technique == "disorder":
        _send_disordered(sock, data, mid + 5)
    elif technique in ("tlsrec", "tlsrec+split"):
        reframed = reframe_tls_records(data, mid)
        if reframed is None:
            # Not a parseable ClientHello (plain HTTP, a partial record, or a
            # protocol we do not model). Forwarding it unchanged is always safe;
            # mangling something we did not understand is not.
            sock.sendall(data)
            return
        if technique == "tlsrec+split":
            segments(reframed, [1])
        else:
            sock.sendall(reframed)
    else:
        sock.sendall(data)


def read_client_hello(sock: socket.socket, timeout: float = 5.0):
    """Buffer until the leading TLS record is complete.

    A browser can hand us the ClientHello in pieces. Deciding where to cut from
    a partial record would either mangle the handshake or read a truncated
    hostname, so wait for the whole record before touching it. Returns
    (buffer, sni) — sni is None when this is not TLS, which is fine and means
    the caller should forward the bytes as they are.
    """
    sock.settimeout(timeout)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) < 5:
            continue
        if buf[0] != 0x16:
            return buf, None             # not TLS; nothing to reassemble
        need = 5 + struct.unpack("!H", buf[3:5])[0]
        if len(buf) >= need:
            return buf, extract_sni(buf)
        if len(buf) > 65535:
            break
    return buf, (extract_sni(buf) if buf[:1] == b"\x16" else None)


def connect_desynced(host: str, port: int, first: bytes, technique: str,
                     resolver=None, deadline: float = None,
                     source_ip: str = None) -> socket.socket:
    """Open a TCP connection and write `first` reshaped by `technique`.

    Raises OSError on failure; the caller owns the socket on success.
    """
    addresses = []
    if resolver is not None:
        addresses = resolver.resolve_all(host, deadline) or []
    if not addresses:
        addresses = [host]               # let the system resolver try

    last = None
    for addr in addresses:
        sock = None
        try:
            sock = socket.create_connection((addr, port), CONNECT_TIMEOUT)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if first:
                send_first_flush(sock, first, technique, host)
            return sock
        except OSError as e:
            last = e
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    raise last or OSError("no address for %s" % host)
