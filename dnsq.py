"""DNS-over-HTTPS resolution — platform-neutral, no system DNS involved.

The macOS engine resolves every connection itself instead of repointing the
system resolver. That is deliberate: rewriting /etc/resolv.conf or the
networksetup DNS list is the one change that strands a user with no working
internet if the app dies, and this project has already shipped one critical DNS
restore bug. Resolving in-process means there is nothing to restore.

Both doh.py and autotune.py had grown their own copy of the wire format and the
answer walk; this is that code, once, with the response cache the proxy needs to
avoid paying a round-trip per connection.
"""

import socket
import struct
import threading
import time
import urllib.request

# Resolvers are addressed by IP, never by name: on a line that intercepts port
# 53 there is no trustworthy way to look up the resolver's own hostname first.
# Cloudflare, Google and Quad9 all present certificates covering these IPs, so
# certificate verification stays on.
DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

QTYPE_A = 1
QTYPE_AAAA = 28

# Answers below this are pointless to cache and answers above it let a hostile
# resolver pin us; both bounds are ordinary practice for a stub cache.
_MIN_TTL = 30
_MAX_TTL = 3600
_MAX_ENTRIES = 512

# Resolve through a DIRECT connection, always. On macOS urllib discovers the
# system proxy through SystemConfiguration, so once the engine registers itself
# as that proxy every DoH lookup would be sent to the engine's own listener —
# which cannot answer it until the lookup completes. That is a deadlock on the
# first connection, and it would look exactly like "the macOS build hangs".
# An empty ProxyHandler pins these requests to the direct path.
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def wire_query(name: str, qtype: int = QTYPE_A, txid: int = 0) -> bytes:
    """Build a DNS query message for `name`."""
    q = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        if not 0 < len(label) < 64:
            raise ValueError("bad label in %r" % name)
        q += bytes([len(label)]) + label.encode("idna")
    return q + b"\x00" + struct.pack("!HH", qtype, 1)


def _skip_name(data: bytes, off: int) -> int:
    """Step over a (possibly compressed) name, returning the offset after it."""
    while True:
        length = data[off]
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1
        if length == 0:
            return off
        off += length


def parse_answers(data: bytes):
    """Extract (ip, ttl) for every A/AAAA record. Order is preserved."""
    out = []
    try:
        qdcount = struct.unpack_from("!H", data, 4)[0]
        ancount = struct.unpack_from("!H", data, 6)[0]
        off = 12
        for _ in range(qdcount):
            off = _skip_name(data, off) + 4          # + QTYPE/QCLASS
        for _ in range(ancount):
            off = _skip_name(data, off)
            rtype, _cls, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            if rtype == QTYPE_A and rdlen == 4:
                out.append((socket.inet_ntoa(data[off:off + 4]), ttl))
            elif rtype == QTYPE_AAAA and rdlen == 16:
                out.append((socket.inet_ntop(socket.AF_INET6,
                                             data[off:off + 16]), ttl))
            off += rdlen
    except (IndexError, struct.error, OSError, ValueError):
        pass
    return out


class DohResolver:
    """Caching DoH resolver. Safe to share across the proxy's worker threads."""

    def __init__(self, servers=DEFAULT_RESOLVERS, timeout: float = 5.0):
        self.servers = tuple(servers) if servers else DEFAULT_RESOLVERS
        self.timeout = timeout
        self._cache = {}
        self._lock = threading.Lock()

    def _cached(self, name: str):
        with self._lock:
            hit = self._cache.get(name)
            if not hit:
                return None
            ips, expires = hit
            if time.time() >= expires:
                self._cache.pop(name, None)
                return None
            return ips

    def _store(self, name: str, ips, ttl: int) -> None:
        ttl = max(_MIN_TTL, min(int(ttl), _MAX_TTL))
        with self._lock:
            if len(self._cache) >= _MAX_ENTRIES:
                # Cheapest sane eviction: drop whatever expires soonest.
                oldest = min(self._cache, key=lambda k: self._cache[k][1])
                self._cache.pop(oldest, None)
            self._cache[name] = (ips, time.time() + ttl)

    def query(self, name: str, qtype: int = QTYPE_A, deadline: float = None):
        """Ask each resolver in turn; return [(ip, ttl)] from the first answer."""
        try:
            payload = wire_query(name, qtype)
        except (ValueError, UnicodeError):
            return []
        for server in self.servers:
            if deadline and time.time() > deadline:
                break
            remaining = self.timeout
            if deadline:
                remaining = min(remaining, max(0.1, deadline - time.time()))
            req = urllib.request.Request(
                "https://%s/dns-query" % server, data=payload,
                headers={"Content-Type": "application/dns-message",
                         "Accept": "application/dns-message"})
            try:
                with _DIRECT.open(req, timeout=remaining) as r:
                    answers = parse_answers(r.read())
                if answers:
                    return answers
            except Exception:
                continue
        return []

    def resolve_all(self, name: str, deadline: float = None):
        """Every A address for `name`, cached for the record's TTL."""
        # An address literal is already an answer; asking a resolver about it
        # would return NXDOMAIN and strand a connection that would have worked.
        try:
            socket.inet_aton(name)
            return [name]
        except OSError:
            pass
        hit = self._cached(name)
        if hit is not None:
            return list(hit)
        answers = self.query(name, QTYPE_A, deadline)
        if not answers:
            return []
        ips = [ip for ip, _ in answers]
        self._store(name, tuple(ips), min(ttl for _, ttl in answers))
        return ips

    def resolve(self, name: str, deadline: float = None):
        """First A address for `name`, or None."""
        ips = self.resolve_all(name, deadline)
        return ips[0] if ips else None


_shared = DohResolver()


def resolve(name: str, deadline: float = None):
    """Module-level convenience against a shared cache."""
    return _shared.resolve(name, deadline)


def resolve_all(name: str, deadline: float = None):
    return _shared.resolve_all(name, deadline)
