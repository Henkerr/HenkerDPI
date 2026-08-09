"""The local listener apps are pointed at, speaking HTTP CONNECT and SOCKS5.

One listener answers both protocols because macOS apps disagree about which one
they honour: Safari and the WebKit/Electron family follow the system HTTP proxy,
while a number of others only ever look at the SOCKS setting. The first byte
tells the two apart — SOCKS5 always opens with 0x05, and no HTTP method does —
so a single port can serve either without the user choosing.

Everything downstream of the handshake is shared: resolve over DoH, decide
whether this hostname is in scope, open the upstream connection with the
measured desync applied to the first flush, then pipe bytes.
"""

import socket
import struct
import threading
import time

from config import MODE_ALL
from sni import should_bypass_fast
from . import desync

# A browser opening a page fans out to dozens of connections; the cap is high
# enough not to be felt and low enough that a runaway client cannot exhaust the
# process. Threads are cheap here because every one of them is blocked on I/O.
MAX_CONNECTIONS = 512

IDLE_TIMEOUT = 300.0
PIPE_CHUNK = 65536

# How long to wait for the server's first bytes before calling the reshaped
# handshake a failure and retrying the connection untouched. Generous enough to
# cover a slow TLS round-trip on a mobile line.
FIRST_BYTE_TIMEOUT = 6.0

# How long a host stays on the do-not-reshape list after it broke.
FALLBACK_TTL = 600.0

_SOCKS5 = 0x05
_SOCKS_CONNECT = 0x01
_ATYP_IPV4, _ATYP_DOMAIN, _ATYP_IPV6 = 0x01, 0x03, 0x04


def _close(sock):
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _pipe(src, dst, on_bytes=None):
    """Shovel bytes one way until the source ends, then half-close the target.

    The half-close matters: a plain close here would tear down the other
    direction too, truncating a response the peer is still sending.
    """
    try:
        while True:
            chunk = src.recv(PIPE_CHUNK)
            if not chunk:
                break
            dst.sendall(chunk)
            if on_bytes:
                on_bytes(len(chunk))
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("peer closed while expecting %d bytes" % n)
        buf += chunk
    return buf


def _read_http_head(sock, limit=65536):
    """Read up to and including the blank line ending an HTTP request head."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > limit:
            break
    return buf


class DesyncProxy:
    """Threaded local proxy applying the DPI desync to every connection."""

    def __init__(self, resolver, technique=lambda: "tlsrec",
                 scope=None, settings_snapshot=None, log=print,
                 host="127.0.0.1", port=0):
        self._resolver = resolver
        self._technique = technique
        # The PAC needs the mode and the domain list, the hot path needs only a
        # yes/no; both come from one snapshot so they can never disagree.
        self._settings_snapshot = settings_snapshot or (lambda: (MODE_ALL, set()))
        self._scope = scope or (lambda name: should_bypass_fast(
            name, *self._settings_snapshot()))
        # Never send the DoH resolvers through ourselves: answering that request
        # would require the answer we are asking for.
        self._direct_hosts = tuple(getattr(resolver, "servers", ())) or ()
        self._log = log
        self._host, self._want_port = host, port
        self._server = None
        self._thread = None
        self._stop = threading.Event()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._fallback = {}
        self._fallback_lock = threading.Lock()
        self.port = None
        self.stats = {"bypassed": 0, "passed": 0, "failed": 0}

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self._host, self._want_port))
        srv.listen(128)
        self.port = srv.getsockname()[1]
        self._server = srv
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        self._stop.set()
        # Closing the listener is what wakes the accept() that is blocking the
        # loop thread; there is no portable way to interrupt it otherwise.
        _close(self._server)
        self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, _ = self._server.accept()
            except OSError:
                break                      # listener closed by stop()
            if not self._slots.acquire(blocking=False):
                self._log("[!] connection limit reached — refusing")
                _close(client)
                continue
            threading.Thread(target=self._serve, args=(client,),
                             daemon=True).start()

    def _serve(self, client):
        upstream = None
        try:
            client.settimeout(IDLE_TIMEOUT)
            first = client.recv(1, socket.MSG_PEEK)
            if not first:
                return
            if first[0] == _SOCKS5:
                upstream = self._handle_socks5(client)
            else:
                upstream = self._handle_http(client)
        except OSError:
            pass
        except Exception as e:
            self._log("[!] proxy: %s" % e)
        finally:
            _close(client)
            _close(upstream)
            self._slots.release()

    # -- front doors -------------------------------------------------------
    def _handle_socks5(self, client):
        greeting = _recv_exactly(client, 2)
        nmethods = greeting[1]
        _recv_exactly(client, nmethods)
        client.sendall(b"\x05\x00")                    # no authentication

        header = _recv_exactly(client, 4)
        if header[1] != _SOCKS_CONNECT:
            client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)  # cmd unsupported
            return None

        atyp = header[3]
        if atyp == _ATYP_IPV4:
            host = socket.inet_ntoa(_recv_exactly(client, 4))
        elif atyp == _ATYP_DOMAIN:
            length = _recv_exactly(client, 1)[0]
            host = _recv_exactly(client, length).decode("idna")
        elif atyp == _ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exactly(client, 16))
        else:
            client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)  # bad address
            return None
        port = struct.unpack("!H", _recv_exactly(client, 2))[0]

        # Success is reported before the upstream connection exists. The client
        # must send its ClientHello before we can know the SNI, choose a
        # technique, or even decide this hostname is in scope — and it will not
        # send anything until the tunnel is acknowledged.
        client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        return self._tunnel(client, host, port)

    def _handle_http(self, client):
        head = _read_http_head(client)
        if not head:
            return None
        try:
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, _version = line.split(" ", 2)
        except ValueError:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return None

        # macOS fetches the PAC file from this same listener, so an origin-form
        # GET is a request for our own configuration, not something to proxy.
        if method.upper() == "GET" and target.startswith("/"):
            self._serve_pac(client)
            return None

        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                host, port = target, 443
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            return self._tunnel(client, host or target, port)

        return self._forward_plain_http(client, head, target)

    def _serve_pac(self, client):
        body = self.pac_script().encode("utf-8")
        client.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Cache-Control: no-store\r\n"
            b"Connection: close\r\n\r\n" + body)

    def pac_script(self) -> str:
        """The proxy-autoconfig file macOS is pointed at.

        A PAC is used rather than a fixed proxy setting because of what happens
        when this process is not running. macOS treats an unreachable PAC as
        "no proxy configured" and every request goes DIRECT, so a crash costs
        the bypass and nothing else. A fixed proxy pointing at a port that has
        stopped listening produces ERR_PROXY_CONNECTION_FAILED in Chromium and
        every Electron app, with no fallback — the user loses all browsing and
        has no idea why. For a tool whose whole promise is "fixes your
        internet", the mechanism that can remove it is not an option.

        It also makes selective mode free: hostnames the user did not ask to
        bypass are returned as DIRECT and never enter this process at all, so
        App Store downloads and iCloud sync do not queue behind a Python
        listener.
        """
        direct_hosts = sorted(set(self._direct_hosts))
        clauses = []
        for host in direct_hosts:
            clauses.append('  if (host == "%s") return "DIRECT";' % host)

        mode, domains = self._settings_snapshot()
        if mode == MODE_ALL:
            decision = '  return "%s";' % self._proxy_directive()
        else:
            patterns = "".join(
                '  if (dnsDomainIs(host, "%s") || host == "%s") return "%s";\n'
                % (d if d.startswith(".") else "." + d, d,
                   self._proxy_directive())
                for d in sorted(domains))
            decision = patterns + '  return "DIRECT";'

        return (
            "// HenkerDPI — generated, do not edit\n"
            "function FindProxyForURL(url, host) {\n"
            '  if (isPlainHostName(host)) return "DIRECT";\n'
            '  if (shExpMatch(host, "*.local")) return "DIRECT";\n'
            '  if (isInNet(host, "127.0.0.0", "255.0.0.0")) return "DIRECT";\n'
            '  if (isInNet(host, "169.254.0.0", "255.255.0.0")) return "DIRECT";\n'
            '  if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";\n'
            '  if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT";\n'
            '  if (isInNet(host, "192.168.0.0", "255.255.0.0")) return "DIRECT";\n'
            + "\n".join(clauses) + ("\n" if clauses else "")
            + decision + "\n}\n")

    def _proxy_directive(self) -> str:
        # The trailing DIRECT is the same promise the docstring above makes,
        # extended to the case macOS not fetching the PAC does not cover:
        # Chromium and Electron cache the PAC body and only re-fetch on a
        # network change, so between this listener dying and that re-fetch a
        # bare PROXY directive would strand every request on a dead port.
        return "PROXY 127.0.0.1:%d; DIRECT" % (self.port or 0)

    def pac_url(self) -> str:
        return "http://127.0.0.1:%d/henkerdpi.pac" % (self.port or 0)

    def _forward_plain_http(self, client, head, target):
        """Relay an absolute-URI request, rewritten to origin form."""
        if not target.lower().startswith("http://"):
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return None
        rest = target[len("http://"):]
        authority, slash, path = rest.partition("/")
        host, _, port_s = authority.rpartition(":")
        if not host:
            host, port = authority, 80
        else:
            try:
                port = int(port_s)
            except ValueError:
                host, port = authority, 80

        head = head.replace(target.encode("latin-1"),
                            (slash + path).encode("latin-1") or b"/", 1)

        if self._scope(host) and not self._on_fallback_list(host):
            technique = self._technique()
        else:
            technique = "none"

        upstream, prefetched = self._open_upstream(host, port, head, technique)
        if upstream is None:
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except OSError:
                pass
            return None
        if prefetched:
            try:
                client.sendall(prefetched)
            except OSError:
                return upstream
        self._splice(client, upstream)
        return upstream

    # -- shared path -------------------------------------------------------
    def _on_fallback_list(self, name):
        with self._fallback_lock:
            until = self._fallback.get(name)
            if until is None:
                return False
            if time.time() >= until:
                del self._fallback[name]
                return False
            return True

    def _remember_fallback(self, name):
        with self._fallback_lock:
            self._fallback[name] = time.time() + FALLBACK_TTL

    def _open_upstream(self, host, port, first, technique):
        """Connect and confirm the server actually answered.

        Re-framing a ClientHello into several TLS records is legal per RFC 8446
        §5.1, but measurements put real-world server acceptance at 92-96%, so a
        few percent of sites reject it outright. Those sites would work fine
        untouched, and a bypass that breaks a site nobody was blocking is worse
        than no bypass at all. So the reshaped attempt has to prove itself: if
        the server sends nothing back, the connection is retried verbatim and
        the host is remembered, which keeps the cost to one slow connection
        rather than one per request.

        Returns (socket, first_bytes_already_read).
        """
        attempts = [technique]
        if technique != "none":
            attempts.append("none")

        last = None
        for attempt in attempts:
            sock = None
            try:
                sock = desync.connect_desynced(
                    host, port, first, attempt, resolver=self._resolver)
                if not first:
                    return sock, b""       # nothing sent, nothing to verify
                sock.settimeout(FIRST_BYTE_TIMEOUT)
                reply = sock.recv(PIPE_CHUNK)
                if reply:
                    if attempt != technique:
                        self._log("[*] %s — reshaped handshake refused, sent "
                                  "untouched" % host)
                        self._remember_fallback(host)
                    self._count(attempt)
                    return sock, reply
                last = OSError("server closed without replying")
            except OSError as e:
                last = e
            _close(sock)
        self.stats["failed"] += 1
        self._log("[!] %s:%d — %s" % (host, port, last))
        return None, b""

    def _tunnel(self, client, host, port):
        """Read the client's first flush, then open the desynced upstream."""
        first, sni = desync.read_client_hello(client)
        # The SNI is the name the DPI actually judges, so scope on it when it is
        # there and fall back to the name the client asked for when it is not.
        name = sni or host
        if self._scope(name) and not self._on_fallback_list(host):
            technique = self._technique()
        else:
            technique = "none"

        upstream, prefetched = self._open_upstream(host, port, first, technique)
        if upstream is None:
            return None
        if prefetched:
            try:
                client.sendall(prefetched)
            except OSError:
                return upstream
        self._splice(client, upstream)
        return upstream

    def _count(self, technique):
        key = "passed" if technique == "none" else "bypassed"
        self.stats[key] += 1

    def _splice(self, client, upstream):
        client.settimeout(None)
        upstream.settimeout(None)
        up = threading.Thread(target=_pipe, args=(client, upstream), daemon=True)
        up.start()
        _pipe(upstream, client)
        up.join(timeout=IDLE_TIMEOUT)


def scope_checker(settings_getter):
    """Build a callable answering 'is this hostname ours to reshape?'.

    Wraps the same should_bypass_fast the Windows engine uses, so ALL mode,
    category selection and custom domains behave identically on both platforms.
    """
    def check(name):
        mode, domains = settings_getter()
        return should_bypass_fast(name, mode, domains)
    return check
