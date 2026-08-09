"""Offline checks that the macOS build is wired together correctly.

Run from CI against the source tree and again against the frozen bundle. The
bundle run is the one that matters: gui.py reaches the macOS engine through a
`sys.platform` branch, which PyInstaller's static analysis cannot see, so a
missing hiddenimport produces an app that builds cleanly and dies on launch.
Nothing here touches the network or system settings, so it is safe in CI.
"""

import struct
import sys


def run(log=print) -> int:
    failures = []

    def check(label, fn):
        try:
            fn()
            log("  ok    %s" % label)
        except Exception as e:
            log("  FAIL  %s -- %s: %s" % (label, type(e).__name__, e))
            failures.append(label)

    log("HenkerDPI macOS selftest")

    # 1. Every module the engine needs must import inside the bundle.
    def imports():
        import dnsq, tunecache, sni, config, lang            # noqa: F401
        from macos import desync, proxy, sysproxy, engine    # noqa: F401
        from macos import autotune_mac                       # noqa: F401
    check("modules import", imports)

    # 2. The Windows-only half must NOT be reachable, or the bundle is carrying
    #    a pydivert dependency it can never satisfy.
    def no_windivert():
        if "pydivert" in sys.modules:
            raise AssertionError("pydivert was imported on macOS")
    check("no pydivert", no_windivert)

    # 3. ClientHello parsing -- shared with the Windows build.
    def sni_parse():
        from sni import extract_sni
        host = b"gateway.discord.gg"
        ext = (struct.pack("!HH", 0, len(host) + 5) +
               struct.pack("!H", len(host) + 3) + b"\x00" +
               struct.pack("!H", len(host)) + host)
        body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" +
                struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" +
                struct.pack("!H", len(ext)) + ext)
        hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
        hello = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
        got = extract_sni(hello)
        if got != host.decode():
            raise AssertionError("got %r" % got)
    check("SNI extraction", sni_parse)

    # 4. TLS record re-framing must preserve every byte and stay well-formed.
    def reframe():
        from macos.desync import reframe_tls_records
        raw = b"\x16\x03\x01" + struct.pack("!H", 10) + b"0123456789"
        out = reframe_tls_records(raw, 4)
        expected = (b"\x16\x03\x01\x00\x040123" +
                    b"\x16\x03\x01\x00\x06456789")
        if out != expected:
            raise AssertionError(out.hex())
        if reframe_tls_records(b"GET / HTTP/1.1\r\n\r\n", 3) is not None:
            raise AssertionError("non-TLS input must be refused")
        if reframe_tls_records(raw, 0) is not None:
            raise AssertionError("a zero-length fragment must be refused")
    check("TLS record re-framing", reframe)

    # 5. The PAC must be syntactically plausible and never route DoH to itself.
    def pac():
        import dnsq
        from config import MODE_ALL
        from macos.proxy import DesyncProxy
        resolver = dnsq.DohResolver()
        px = DesyncProxy(resolver, settings_snapshot=lambda: (MODE_ALL, set()),
                         log=lambda m: None)
        px.port = 8080
        script = px.pac_script()
        if "FindProxyForURL" not in script:
            raise AssertionError("no PAC entry point")
        if script.count("{") != script.count("}"):
            raise AssertionError("unbalanced braces in PAC")
        for server in resolver.servers:
            if 'host == "%s"' % server not in script:
                raise AssertionError("resolver %s not DIRECT" % server)
        # Every PROXY decision must carry its own escape hatch. Browsers cache
        # the PAC body and only re-fetch on a network change, so a bare PROXY
        # directive strands every request on a dead port for as long as that
        # cache lives -- the one failure mode choosing PAC was meant to rule
        # out.
        for line in script.splitlines():
            if "PROXY" in line and "; DIRECT" not in line:
                raise AssertionError("PROXY without a DIRECT fallback: %s"
                                     % line.strip())
    check("PAC generation", pac)

    # 6. The restore script must put a saved proxy back and quote odd names.
    def restore():
        from macos import sysproxy
        script = sysproxy._restore_script({
            "USB 10/100": {"auto": {"url": "", "enabled": False},
                           "secure": {"enabled": True, "server": "10.0.0.1",
                                      "port": "3128"},
                           "bypass": ["*.local"]}})
        for fragment in ("-setautoproxystate 'USB 10/100' off",
                         "-setsecurewebproxy 'USB 10/100' 10.0.0.1 3128",
                         "'*.local'"):
            if fragment not in script:
                raise AssertionError("missing %r in:\n%s" % (fragment, script))
        if sysproxy._parse_bypass("There aren't any bypass domains set.") != []:
            raise AssertionError("the empty-list sentence was stored as a domain")
        # Losing the journal must still take our PAC off. _restore_script({})
        # is empty, and run_privileged treats an empty script as success, so
        # without this path the app reports "proxy off" to a user whose Mac is
        # still pointed at a listener that has gone.
        off = sysproxy._disable_script(["Wi-Fi", "USB 10/100"])
        for fragment in ("-setautoproxystate Wi-Fi off",
                         "-setautoproxystate 'USB 10/100' off"):
            if fragment not in off:
                raise AssertionError("missing %r in:\n%s" % (fragment, off))
    check("system-proxy restore script", restore)

    # 6b. networksetup reports "no PAC URL" as the literal string "(null)".
    #     Stored verbatim it is truthy, and the restore then writes
    #     `-setautoproxyurl <svc> '(null)'` into the user's System Settings for
    #     good. Observed on a real journal before it was fixed.
    def null_pac_url():
        from macos import sysproxy
        script = sysproxy._restore_script({
            "Wi-Fi": {"auto": {"url": "(null)", "enabled": False},
                      "bypass": []}})
        if "setautoproxyurl" in script:
            raise AssertionError("(null) was written back as a URL:\n%s" % script)
        if "-setautoproxystate Wi-Fi off" not in script:
            raise AssertionError("the PAC was not switched off:\n%s" % script)
        # Our own leftover URL must never be recorded as the user's setting:
        # networksetup cannot unset a PAC URL, so one survives every clean
        # restore and would otherwise be laundered into the journal next time.
        ours = "http://127.0.0.1:8080/%s" % sysproxy.PAC_FILENAME
        if sysproxy._clean_pac_url(ours) != "":
            raise AssertionError("our own PAC URL was kept: %s" % ours)
        theirs = "http://proxy.example.com/company.pac"
        if sysproxy._clean_pac_url(theirs) != theirs:
            raise AssertionError("a real PAC URL was discarded: %s" % theirs)
        # The proxy must serve the path sysproxy filters on, or that filter
        # silently stops matching.
        from config import MODE_ALL
        import dnsq
        from macos.proxy import DesyncProxy
        px = DesyncProxy(dnsq.DohResolver(), log=lambda m: None)
        px.port = 8080
        if px.pac_url() != ours:
            raise AssertionError("pac_url %r does not match PAC_FILENAME"
                                 % px.pac_url())
    check("no (null) PAC URL is restored", null_pac_url)

    # 6c. A pre-environment-variable journal must still be readable: it is the
    #     only record of what the user's proxy settings were before us, and
    #     upgrading them into a state that cannot be undone is unacceptable.
    def legacy_journal():
        from macos import sysproxy
        legacy = {"Wi-Fi": {"auto": {"url": "", "enabled": False}}}
        services, env = sysproxy._split_journal(legacy)
        if services != legacy or env != {}:
            raise AssertionError("legacy journal misread: %r / %r" % (services, env))
        current = {"services": legacy, "env": {"HTTPS_PROXY": "http://x"}}
        services, env = sysproxy._split_journal(current)
        if services != legacy or env != {"HTTPS_PROXY": "http://x"}:
            raise AssertionError("current journal misread: %r / %r" % (services, env))
        if sysproxy._split_journal(None) != ({}, {}):
            raise AssertionError("a missing journal must read as empty")
    check("journal layouts", legacy_journal)

    # 6d. Every variable published to the session must have a matching restore,
    #     or a run that ends leaves software pointed at a listener that is gone.
    def env_vars_symmetric():
        from macos import sysproxy
        published = set(sysproxy._ENV_PROXY_VARS) | set(sysproxy._ENV_NO_PROXY_VARS)
        if published != set(sysproxy._ENV_VARS):
            raise AssertionError("restore does not cover every published var")
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            if name not in sysproxy._ENV_PROXY_VARS:
                raise AssertionError("%s is not published; reqwest/curl need it"
                                     % name)
    check("environment proxy symmetry", env_vars_symmetric)

    # 6e. Our own leftovers must never be journalled as the user's settings.
    #     launchctl variables outlive the process, so a force-killed run leaves
    #     ours in the session; recording those as "the original" and restoring
    #     them on exit points every tool that reads them — git, npm, curl,
    #     Discord's updater — at a listener that stopped existing runs ago. The
    #     services journal is written once to avoid exactly this, and write-once
    #     cannot help here because the leftovers precede the first write.
    def env_leftovers_not_ours():
        from macos import sysproxy
        ours = "http://127.0.0.1:60395"
        if not sysproxy._is_ours(ours, ours):
            raise AssertionError("the URL we publish was not recognised as ours")
        # A loopback proxy nothing answers on cannot be a working setting.
        dead = "http://127.0.0.1:1"          # nothing listens on port 1
        if not sysproxy._is_ours(dead, ""):
            raise AssertionError("a dead loopback proxy was treated as the user's")
        # Somebody else's proxy is theirs, and must survive.
        for theirs in ("http://proxy.corp.example:3128", "http://10.0.0.1:8080"):
            if sysproxy._is_ours(theirs, ours):
                raise AssertionError("a real proxy was discarded: %s" % theirs)
        if sysproxy._loopback_port("http://proxy.corp.example:3128") is not None:
            raise AssertionError("a remote host was read as loopback")
        if sysproxy._loopback_port("http://127.0.0.1:8080") != 8080:
            raise AssertionError("the loopback port was misread")
    check("our leftovers are not the user's settings", env_leftovers_not_ours)

    # 6f. A restore that did not take must be reportable, not silent.
    def env_restore_reports():
        from macos import sysproxy
        store = {"HTTPS_PROXY": "http://127.0.0.1:1"}
        real = sysproxy._launchctl

        def fake(*args):
            if args[0] == "getenv":
                return True, store.get(args[1], "")
            if args[0] == "setenv":
                store[args[1]] = args[2]
                return True, ""
            if args[0] == "unsetenv":
                return False, ""      # refuses, as a failing launchctl would
            return True, ""

        sysproxy._launchctl = fake
        try:
            stuck = sysproxy.restore_env({})
        finally:
            sysproxy._launchctl = real
        if "HTTPS_PROXY" not in stuck:
            raise AssertionError("a variable that would not clear was not reported")
    check("a stuck environment variable is reported", env_restore_reports)

    # 7. State must land in the user's Library, never under /var/root.
    def state():
        import os
        from config import STATE_DIR
        if "/var/root" in STATE_DIR:
            raise AssertionError("state dir escaped to root: %s" % STATE_DIR)
        if sys.platform == "darwin" and "Library/Application Support" not in STATE_DIR:
            raise AssertionError("unexpected state dir: %s" % STATE_DIR)
        if not os.path.isdir(STATE_DIR):
            raise AssertionError("state dir was not created: %s" % STATE_DIR)
    check("state directory", state)

    if failures:
        log("\nFAILED: %s" % ", ".join(failures))
        return 1
    log("\nall selftest checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(run())
