"""
HenkerDPI - Self-updater

Checks the GitHub Releases API for a newer build, downloads the published exe,
verifies it against the digest GitHub computed server-side, swaps it in and
restarts.

Threat model. The exe is unsigned and runs elevated, so a compromised update
path is admin-level code execution on every user. The defences here are:
  * HTTPS with certificate verification for both the API call and the download
    (an explicit default SSL context — never an unverified one).
  * The download host must be a github.com/githubusercontent.com domain, so a
    tampered API response cannot redirect the downloader elsewhere.
  * The downloaded bytes must match the asset's sha256 digest from the API
    before the file is allowed anywhere near the install path. A release with
    no digest is treated as un-installable rather than trusted.
  * Downgrades are refused; only a strictly newer version is applied.
This does not defend against a compromised GitHub account — for that the
release would have to be signed with a key that never touches GitHub.

Windows note: a running .exe cannot be overwritten, but it CAN be renamed. The
swap therefore renames the live exe aside, moves the new one into its place and
relaunches, leaving the old file to be deleted on the next start.
"""

import hashlib
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

from config import (APP_VERSION, GITHUB_REPO, RELEASE_ASSET_NAME, STATE_DIR)

_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
_RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases/latest"
_STATE_FILE = os.path.join(STATE_DIR, "update_state.json")

# Hosts the release asset may legitimately live on. GitHub redirects release
# downloads to its object CDN, so both must be allowed — but nothing else.
_ALLOWED_HOSTS = (".github.com", ".githubusercontent.com", "github.com")

_USER_AGENT = f"HenkerDPI/{APP_VERSION} (+https://github.com/{GITHUB_REPO})"

# A single check per day is plenty for a desktop tool and keeps us far away
# from GitHub's unauthenticated rate limit.
_CHECK_INTERVAL = 24 * 60 * 60

# A check that never reached GitHub (offline, or the ISP blocking it) retries
# soon instead of burning the whole daily budget on a failure.
_RETRY_INTERVAL = 10 * 60

# The published exe is ~28 MB. Refuse anything absurd so a hostile or corrupt
# response cannot make us stream gigabytes to disk.
_MAX_ASSET_BYTES = 200 * 1024 * 1024

_CF = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0)
_NEW_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)


class UpdateInfo:
    """A newer release than the one running, with a verifiable asset."""

    def __init__(self, version, tag, url, size, sha256, notes_url):
        self.version = version
        self.tag = tag
        self.url = url
        self.size = size
        self.sha256 = sha256
        self.notes_url = notes_url


def parse_version(text):
    """'v2.10.1' -> (2, 10, 1). Unparseable components read as 0.

    Compared as integer tuples, so 2.10.0 correctly sorts above 2.9.0 — a
    string compare would get that backwards the first time a minor hits 10.
    """
    parts = []
    for chunk in str(text or "").strip().lstrip("vV").split(".")[:4]:
        digits = ""
        for ch in chunk:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _host_allowed(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme != "https" or not p.hostname:
        return False
    host = p.hostname.lower()
    return host == "github.com" or any(
        host == h.lstrip(".") or host.endswith(h)
        for h in _ALLOWED_HOSTS if h.startswith("."))


def _ssl_context():
    """Certificate-verifying context. Frozen builds carry no cert store of their
    own, so fall back to certifi/OpenSSL defaults rather than to no verification.
    """
    return ssl.create_default_context()


def _read_state() -> dict:
    try:
        with open(_STATE_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _write_state(data: dict) -> None:
    try:
        tmp = _STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, _STATE_FILE)
    except OSError:
        pass


def due_for_check(force: bool = False) -> bool:
    """True if a check is allowed now.

    Successful checks back off a full day; failed ones only a few minutes, so a
    machine that was offline (or behind a blocked GitHub) at launch is not
    locked out of updates for the next 24 hours.
    """
    if force:
        return True
    nxt = _read_state().get("next_check", 0)
    try:
        nxt = float(nxt)
    except (TypeError, ValueError):
        nxt = 0
    return time.time() >= nxt


def mark_checked(ok: bool) -> None:
    state = _read_state()
    state["next_check"] = time.time() + (_CHECK_INTERVAL if ok
                                         else _RETRY_INTERVAL)
    state["last_result"] = "ok" if ok else "error"
    _write_state(state)


def last_check_failed() -> bool:
    """True if the most recent attempt could not reach GitHub at all."""
    return _read_state().get("last_result") == "error"


def is_skipped(version: str) -> bool:
    """True if the user dismissed the banner for exactly this version."""
    return _read_state().get("skipped_version") == version


def skip_version(version: str) -> None:
    state = _read_state()
    state["skipped_version"] = version
    _write_state(state)


def check_for_update(force: bool = False):
    """Return an UpdateInfo for a newer release, or None.

    Never raises and never blocks the caller's UI: every failure (no network,
    GitHub blocked by the ISP, rate limit, malformed JSON) simply yields None
    so the app carries on silently.
    """
    if not due_for_check(force):
        return None
    try:
        req = urllib.request.Request(
            _API_URL,
            headers={"User-Agent": _USER_AGENT,
                     "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=10,
                                    context=_ssl_context()) as resp:
            if resp.status != 200:
                mark_checked(False)
                return None
            payload = json.loads(resp.read(1024 * 1024).decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        mark_checked(False)
        return None
    mark_checked(True)

    if payload.get("draft") or payload.get("prerelease"):
        return None

    tag = payload.get("tag_name") or ""
    remote = parse_version(tag)
    if remote <= parse_version(APP_VERSION):
        return None            # same or older — never "update" backwards

    asset = None
    for a in payload.get("assets") or []:
        if a.get("name") == RELEASE_ASSET_NAME and a.get("state") == "uploaded":
            asset = a
            break
    if not asset:
        return None

    url = asset.get("browser_download_url") or ""
    if not _host_allowed(url):
        return None

    # GitHub reports "sha256:<hex>". Without it we cannot prove what we
    # downloaded, so the release is treated as not auto-installable.
    digest = str(asset.get("digest") or "")
    if not digest.startswith("sha256:"):
        return None
    sha256 = digest.split(":", 1)[1].strip().lower()
    if len(sha256) != 64:
        return None

    size = asset.get("size") or 0
    if not isinstance(size, int) or size <= 0 or size > _MAX_ASSET_BYTES:
        return None

    return UpdateInfo(
        version=tag.lstrip("vV"), tag=tag, url=url, size=size, sha256=sha256,
        notes_url=payload.get("html_url") or _RELEASES_PAGE)


def download_update(info: UpdateInfo, progress=None, cancel=None) -> str:
    """Download and verify the asset. Returns the path, or raises.

    Written beside the current exe so the final swap is a same-volume rename
    rather than a cross-volume copy that could half-complete.
    """
    if not _host_allowed(info.url):
        raise ValueError("refusing download from unexpected host")

    target_dir = os.path.dirname(current_exe()) or STATE_DIR
    try:
        os.makedirs(target_dir, exist_ok=True)
        probe = os.path.join(target_dir, ".henkerdpi_write_test")
        with open(probe, "wb"):
            pass
        os.remove(probe)
    except OSError:
        target_dir = STATE_DIR

    dest = os.path.join(target_dir, RELEASE_ASSET_NAME + ".new")
    try:
        os.remove(dest)
    except OSError:
        pass

    digest = hashlib.sha256()
    read = 0
    req = urllib.request.Request(
        info.url, headers={"User-Agent": _USER_AGENT,
                           "Accept": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=30,
                                    context=_ssl_context()) as resp, \
                open(dest, "wb") as out:
            if not _host_allowed(resp.geturl()):
                raise ValueError("redirected to unexpected host")
            while True:
                if cancel is not None and cancel():
                    raise InterruptedError("cancelled")
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > _MAX_ASSET_BYTES:
                    raise ValueError("asset larger than expected")
                digest.update(chunk)
                out.write(chunk)
                if progress:
                    progress(read, info.size)
    except BaseException:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise

    if digest.hexdigest().lower() != info.sha256:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise ValueError("checksum mismatch — download rejected")
    return dest


def current_exe() -> str:
    """Path of the installed executable (only meaningful in a frozen build)."""
    return sys.executable


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def can_self_update() -> bool:
    """Whether this build can swap itself in place.

    Only the Windows exe can. current_exe() on macOS is
    HenkerDPI.app/Contents/MacOS/HenkerDPI — the bundle's entry binary — so the
    swap below would drop a .dmg where the Mach-O belongs, invalidate the
    bundle's signature and leave an app that cannot be launched at all. The Mac
    is sent to the release page instead.
    """
    return is_frozen() and os.name == "nt"


def _backup_path() -> str:
    return current_exe() + ".old"


def cleanup_old_version() -> None:
    """Delete the previous exe left behind by an update. Safe to call always."""
    old = _backup_path()
    try:
        if os.path.exists(old):
            os.remove(old)
    except OSError:
        pass       # still locked by the exiting process; next launch gets it


def apply_update(new_exe: str) -> None:
    """Swap the downloaded exe into place. Raises on failure, leaving the
    working install untouched.

    Windows refuses to overwrite a running image but allows renaming it, so the
    live exe is moved aside first. If the second move fails the rename is undone
    so the user is never left without an executable.
    """
    if not can_self_update():
        raise RuntimeError("in-place update only applies to the packaged "
                           "Windows exe")

    cur = current_exe()
    backup = _backup_path()
    try:
        if os.path.exists(backup):
            os.remove(backup)
    except OSError:
        # A stale, still-locked backup: use a unique name instead of failing.
        backup = f"{cur}.old{int(time.time())}"

    os.replace(cur, backup)
    try:
        os.replace(new_exe, cur)
    except OSError:
        os.replace(backup, cur)      # roll back; install stays usable
        raise


def relaunch() -> None:
    """Start the freshly installed exe detached and let this process exit.

    --updated makes the new instance wait for this one's single-instance mutex
    to be released instead of exiting with "already running".
    """
    subprocess.Popen(
        [current_exe(), "--updated"],
        creationflags=_DETACHED | _NEW_GROUP | _CF,
        close_fds=True,
        cwd=os.path.dirname(current_exe()) or None)
