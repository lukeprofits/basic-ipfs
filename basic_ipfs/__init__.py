"""
basic_ipfs — stupid-simple IPFS for Python.

Runs a real Kubo node under the hood. Auto-downloads the binary on first use.

Quick start:

    import basic_ipfs

    cid = basic_ipfs.add("photo.jpg")       # or bytes — adds AND pins
    cid = basic_ipfs.announce("photo.jpg")  # adds without pinning (may be GC'd)
    data = basic_ipfs.get(cid)              # → bytes
    basic_ipfs.get(cid, "copy.jpg")         # or write to disk

    basic_ipfs.pin(cid)                     # keep forever
    basic_ipfs.unpin(cid)                   # let GC reclaim

The daemon starts lazily on the first call and stops cleanly on process exit.
"""

from __future__ import annotations

import atexit
import datetime
import glob as _glob
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any, TypedDict, Union, overload
from urllib.parse import urlparse

import requests
from platformdirs import user_data_dir

from . import kubo_checksums

# Single source of truth: the version that pip resolved when installing this
# wheel. Avoids drift between pyproject.toml and a hardcoded literal — if
# __version__ ever lies about which fix is deployed, security advisories
# become very hard to reason about.
try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("basic-ipfs")
except PackageNotFoundError:
    # Running from a source checkout that was never installed (e.g. tests
    # invoked with `pytest` against the working tree). Stay obviously fake.
    __version__ = "0+unknown"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — assign before the first API call if you want to override
# ---------------------------------------------------------------------------

APP_NAME = "basic_ipfs"

# Pinned Kubo version — downloaded automatically if not already present.
KUBO_VERSION = "v0.40.1"
KUBO_DIST_BASE = "https://dist.ipfs.tech/kubo"

# Hostnames the download is permitted to redirect to. TLS still catches a
# MitM, but pinning the origin means a 30x to attacker.example also fails
# instead of relying on the SHA-512 check alone.
_ALLOWED_DOWNLOAD_HOSTS = ("dist.ipfs.tech",)

# Where the IPFS repo lives. None = platformdirs.user_data_dir(APP_NAME)
REPO_PATH: Path | None = None

# Local API the daemon listens on
API_HOST = "127.0.0.1"
API_PORT = 5001

# Local HTTP gateway address. Kubo defaults to 127.0.0.1:8080 — only
# override if you need to run a second basic_ipfs node on the same host.
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8080

# Optional override for ``Addresses.Swarm``. When ``None``, Kubo's defaults
# apply (listens on 0.0.0.0:4001 etc.). Set to a list of multiaddrs to pin
# the swarm listener — e.g. ``["/ip4/127.0.0.1/tcp/4001"]`` for
# loopback-only on a multi-tenant host. Applied before daemon launch.
SWARM_ADDRESSES: list[str] | None = None

# Repo size cap. Empty string = unlimited.
STORAGE_MAX = "50GB"

# Seconds to wait for the daemon to come up on startup
DAEMON_STARTUP_TIMEOUT = 60

# Free-space buffer required before auto-download (~115 MB archive + extracted).
_INSTALL_FREE_BYTES = 300 * 1024 * 1024

# How many CIDs to send per batch pin/unpin HTTP call. Kubo's URL is the limit;
# 500 × ~60-byte CIDs ≈ 30 KB — comfortable headroom under typical 8 KB+ limits.
_PIN_BATCH_SIZE = 500

# Kubo daemon log: kept inside the repo for easy bug reports.
_DAEMON_LOG_NAME = "basic_ipfs_daemon.log"
_DAEMON_LOG_MAX_BYTES = 5 * 1024 * 1024  # rotate when the previous log exceeds this

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class IPFSError(RuntimeError):
    """Base class for everything this package raises."""


class IPFSBinaryNotFound(IPFSError):
    """Kubo binary missing and auto-download failed."""


class IPFSDaemonTimeout(IPFSError):
    """Daemon did not become ready in time."""


class IPFSOperationError(IPFSError):
    """An IPFS API call returned an error.

    Attributes mirror Kubo's JSON error envelope so callers can branch on
    the structured fields instead of pattern-matching the message string.
    Any of them may be ``None`` if the response was not a well-formed Kubo
    error body (e.g. an HTML 502 from a reverse proxy).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        kubo_code: int | None = None,
        kubo_type: str | None = None,
        kubo_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.kubo_code = kubo_code
        self.kubo_type = kubo_type
        self.kubo_message = kubo_message

    def is_not_pinned(self) -> bool:
        """True iff this error is Kubo's ``<cid> is not pinned`` response.

        Used to make pin-removal idempotent without swallowing real failures.
        Requires both a Kubo-shaped error body (``Type == "error"``) and the
        canonical ``not pinned`` substring — guards against accidentally
        treating an unrelated 500 as a successful no-op.
        """
        if self.kubo_type != "error":
            return False
        msg = (self.kubo_message or "").lower()
        return "not pinned" in msg


class IPFSPortInUse(IPFSError):
    """The configured API port is already bound by something other than our daemon."""


class IPFSRepoLocked(IPFSError):
    """The IPFS repo is locked by another running Kubo daemon."""


class IPFSRepoCorrupt(IPFSError):
    """The IPFS repo on disk failed a sanity check."""


# ---------------------------------------------------------------------------
# TypedDicts
# ---------------------------------------------------------------------------


class StatusDict(TypedDict):
    peer_id: str | None
    agent_version: str | None
    repo_size_bytes: int | None
    num_objects: int | None
    pinned_cids: int
    addresses: list[str]


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def _base_dir() -> Path:
    """Package directory — respects PyInstaller one-file bundles."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def _is_musl() -> bool:
    """True on musl-libc Linux (e.g. Alpine). Kubo ships glibc only."""
    if sys.platform != "linux":
        return False
    return bool(_glob.glob("/lib/ld-musl-*")) or bool(_glob.glob("/lib64/ld-musl-*"))


_SUPPORTED_TRIPLES = (
    "linux-amd64", "linux-arm64", "linux-riscv64",
    "darwin-amd64", "darwin-arm64",
    "windows-amd64",
)


def _platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if _is_musl():
            manual = Path(user_data_dir(APP_NAME)) / "bin" / f"linux-{machine}" / "ipfs"
            raise IPFSBinaryNotFound(
                "Detected Alpine/musl Linux. Kubo publishes glibc binaries only.\n"
                "  - With `apk add gcompat` the glibc build *may* run, but it isn't officially supported.\n"
                "  - Otherwise, place a musl-compatible `ipfs` binary at:\n"
                f"      {manual}"
            )
        if machine in ("x86_64", "amd64"):
            return "linux-amd64"
        if machine in ("aarch64", "arm64"):
            return "linux-arm64"
        if machine in ("riscv64",):
            return "linux-riscv64"
        if machine in ("armv7l", "armv6l", "armhf", "arm"):
            raise IPFSBinaryNotFound(
                f"32-bit ARM ({machine}) is not supported by current Kubo releases. "
                "Run a 64-bit OS (aarch64) on Raspberry Pi 4/5 or similar."
            )
    if system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "darwin-arm64"
        if machine in ("x86_64", "amd64"):
            return "darwin-amd64"
    if system == "windows":
        if machine in ("amd64", "x86_64"):
            return "windows-amd64"

    manual = Path(user_data_dir(APP_NAME)) / "bin" / f"{system}-{machine}" / "ipfs"
    raise IPFSBinaryNotFound(
        f"Unsupported platform: {system}/{machine}.\n"
        f"  Supported: {', '.join(_SUPPORTED_TRIPLES)}.\n"
        f"  To use an unsupported platform, place an ipfs binary manually at:\n"
        f"    {manual}"
    )


def _binary_name() -> str:
    return "ipfs.exe" if sys.platform == "win32" else "ipfs"


def _bundled_binary_path() -> Path:
    """Path inside the installed wheel — used for pre-placed binaries
    (PyInstaller / Briefcase / air-gapped deploys)."""
    return _base_dir() / "bin" / _platform_key() / _binary_name()


def _user_binary_path() -> Path:
    """Per-user install path. The auto-downloader writes here so we never
    mutate site-packages — site-packages is a trust boundary owned by the
    package manager, not by runtime code, and on a multi-user host any
    other user with write access there could swap the binary."""
    return Path(user_data_dir(APP_NAME)) / "bin" / _platform_key() / _binary_name()


def _binary_path() -> Path:
    """Back-compat alias. Returns the user-install path that the downloader
    writes to. Lookup order is implemented in _find_or_install_kubo()."""
    return _user_binary_path()


# ---------------------------------------------------------------------------
# Kubo auto-download
# ---------------------------------------------------------------------------


# Kubo version strings look like ``v0.40.1`` or ``v0.41.0-rc1``. We
# interpolate KUBO_VERSION into a download URL, so anything outside this
# shape (path traversal, query injection, accidental whitespace) is
# rejected before it can reach _download(). Defence in depth: the redirect
# host pin and the baked-in SHA-512 table also block the attack, but a
# regex gate makes the failure mode obvious and local.
_KUBO_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(-rc\d+)?$")


def _archive_info() -> tuple[str, str]:
    if not _KUBO_VERSION_RE.match(KUBO_VERSION):
        raise IPFSBinaryNotFound(
            f"Refusing to download with malformed KUBO_VERSION {KUBO_VERSION!r}. "
            f"Expected something like 'v0.40.1' or 'v0.41.0-rc1'."
        )
    key = _platform_key()
    os_name, arch = key.split("-", 1)
    ext = "zip" if os_name == "windows" else "tar.gz"
    name = f"kubo_{KUBO_VERSION}_{os_name}-{arch}.{ext}"
    return f"{KUBO_DIST_BASE}/{KUBO_VERSION}/{name}", ext


def _download_session() -> requests.Session:
    """A session with retry+backoff on transient HTTP failures."""
    from requests.adapters import HTTPAdapter
    try:
        from urllib3.util.retry import Retry
    except ImportError:  # very old urllib3
        from requests.packages.urllib3.util.retry import Retry  # type: ignore

    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=(502, 503, 504, 520, 522, 524),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _check_redirect_origin(final_url: str) -> None:
    host = (urlparse(final_url).hostname or "").lower()
    for allowed in _ALLOWED_DOWNLOAD_HOSTS:
        if host == allowed or host.endswith("." + allowed):
            return
    raise IPFSBinaryNotFound(
        f"Refusing to follow redirect to unexpected host {host!r}. "
        f"Allowed: {', '.join(_ALLOWED_DOWNLOAD_HOSTS)}."
    )


def _download(url: str, dest: Path, timeout: int = 600) -> str:
    """Stream ``url`` into ``dest``, returning the SHA-512 hex digest.

    The whole archive used to be buffered in memory, which let a hostile
    origin (or any 30x to a misconfigured mirror) waste up to a gigabyte
    of RAM before the SHA mismatch ever rejected it. Stream to disk
    instead, hash incrementally, and abort early if the byte count
    exceeds ``_MAX_DOWNLOAD_BYTES`` — the hash check is still
    fail-closed, this just bounds the resource cost of a bad response.
    """
    logger.info("Downloading %s", url)
    last_pct_logged = -1
    hasher = hashlib.sha512()
    received = 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _download_session() as session, session.get(url, stream=True, timeout=timeout) as r:
        _check_redirect_origin(r.url)
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 16):
                if not chunk:
                    continue
                received += len(chunk)
                if received > _MAX_DOWNLOAD_BYTES:
                    raise IPFSBinaryNotFound(
                        f"Refusing to download more than {_MAX_DOWNLOAD_BYTES} bytes "
                        f"from {url} — got {received} bytes and counting. "
                        f"Either the origin is misbehaving or KUBO_VERSION points at "
                        f"something unexpected."
                    )
                hasher.update(chunk)
                fh.write(chunk)
                if total:
                    pct = received * 100 // total
                    if pct >= last_pct_logged + 10:
                        logger.info("  %3d%%  (%d / %d bytes)", pct, received, total)
                        last_pct_logged = pct
    return hasher.hexdigest().lower()


def _expected_sha512(archive_url: str) -> str:
    """Look up the SHA-512 we expect for this version+platform.

    Only the baked-in table is trusted. Fetching the companion ``.sha512``
    from the same origin is rejected: an attacker who controls
    ``dist.ipfs.tech`` can swap both files together. New Kubo versions must
    have their hash committed to ``kubo_checksums.py`` before they can be
    installed.
    """
    baked = kubo_checksums.known_checksum(KUBO_VERSION, _platform_key())
    if baked is not None:
        return baked.lower()
    raise IPFSBinaryNotFound(
        f"No baked-in SHA-512 for Kubo {KUBO_VERSION}/{_platform_key()}. "
        f"Refusing to fetch a digest from the same origin as the archive — "
        f"that defeats the verification. Add the hash to "
        f"basic_ipfs/kubo_checksums.py and reinstall, or pin "
        f"basic_ipfs.KUBO_VERSION to a version already in the table."
    )


# Hardening caps for archive extraction. Real Kubo binaries are ~115 MB
# inside a tarball with a single top-level ``kubo/`` directory, so anything
# materially larger or more deeply nested is suspicious — refuse rather
# than allocate.
_MAX_ARCHIVE_MEMBER_BYTES = 512 * 1024 * 1024  # 512 MB per entry
_MAX_ARCHIVE_PATH_DEPTH = 4

# Hard ceiling on the streamed download itself — independent of the per-member
# cap above, because streaming happens before extraction. A hostile origin (or
# a Content-Length that lies) cannot cost us more than this in disk + time.
# Twice the per-member cap leaves comfortable headroom for archive overhead
# while still bounding the worst case.
_MAX_DOWNLOAD_BYTES = 2 * _MAX_ARCHIVE_MEMBER_BYTES


def _safe_member_name(name: str) -> bool:
    # Defence in depth: extraction never honours the member's path (we always
    # write to a fixed `dest`), but reject obviously-hostile names anyway so
    # the helper matches its name and a future refactor that does honour the
    # path stays safe.
    if not name or name.startswith(("/", "\\")):
        return False
    p = Path(name)
    if p.is_absolute():
        return False
    parts = p.parts
    if not 0 < len(parts) <= _MAX_ARCHIVE_PATH_DEPTH:
        return False
    return all(part not in ("..",) for part in parts)


def _extract_binary(archive_path: Path, ext: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if ext == "tar.gz":
        with tarfile.open(str(archive_path), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile() or Path(member.name).name != "ipfs":
                    continue
                if not _safe_member_name(member.name):
                    raise IPFSBinaryNotFound(
                        f"Refusing archive member with unsafe path: {member.name!r}"
                    )
                if member.size > _MAX_ARCHIVE_MEMBER_BYTES:
                    raise IPFSBinaryNotFound(
                        f"Archive member {member.name!r} is {member.size} bytes — "
                        f"exceeds the {_MAX_ARCHIVE_MEMBER_BYTES}-byte cap."
                    )
                src = tf.extractfile(member)
                if src is not None:
                    with open(dest, "wb") as out:
                        shutil.copyfileobj(src, out, length=1 << 16)
                break
    else:
        with zipfile.ZipFile(str(archive_path)) as zf:
            for info in zf.infolist():
                if Path(info.filename).name != "ipfs.exe":
                    continue
                if not _safe_member_name(info.filename):
                    raise IPFSBinaryNotFound(
                        f"Refusing archive member with unsafe path: {info.filename!r}"
                    )
                if info.file_size > _MAX_ARCHIVE_MEMBER_BYTES:
                    raise IPFSBinaryNotFound(
                        f"Archive member {info.filename!r} is {info.file_size} bytes — "
                        f"exceeds the {_MAX_ARCHIVE_MEMBER_BYTES}-byte cap."
                    )
                with zf.open(info.filename) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out, length=1 << 16)
                break

    if not dest.exists():
        raise IPFSBinaryNotFound(
            f"Could not find ipfs binary inside Kubo archive for {_platform_key()}"
        )
    # Owner-execute only — site-packages is typically owned by the install
    # user, and a multi-user host has its own kubo install.
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC)


def _check_disk_space(dest: Path) -> None:
    target = dest.parent
    while not target.exists() and target != target.parent:
        target = target.parent
    try:
        free = shutil.disk_usage(target).free
    except OSError:
        return  # best-effort
    if free < _INSTALL_FREE_BYTES:
        raise IPFSBinaryNotFound(
            f"Not enough disk space to install Kubo: {free // (1024 * 1024)} MB free at "
            f"{target}, need at least {_INSTALL_FREE_BYTES // (1024 * 1024)} MB. "
            f"Free up space or set basic_ipfs.REPO_PATH to a different disk."
        )


def _write_provenance(binary_path: Path, url: str, sha512_hex: str) -> None:
    """Audit trail next to the binary: where it came from and how we verified it."""
    prov = binary_path.parent / ".provenance.json"
    data = {
        "version": KUBO_VERSION,
        "url": url,
        "sha512": sha512_hex,
        "verification": "baked-in",
        "installed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": _platform_key(),
    }
    try:
        prov.write_text(json.dumps(data, indent=2))
    except OSError:
        pass  # non-fatal


def _auto_download_kubo(dest: Path) -> None:
    archive_url, ext = _archive_info()
    _check_disk_space(dest)
    expected = _expected_sha512(archive_url)

    dest.parent.mkdir(parents=True, exist_ok=True)
    archive_tmp = dest.parent / (dest.name + ".archive.partial")
    archive_tmp.unlink(missing_ok=True)
    partial = dest.parent / (dest.name + ".partial")
    partial.unlink(missing_ok=True)

    try:
        actual = _download(archive_url, archive_tmp)
        if not hmac.compare_digest(actual, expected):
            raise IPFSBinaryNotFound(
                f"SHA-512 mismatch for Kubo {KUBO_VERSION} ({_platform_key()}): "
                f"expected {expected}, got {actual}. Refusing to install an unverified binary."
            )
        # Extract to a sibling .partial path, then atomic rename. Prevents a
        # half-written binary on interrupted installs.
        _extract_binary(archive_tmp, ext, partial)
        os.replace(partial, dest)
    finally:
        # Always clean up the streamed archive; never leave a half-written
        # .partial executable around on a verification or extraction failure.
        archive_tmp.unlink(missing_ok=True)
        if partial.exists() and not dest.exists():
            partial.unlink(missing_ok=True)

    _write_provenance(dest, archive_url, expected)
    logger.info("Kubo %s installed at %s (verified via baked-in SHA-512)",
                KUBO_VERSION, dest)


def _find_or_install_kubo() -> Path:
    """user_data_dir bin → bundled bin (PyInstaller / pre-placed) → system PATH → auto-download.

    Resolution order matters: a binary the user explicitly dropped into
    user_data_dir wins so air-gapped or pre-vetted installs are honoured;
    a binary inside the wheel wins next so PyInstaller / Briefcase
    bundles still work; only then do we fall back to whatever ``ipfs``
    is on PATH or download a fresh copy. The downloader always writes
    to the user_data_dir path — never into site-packages.
    """
    user = _user_binary_path()
    if user.exists():
        try:
            user.chmod(user.stat().st_mode | stat.S_IEXEC)
        except OSError as exc:
            logger.warning("could not chmod %s: %s", user, exc)
        return user

    bundled = _bundled_binary_path()
    if bundled.exists():
        try:
            bundled.chmod(bundled.stat().st_mode | stat.S_IEXEC)
        except OSError as exc:
            logger.warning("could not chmod %s: %s", bundled, exc)
        return bundled

    on_path = shutil.which("ipfs")
    if on_path:
        logger.info("Using system-installed Kubo at %s", on_path)
        return Path(on_path)

    logger.info("Kubo binary not found locally — downloading %s…", KUBO_VERSION)
    try:
        _auto_download_kubo(user)
    except IPFSBinaryNotFound:
        raise
    except (requests.RequestException, OSError) as exc:
        raise IPFSBinaryNotFound(
            f"Failed to auto-download Kubo {KUBO_VERSION} for {_platform_key()}: {exc}\n"
            f"  Check your internet connection (or HTTPS_PROXY / REQUESTS_CA_BUNDLE), "
            f"  or place the binary manually at:\n    {user}"
        ) from exc
    return user


# ---------------------------------------------------------------------------
# Repo path
# ---------------------------------------------------------------------------


def _get_repo_path() -> Path:
    if REPO_PATH is not None:
        return Path(REPO_PATH)
    return Path(user_data_dir(APP_NAME)) / "ipfs_repo"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _as_str_list(arg: str | Iterable[str]) -> list[str]:
    """Normalise a single string or an iterable of strings into a plain list."""
    if isinstance(arg, str):
        return [arg]
    if isinstance(arg, (bytes, bytearray)):
        raise TypeError("argument must be str or iterable of str, not bytes")
    try:
        items = list(arg)
    except TypeError as exc:
        raise TypeError(
            f"argument must be str or iterable of str, not {type(arg).__name__}"
        ) from exc
    for c in items:
        if not isinstance(c, str):
            raise TypeError(f"every element must be str, got {type(c).__name__}")
    return items


def _chunked(items: list[str], size: int) -> Iterable[list[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _addr_score(multiaddr: str) -> int:
    """Score a multiaddr for sharing with others. Higher = better. -1 = exclude."""
    try:
        parts = multiaddr.split("/")
        proto = parts[1] if len(parts) > 1 else ""
        ip_str = parts[2] if len(parts) > 2 else ""
        if proto == "ip4":
            v4 = ipaddress.IPv4Address(ip_str)
            if v4.is_loopback:
                return -1
            return 2 if v4.is_global else 1  # public > private/LAN
        if proto == "ip6":
            v6 = ipaddress.IPv6Address(ip_str)
            if v6.is_loopback or v6.is_link_local:
                return -1
            return 2 if v6.is_global else 1
    except Exception:
        pass
    return -1


def _is_port_in_use(host: str, port: int) -> bool:
    """True if something is accepting on host:port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, port))
            return True
    except OSError:
        return False


def _secure_open(path: Path, mode: int = 0o600) -> int:
    """Open ``path`` for writing with restrictive perms applied atomically.

    Closes the TOCTOU window between ``write_text`` and ``chmod`` — without
    this, the file briefly exists with the process umask before its mode is
    tightened, so a co-tenant can race in and read a credential. Returns an
    OS-level file descriptor; caller is responsible for closing it.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW  # refuse to write through a symlink swap
    return os.open(str(path), flags, mode)


def _secure_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Write ``text`` to ``path`` with ``mode`` applied at create time."""
    fd = _secure_open(path, mode=mode)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
    except BaseException:
        # Clean up a half-written file on any failure (KeyboardInterrupt
        # included) so the next run starts from a known-empty state.
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _secure_mkdir(path: Path, mode: int = 0o700) -> None:
    """Create directories up to ``path`` with restrictive ``mode``.

    Each newly-created leaf is mkdir'd with the requested mode so an
    attacker can't snapshot the directory's contents during the umask
    window between ``mkdir`` and ``chmod``. Existing directories are left
    alone — the operator may have intentionally widened them.
    """
    path = Path(path)
    if path.exists():
        return
    parent = path.parent
    if parent != path and not parent.exists():
        _secure_mkdir(parent, mode=mode)
    try:
        os.mkdir(str(path), mode)
    except FileExistsError:
        return
    # umask can still mask bits off; force them on for the leaf.
    try:
        os.chmod(str(path), mode)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# IPFSManager — process-singleton daemon lifecycle (managed via module locks)
# ---------------------------------------------------------------------------


class IPFSManager:
    """Manages the Kubo daemon subprocess for the lifetime of the process.

    Public surface used by the module-level functions: ``start``, ``stop``,
    ``add``, ``announce``, ``add_folder``, ``cat``, ``pin_add``, ``pin_rm``,
    ``pin_ls``, ``pin_check``, ``block_exists``, ``repo_gc``, ``swarm_peers``,
    ``swarm_connect``, ``my_addrs``, ``status``.
    """

    def __init__(self) -> None:
        self._binary: Path | None = None
        self._repo: Path | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._owns_daemon = False
        self._api_url = f"http://{API_HOST}:{API_PORT}/api/v0"
        self._session: requests.Session | None = None
        self._log_path: Path | None = None
        self._log_file: io.IOBase | None = None  # writable handle for subprocess stderr
        self._initialised = False
        self._atexit_registered = False

    # ---------------- startup ----------------

    def start(self) -> None:
        if self._initialised:
            return

        self._binary = _find_or_install_kubo()
        self._repo = _get_repo_path()
        self._session = requests.Session()
        # Re-read config every start so callers can change API_HOST/API_PORT
        # between stop() and start().
        self._api_url = f"http://{API_HOST}:{API_PORT}/api/v0"

        self._ensure_repo()

        # Apply config to the on-disk repo, but only if no daemon is already
        # running — we don't want to edit another process's live config out
        # from under it.
        if not self._is_api_up():
            self._configure_api_address()
            self._configure_gateway_address()
            self._configure_storage_limit()
            self._configure_swarm_addresses()

        _swarm_key_warn_if_world_readable()
        self._start_daemon()
        self._wait_for_api()

        if not self._atexit_registered:
            atexit.register(self.stop)
            self._atexit_registered = True

        self._initialised = True
        logger.info("IPFS node ready — repo: %s", self._repo)

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["IPFS_PATH"] = str(self._repo)
        return env

    def _run_cli(
        self,
        *args: str,
        check: bool = True,
        timeout: int | None = 30,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self._binary), *args],
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )

    def _ensure_repo(self) -> None:
        assert self._repo is not None
        # Create with restrictive mode atomically so a multi-user host can't
        # peek into a freshly-created repo before chmod runs. mkdir() applies
        # the mode under the process umask; on POSIX we re-apply afterwards
        # to defeat a 0o077 umask, but the directory was never world-traversable
        # because mkdir(mode=0o700) clamps via the umask only for *additional*
        # bits — owner bits stay set. Existing dirs are left as-is (operator
        # may have widened them deliberately).
        if os.name == "posix":
            _secure_mkdir(self._repo, mode=0o700)
        else:
            self._repo.mkdir(parents=True, exist_ok=True)
        config_path = self._repo / "config"

        if not config_path.exists():
            logger.info("Initialising IPFS repo at %s", self._repo)
            try:
                self._run_cli("init", "--profile", "server")
            except subprocess.CalledProcessError as exc:
                raise IPFSError(
                    f"Failed to initialise IPFS repo at {self._repo}: {exc.stderr.strip()}"
                ) from exc
            return

        # Cheap corruption check: config exists and parses as JSON.
        try:
            json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            raise IPFSRepoCorrupt(
                f"IPFS repo config at {config_path} is unreadable: {exc}\n"
                f"  If salvageable, fix it manually. Otherwise delete\n"
                f"    {self._repo}\n"
                f"  and let basic_ipfs recreate it (you will lose local pins)."
            ) from exc

    def _configure_api_address(self) -> None:
        try:
            self._run_cli(
                "config", "Addresses.API",
                f"/ip4/{API_HOST}/tcp/{API_PORT}",
            )
        except subprocess.CalledProcessError as exc:
            logger.warning("Could not set API address: %s", exc.stderr)

    def _configure_gateway_address(self) -> None:
        try:
            self._run_cli(
                "config", "Addresses.Gateway",
                f"/ip4/{GATEWAY_HOST}/tcp/{GATEWAY_PORT}",
            )
        except subprocess.CalledProcessError as exc:
            logger.warning("Could not set Gateway address: %s", exc.stderr)

    def _configure_storage_limit(self) -> None:
        if not STORAGE_MAX:
            return
        try:
            self._run_cli("config", "Datastore.StorageMax", STORAGE_MAX)
        except subprocess.CalledProcessError as exc:
            logger.warning("Could not set storage limit: %s", exc.stderr)

    def _configure_swarm_addresses(self) -> None:
        if SWARM_ADDRESSES is None:
            return
        try:
            self._run_cli(
                "config", "Addresses.Swarm",
                "--json", json.dumps(list(SWARM_ADDRESSES)),
            )
        except subprocess.CalledProcessError as exc:
            logger.warning("Could not set Addresses.Swarm: %s", exc.stderr)

    def _open_daemon_log(self) -> None:
        """Open the daemon log file, rotating if the previous one is large."""
        assert self._repo is not None
        self._log_path = self._repo / _DAEMON_LOG_NAME
        try:
            if self._log_path.exists() and self._log_path.stat().st_size > _DAEMON_LOG_MAX_BYTES:
                old = self._log_path.with_suffix(self._log_path.suffix + ".old")
                if old.exists():
                    try:
                        old.unlink()
                    except OSError:
                        pass
                self._log_path.replace(old)
        except OSError:
            pass  # rotation is best-effort
        # Buffered: stderr write rates from Kubo are low, no need for unbuffered.
        # Open via os.open with mode 0o600 on POSIX so the file is never
        # world-readable, even briefly. The daemon log captures CIDs, peer
        # IDs, multiaddrs — fingerprintable activity.
        if os.name == "posix":
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            fd = os.open(str(self._log_path), flags, 0o600)
            self._log_file = os.fdopen(fd, "ab")
            # If the file pre-existed with a wider mode, narrow it.
            try:
                os.chmod(self._log_path, 0o600)
            except OSError as exc:
                logger.warning("could not restrict log perms at %s: %s", self._log_path, exc)
        else:
            self._log_file = open(self._log_path, "ab")

    def _start_daemon(self) -> None:
        if self._is_api_up():
            logger.info("IPFS API already reachable — skipping daemon launch")
            return

        # If something is bound to the port and isn't a Kubo daemon, fail loud.
        if _is_port_in_use(API_HOST, API_PORT):
            raise IPFSPortInUse(
                f"Port {API_HOST}:{API_PORT} is in use but does not look like an IPFS daemon. "
                f"Set basic_ipfs.API_PORT to a different port, or stop whatever is using it."
            )

        self._open_daemon_log()

        cmd = [
            str(self._binary), "daemon",
            "--migrate=true",
        ]
        # Critical: never pass PIPE for stdout/stderr on a long-lived process;
        # the OS pipe buffer (~64 KB) fills and the daemon blocks on its next
        # write. Discard stdout, send stderr to a rotating file.
        popen_kwargs: dict[str, Any] = {
            "env": self._env(),
            "stdout": subprocess.DEVNULL,
            "stderr": self._log_file,
        }
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        self._process = subprocess.Popen(cmd, **popen_kwargs)
        self._owns_daemon = True
        logger.info("Kubo daemon started (pid %d)", self._process.pid)

    def _read_log_tail(self, n_bytes: int = 4096) -> str:
        if not self._log_path or not self._log_path.exists():
            return "(no daemon log yet)"
        try:
            with open(self._log_path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - n_bytes))
                return fh.read().decode(errors="replace")
        except OSError:
            return "(log unreadable)"

    def _wait_for_api(self) -> None:
        deadline = time.monotonic() + DAEMON_STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self._is_api_up():
                return
            if self._process and self._process.poll() is not None:
                tail = self._read_log_tail()
                lower = tail.lower()
                if "lock" in lower and "repo" in lower:
                    raise IPFSRepoLocked(
                        f"The IPFS repo at {self._repo} is locked by another process. "
                        "Only one Kubo daemon can use a repo at a time. Stop the other "
                        "process, or set basic_ipfs.REPO_PATH to a different path.\n"
                        f"--- daemon log tail ---\n{tail}"
                    )
                raise IPFSError(
                    f"Kubo daemon exited unexpectedly (code {self._process.returncode}):\n{tail}"
                )
            time.sleep(0.5)
        raise IPFSDaemonTimeout(
            f"Kubo daemon did not become ready within {DAEMON_STARTUP_TIMEOUT}s. "
            f"See log: {self._log_path}"
        )

    # ---------------- shutdown ----------------

    def stop(self) -> None:
        if not self._initialised:
            return

        if not self._owns_daemon:
            # We piggy-backed on a daemon another process started. Don't
            # shut it down — that'd pull the rug out from under them.
            self._close_session_and_log()
            self._initialised = False
            return

        logger.info("Shutting down IPFS daemon…")
        try:
            self._post("shutdown", timeout=10)
        except Exception:
            pass

        if self._process:
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if sys.platform == "win32":
                    self._process.terminate()
                else:
                    self._process.send_signal(signal.SIGTERM)
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()

        self._close_session_and_log()
        self._owns_daemon = False
        self._initialised = False

    def _close_session_and_log(self) -> None:
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None
        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
            self._log_file = None

    # ---------------- HTTP helpers ----------------

    def _is_api_up(self) -> bool:
        # Confirm the listener on API_HOST:API_PORT is actually a Kubo
        # daemon, not a stray service that happens to return 200 on POST.
        # Without this check, a port collision on a shared dev host could
        # silently route add/pin calls into an unrelated service.
        if self._session is None:
            return False
        try:
            r = self._session.post(f"{self._api_url}/version", timeout=2)
        except Exception:
            return False
        if r.status_code != 200:
            return False
        try:
            body = r.json()
        except Exception:
            return False
        return isinstance(body, dict) and isinstance(body.get("Version"), str)

    def _post(
        self,
        endpoint: str,
        *,
        params: dict[str, Any] | list[tuple[str, Any]] | None = None,
        files: Any | None = None,
        data: Any | None = None,
        stream: bool = False,
        timeout: float | None = 60,
    ) -> requests.Response:
        assert self._session is not None
        url = f"{self._api_url}/{endpoint}"
        try:
            resp = self._session.post(
                url, params=params, files=files, data=data,
                stream=stream, timeout=timeout,
            )
        except requests.ConnectionError as exc:
            raise IPFSOperationError(
                f"Cannot reach IPFS daemon at {url}. Is it running?"
            ) from exc

        if not resp.ok:
            kubo_code: int | None = None
            kubo_type: str | None = None
            kubo_message: str | None = None
            try:
                body = resp.json()
            except Exception:
                body = None
            if isinstance(body, dict):
                kubo_message = body.get("Message")
                raw_code = body.get("Code")
                if isinstance(raw_code, int):
                    kubo_code = raw_code
                raw_type = body.get("Type")
                if isinstance(raw_type, str):
                    kubo_type = raw_type
            detail = kubo_message if kubo_message is not None else resp.text
            raise IPFSOperationError(
                f"IPFS API error [{resp.status_code}] {endpoint}: {detail}",
                status_code=resp.status_code,
                kubo_code=kubo_code,
                kubo_type=kubo_type,
                kubo_message=kubo_message,
            )
        return resp

    # ---------------- core operations ----------------

    def _add(
        self,
        source: str | bytes | os.PathLike[str],
        pin: bool,
        provide: bool = True,
        only_hash: bool = False,
    ) -> str:
        if isinstance(source, (bytes, bytearray, memoryview)):
            file_obj: io.IOBase = io.BytesIO(bytes(source))
            filename = "data"
            close_after = False
        elif isinstance(source, (str, os.PathLike)):
            path = Path(os.fspath(source))
            if not path.exists():
                raise FileNotFoundError(f"File not found: {path}")
            if path.is_dir():
                raise IsADirectoryError(
                    f"{path} is a directory — use add_folder() for directories."
                )
            file_obj = open(path, "rb")
            filename = path.name
            close_after = True
        else:
            raise TypeError(
                f"source must be str, PathLike, or bytes, not {type(source).__name__}"
            )

        params: list[tuple[str, str]] = [
            ("pin", "true" if pin else "false"),
            ("cid-version", "1"),
        ]
        if not provide:
            # Skip DHT announce. Content is still locally addressable; peers
            # who already know the CID can fetch via bitswap, but no provider
            # record is published.
            params.append(("provide", "false"))
        if only_hash:
            # Compute the CID without writing a block to the repo, pinning,
            # or announcing anything. Pin/provide flags are silently ignored
            # by Kubo when only-hash is set; we still send the same shape so
            # the request is uniform with the regular add path.
            params.append(("only-hash", "true"))
        try:
            resp = self._post(
                "add",
                params=params,
                files={"file": (filename, file_obj)},
                timeout=None,
            )
        finally:
            if close_after:
                file_obj.close()

        lines = [ln for ln in resp.text.strip().splitlines() if ln.strip()]
        cid: str = json.loads(lines[-1])["Hash"]
        return cid

    def add(
        self,
        source: str | bytes | os.PathLike[str],
        provide: bool = True,
    ) -> str:
        return self._add(source, pin=True, provide=provide)

    def announce(
        self,
        source: str | bytes | os.PathLike[str],
        provide: bool = True,
    ) -> str:
        return self._add(source, pin=False, provide=provide)

    def compute_cid_locally(
        self,
        source: str | bytes | os.PathLike[str],
    ) -> str:
        # only-hash=true is Kubo's "chunk and hash, do not write" mode. No
        # block is stored in the repo, no pin is created, no provider record
        # is announced, no peer ever learns the CID exists.
        return self._add(source, pin=False, provide=False, only_hash=True)

    def add_folder(self, path: str | os.PathLike[str]) -> str:
        src = Path(os.fspath(path)).resolve()
        if not src.is_dir():
            raise NotADirectoryError(f"Not a directory: {src}")

        # Build a multipart body: every directory becomes an empty part with
        # Content-Type: application/x-directory; every file becomes a regular
        # part. Filenames are POSIX-style relative paths rooted at src.name,
        # which makes the response's last entry the CID of src itself.
        files: list[tuple[str, tuple[str, Any, str]]] = []
        open_handles: list[Any] = []
        try:
            for current_dir, dirnames, filenames in os.walk(src):
                dirnames.sort()
                filenames.sort()
                current_path = Path(current_dir)
                rel = current_path.relative_to(src)
                dir_name = src.name if rel == Path(".") else (Path(src.name) / rel).as_posix()
                files.append(("file", (dir_name, b"", "application/x-directory")))
                for fname in filenames:
                    rel_file = (Path(src.name) / rel / fname).as_posix()
                    fh = open(current_path / fname, "rb")
                    open_handles.append(fh)
                    files.append(("file", (rel_file, fh, "application/octet-stream")))

            resp = self._post(
                "add",
                params=[
                    ("recursive", "true"),
                    ("wrap-with-directory", "false"),
                    ("pin", "true"),
                    ("cid-version", "1"),
                    ("quieter", "true"),
                ],
                files=files,
                timeout=None,
            )
        finally:
            for fh in open_handles:
                try:
                    fh.close()
                except Exception:
                    pass

        # quieter=true emits only the root entry — but parse defensively in
        # case Kubo decides to be chatty in a future version.
        lines = [ln for ln in resp.text.strip().splitlines() if ln.strip()]
        if not lines:
            raise IPFSOperationError("ipfs add returned no output")
        cid: str = json.loads(lines[-1])["Hash"]
        return cid

    def cat(self, cid: str, output_path: str | os.PathLike[str] | None = None) -> bytes | None:
        resp = self._post("cat", params={"arg": cid}, stream=True, timeout=None)
        if output_path is not None:
            with open(os.fspath(output_path), "wb") as fh:
                for chunk in resp.iter_content(chunk_size=1 << 16):
                    fh.write(chunk)
            return None
        return resp.content

    def pin_add(self, cids: str | Iterable[str]) -> None:
        cid_list = _as_str_list(cids)
        for chunk in _chunked(cid_list, _PIN_BATCH_SIZE):
            params = [("arg", c) for c in chunk]
            params.append(("recursive", "true"))
            self._post("pin/add", params=params, timeout=None)

    def pin_rm(self, cids: str | Iterable[str]) -> None:
        cid_list = _as_str_list(cids)
        for chunk in _chunked(cid_list, _PIN_BATCH_SIZE):
            try:
                params = [("arg", c) for c in chunk]
                params.append(("recursive", "true"))
                self._post("pin/rm", params=params, timeout=60)
            except IPFSOperationError as exc:
                if not exc.is_not_pinned():
                    raise
                # One or more CIDs in the batch weren't pinned. Kubo aborts the
                # whole batch in that case, so fall back to per-CID removal to
                # preserve idempotency — each swallowed individually.
                for c in chunk:
                    try:
                        self._post(
                            "pin/rm",
                            params={"arg": c, "recursive": "true"},
                            timeout=60,
                        )
                    except IPFSOperationError as per_exc:
                        if not per_exc.is_not_pinned():
                            raise

    def pin_ls(self) -> list[str]:
        resp = self._post("pin/ls", params={"type": "recursive"}, timeout=10).json()
        return list(resp.get("Keys", {}).keys())

    def pin_check(self, cid: str) -> bool:
        # Use type=recursive (matches pin_ls). Indirect pins (folder children)
        # are intentionally NOT counted — the only pins basic_ipfs creates are
        # recursive ones via add(), so this is the consistent answer.
        try:
            self._post("pin/ls", params={"arg": cid, "type": "recursive"}, timeout=10)
            return True
        except IPFSOperationError as exc:
            if exc.is_not_pinned():
                return False
            raise

    def block_exists(self, cid: str) -> bool:
        # offline=true is critical: without it, Kubo will try to fetch the
        # block from the swarm if it isn't local, which can hang for the
        # full timeout and contradicts what exists() promises.
        try:
            self._post(
                "block/stat",
                params={"arg": cid, "offline": "true"},
                timeout=5,
            )
            return True
        except (IPFSOperationError, requests.exceptions.Timeout):
            return False

    def repo_gc(self) -> None:
        self._post("repo/gc", timeout=None)

    def swarm_peers(self) -> list[str]:
        resp = self._post("swarm/peers", timeout=10).json()
        result = []
        for p in resp.get("Peers", []) or []:
            addr = p.get("Addr", "")
            peer = p.get("Peer", "")
            if peer and "/p2p/" not in addr:
                addr = f"{addr}/p2p/{peer}"
            if addr:
                result.append(addr)
        return result

    def swarm_connect(self, multiaddrs: str | Iterable[str]) -> None:
        for addr in _as_str_list(multiaddrs):
            self._post("swarm/connect", params={"arg": addr}, timeout=30)

    def my_addrs(self) -> list[str]:
        resp = self._post("id", timeout=5).json()
        return resp.get("Addresses", []) or []

    def status(self) -> StatusDict:
        ver = self._post("version", timeout=5).json()
        id_info = self._post("id", timeout=5).json()
        repo_stat = self._post("repo/stat", timeout=10).json()
        pins = self._post("pin/ls", params={"type": "recursive"}, timeout=10).json()
        return {
            "peer_id": id_info.get("ID"),
            "agent_version": ver.get("Version"),
            "repo_size_bytes": repo_stat.get("RepoSize"),
            "num_objects": repo_stat.get("NumObjects"),
            "pinned_cids": len(pins.get("Keys", {})),
            "addresses": id_info.get("Addresses", []) or [],
        }


# ---------------------------------------------------------------------------
# Module-level singleton — lazy-started on first use
# ---------------------------------------------------------------------------

_manager: IPFSManager | None = None
_start_lock = threading.Lock()


def _get_manager() -> IPFSManager:
    global _manager
    if _manager is None:
        with _start_lock:
            if _manager is None:
                m = IPFSManager()
                m.start()
                # Publish only after start() completes, so other threads
                # never observe a half-initialised manager.
                _manager = m
    return _manager


# ---------------------------------------------------------------------------
# Public API — the functions you actually call
# ---------------------------------------------------------------------------


def add(
    source: str | bytes | os.PathLike[str],
    provide: bool = True,
) -> str:
    """Add a file (path or bytes) to IPFS and pin it. Returns the CID.

    Pass ``provide=False`` to skip the DHT announce — the content is still
    addressable by CID, but its presence on this node is not advertised to
    the public network. Useful for staging private data before deciding
    whether to publish.
    """
    return _get_manager().add(source, provide=provide)


def announce(
    source: str | bytes | os.PathLike[str],
    provide: bool = True,
) -> str:
    """Add a file (path or bytes) to IPFS without pinning. Returns the CID.

    Content is available on the network but may be garbage-collected unless
    pinned later. Pass ``provide=False`` to skip the DHT announce.
    """
    return _get_manager().announce(source, provide=provide)


@overload
def get(cid: str) -> bytes: ...
@overload
def get(cid: str, output_path: str | os.PathLike[str]) -> None: ...


def get(cid: str, output_path: str | os.PathLike[str] | None = None) -> bytes | None:
    """Retrieve content by CID.

    Returns bytes unless output_path is given (then writes to disk and
    returns None).
    """
    return _get_manager().cat(cid, output_path)


def pin(cids: str | Iterable[str]) -> None:
    """Recursively pin one or many CIDs so they are never garbage-collected.

    Accepts a single CID string or any iterable of CID strings.
    """
    _get_manager().pin_add(cids)


def unpin(cids: str | Iterable[str]) -> None:
    """Unpin one or many CIDs. Accepts a single CID string or any iterable.

    Idempotent — already-unpinned CIDs are silently skipped.
    """
    _get_manager().pin_rm(cids)


def get_all_pins() -> list[str]:
    """Return a list of all currently pinned CIDs (recursive pins only)."""
    return _get_manager().pin_ls()


def is_pinned(cid: str) -> bool:
    """Return True if cid has a recursive pin (matches get_all_pins())."""
    return _get_manager().pin_check(cid)


def exists(cid: str) -> bool:
    """Return True if cid is available in the local node."""
    return _get_manager().block_exists(cid)


def garbage_collection() -> None:
    """Trigger Kubo GC, freeing storage used by unpinned content."""
    _get_manager().repo_gc()


def add_folder(path: str | os.PathLike[str]) -> str:
    """Add a directory to IPFS recursively and pin it. Returns the root CID."""
    return _get_manager().add_folder(path)


def compute_cid_locally(
    source: str | bytes | os.PathLike[str],
) -> str:
    """Return the CID a file or bytes payload *would* have, without
    publishing anything.

    Chunks and hashes the data using Kubo's ``add --only-hash`` mode:
    no block is written to the repo, no pin is created, no provider
    record is announced to the DHT, no peer ever learns the CID exists.
    Useful for previewing the CID of content you have not yet decided
    to publish.

    Output matches what ``add()`` / ``announce()`` would return for the
    same bytes (CIDv1, default chunker).
    """
    return _get_manager().compute_cid_locally(source)


def peers() -> list[str]:
    """Return the full multiaddrs of all currently connected peers."""
    return _get_manager().swarm_peers()


def connect_to_node(multiaddress: str) -> None:
    """Connect to a peer by multiaddr (e.g. /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...)."""
    _get_manager().swarm_connect(multiaddress)


def connect_to_nodes(multiaddresses: Iterable[str]) -> None:
    """Connect to multiple peers. Errors raise on the first failed address."""
    _get_manager().swarm_connect(multiaddresses)


def my_node_multiaddress() -> tuple[str | None, str | None]:
    """Return (ipv4_multiaddr, ipv6_multiaddr) for this node.

    Filters out loopback and link-local addresses and prefers public IPs.
    Either value may be None if that address family isn't available.
    Both strings are in the exact format connect_to_node() accepts.
    """
    all_addrs = _get_manager().my_addrs()
    scored = [(a, _addr_score(a)) for a in all_addrs]
    usable = [(a, s) for a, s in scored if s >= 0]

    ipv4 = next(
        (a for a, _ in sorted(
            ((a, s) for a, s in usable if a.startswith("/ip4/")),
            key=lambda x: x[1], reverse=True,
        )),
        None,
    )
    ipv6 = next(
        (a for a, _ in sorted(
            ((a, s) for a, s in usable if a.startswith("/ip6/")),
            key=lambda x: x[1], reverse=True,
        )),
        None,
    )
    return ipv4, ipv6


def status() -> StatusDict:
    """Return peer ID, repo size, pinned count, etc."""
    return _get_manager().status()


def start() -> None:
    """Explicitly start the daemon. Also happens lazily on the first call."""
    _get_manager()


def stop() -> None:
    """Explicitly stop the daemon. Also happens automatically on process exit."""
    global _manager
    with _start_lock:
        if _manager is not None:
            _manager.stop()
            _manager = None


class Node:
    """Context manager: start on enter, stop on exit."""

    def __enter__(self) -> Node:
        start()
        return self

    def __exit__(self, *_: Any) -> None:
        stop()


# Lowercase alias kept permanently for the documented `with basic_ipfs.node():` form.
node = Node


# ---------------------------------------------------------------------------
# Private network support
#
# By default every IPFS node joins the *public* IPFS network: anyone can
# connect to you, and your CIDs are discoverable by the whole world.
#
# A private network changes this completely. Every node in your group shares
# a secret 256-bit key stored in a file called `swarm.key` inside the IPFS
# repo. When Kubo starts with that file present it enters isolation mode:
#
#   - It will ONLY complete the libp2p handshake with peers that present the
#     same key. Peers without it are silently dropped before any data is
#     exchanged — they can't even tell a node is there.
#   - It does NOT join the public DHT. Your group maintains its own private
#     routing table. The outside world cannot discover your peers or CIDs.
#   - XSalsa20 stream encryption is applied on top of every connection using
#     the shared key, so traffic between members is also encrypted in transit.
#
# The practical result: connect_to_nodes() + a shared swarm key gives you a
# completely isolated peer-to-peer network. Only nodes you give the key to
# can participate — this is your private DHT.
#
# ── How to set up a private network ─────────────────────────────────────────
#
# One node (the "founder") runs this BEFORE starting the daemon:
#
#     import basic_ipfs
#     key = basic_ipfs.create_private_network()  # generates key, writes swarm.key
#     basic_ipfs.start()                         # daemon starts in isolation mode
#     ipv4, ipv6 = basic_ipfs.my_node_multiaddress()
#     print(key)    # share this secret string with trusted nodes
#     print(ipv4)   # share your address so they can connect to you
#
# Every other node runs this BEFORE starting their daemon:
#
#     import basic_ipfs
#     basic_ipfs.join_private_network("<key from founder>")
#     basic_ipfs.start()
#     basic_ipfs.connect_to_node("<founder's ipv4 or ipv6 multiaddr>")
#     # now fully peered — content flows directly between members
#
# IMPORTANT: swarm.key must exist before `ipfs daemon` launches. These
# functions raise IPFSError if called while the daemon is already running.
# ---------------------------------------------------------------------------


def _swarm_key_path() -> Path:
    # Kubo looks for swarm.key directly inside $IPFS_PATH (the repo root).
    return _get_repo_path() / "swarm.key"


def _write_swarm_key(key_hex: str) -> None:
    # The swarm.key file format is defined by go-libp2p-pnet. It is a
    # three-line text file:
    #
    #   /key/swarm/psk/1.0.0/  ← protocol identifier — must be this exact string
    #   /base16/               ← encoding of the key material — base16 = hex
    #   <64 hex chars>         ← 32 random bytes = 256-bit key
    #
    # Kubo reads this at startup and refuses connections from any peer whose
    # swarm.key does not contain the same 64 hex chars.
    path = _swarm_key_path()
    if os.name == "posix":
        _secure_mkdir(path.parent, mode=0o700)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    body = f"/key/swarm/psk/1.0.0/\n/base16/\n{key_hex}\n"
    if os.name == "posix":
        # Atomic create with mode 0o600 — closes the TOCTOU window between
        # write_text() and chmod() that would otherwise leak this credential
        # to any local user during the umask gap. swarm.key is a 256-bit
        # symmetric secret; a single read leaks permanent network access.
        _secure_write_text(path, body, mode=0o600)
    else:
        path.write_text(body)


def _swarm_key_warn_if_world_readable() -> None:
    if os.name != "posix":
        return
    path = _swarm_key_path()
    if not path.exists():
        return
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return
    if mode & 0o077:
        logger.warning(
            "swarm.key at %s is readable by other users (mode 0o%o). "
            "Run: chmod 600 %s", path, mode, path,
        )


def _daemon_is_running() -> bool:
    return _manager is not None and getattr(_manager, "_initialised", False)


def create_private_network() -> str:
    """Create a new private IPFS network by generating a random swarm key.

    Writes swarm.key to the repo so that when the daemon starts it will only
    accept connections from peers that share the same key.

    Returns the key as a 64-character hex string. Share this string (securely)
    with every node that should join your network — they pass it to
    join_private_network() before starting their daemon.

    Must be called BEFORE start() / the first IPFS operation.
    Safe to call multiple times — overwrites any existing swarm.key.
    """
    if _daemon_is_running():
        raise IPFSError(
            "Cannot write swarm.key while the daemon is running. "
            "Call create_private_network() before start() or any IPFS operation."
        )
    # os.urandom uses the OS CSPRNG (e.g. /dev/urandom on Linux, CryptGenRandom
    # on Windows) — safe for generating cryptographic key material.
    key_hex = os.urandom(32).hex()  # 32 bytes → 64 hex chars → 256-bit key
    _write_swarm_key(key_hex)
    logger.info("Private network swarm key written to %s", _swarm_key_path())
    return key_hex


def join_private_network(key: str) -> None:
    """Join an existing private network using a swarm key from another node.

    key: the 64-character hex string returned by create_private_network() on
         the founder's node. Treat it like a password — anyone with this key
         can join your network.

    Writes swarm.key to the repo so that when the daemon starts it will only
    accept connections from peers sharing the same key.

    Must be called BEFORE start() / the first IPFS operation.
    """
    if _daemon_is_running():
        raise IPFSError(
            "Cannot write swarm.key while the daemon is running. "
            "Call join_private_network() before start() or any IPFS operation."
        )
    key = key.strip().lower()
    # Validate: must be exactly 64 lowercase hex characters (32 bytes).
    if len(key) != 64 or not all(c in "0123456789abcdef" for c in key):
        raise ValueError(
            "key must be a 64-character hex string, as returned by "
            "create_private_network(). "
            f"Got {len(key)!r} characters."
        )
    _write_swarm_key(key)
    logger.info("Private network swarm key written to %s", _swarm_key_path())


def get_private_network_key() -> str | None:
    """Return this node's swarm key as a hex string, or None if not configured.

    Use this to retrieve the key from the founder node so you can share it
    with new members who need to call join_private_network().
    """
    path = _swarm_key_path()
    if not path.exists():
        return None
    for line in path.read_text().splitlines():
        line = line.strip()
        # The key line is the only line that doesn't start with '/'.
        if line and not line.startswith("/"):
            return line
    return None


def is_private_network() -> bool:
    """Return True if this node is configured to run as a private network."""
    return _swarm_key_path().exists()


def rotate_identity(oldkey_name: str = "previous-self") -> str:
    """Generate a new libp2p keypair, severing peer-ID linkability with prior runs.

    The old key is preserved under ``oldkey_name`` (default
    ``"previous-self"``) inside the keystore so it can be exported if you
    ever need to re-sign IPNS records published under the old identity.
    Pins, config, and ``swarm.key`` are untouched.

    The daemon must NOT be running. Call before the first IPFS operation,
    or stop a running daemon first (Python process exit stops it cleanly).

    Returns the new peer ID. Raises :class:`IPFSError` if the daemon is
    running, the repo is missing, or the underlying ``ipfs key rotate``
    fails.
    """
    if _daemon_is_running():
        raise IPFSError(
            "Cannot rotate identity while the daemon is running. "
            "Stop it first (let the Python process exit, or call stop())."
        )
    repo = _get_repo_path()
    if not (repo / "config").exists():
        raise IPFSError(
            f"No IPFS repo at {repo}. rotate_identity() requires an existing "
            "repo — run an operation once to initialise it, then rotate."
        )
    binary = _find_or_install_kubo()
    env = os.environ.copy()
    env["IPFS_PATH"] = str(repo)
    try:
        subprocess.run(
            [
                str(binary), "key", "rotate",
                f"--oldkey={oldkey_name}",
                "--type=ed25519",
            ],
            env=env, check=True, capture_output=True, text=True, timeout=30,
        )
    except subprocess.CalledProcessError as exc:
        raise IPFSError(
            f"Failed to rotate identity: {exc.stderr.strip()}"
        ) from exc
    try:
        config = json.loads((repo / "config").read_text())
        new_id: str = config["Identity"]["PeerID"]
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise IPFSError(f"Could not read new PeerID after rotation: {exc}") from exc
    logger.info(
        "Identity rotated. New peer ID: %s. Old key preserved as %r.",
        new_id, oldkey_name,
    )
    return new_id


def lockdown_mode() -> None:
    """Configure this node to never talk to the public IPFS network.

    Sets, on the on-disk repo:

    - ``Routing.Type = "none"`` — no DHT participation, no provider records.
    - ``Bootstrap = []`` — no auto-dial of Protocol Labs / Cloudflare nodes.
    - ``Swarm.Addresses`` restricted to loopback (``127.0.0.1`` + ``::1``).
    - ``Gateway.NoFetch = true`` — local gateway will not fetch remote CIDs.

    Call BEFORE :func:`start` / the first IPFS operation. The repo must
    already exist (run any operation once to initialise it, or call
    :func:`create_private_network` first if you want a private network
    overlaid).

    This is the right starting point for: encrypted-content stores, local
    caches, air-gapped pipelines, or any workflow where contacting third
    parties is unacceptable.
    """
    if _daemon_is_running():
        raise IPFSError(
            "Cannot apply lockdown_mode while the daemon is running. "
            "Call lockdown_mode() before start() / the first IPFS operation."
        )
    repo = _get_repo_path()
    if not (repo / "config").exists():
        raise IPFSError(
            f"No IPFS repo at {repo}. lockdown_mode() requires an existing "
            "repo — run an operation once to initialise it, or call "
            "create_private_network() first."
        )
    binary = _find_or_install_kubo()
    env = os.environ.copy()
    env["IPFS_PATH"] = str(repo)

    settings: list[tuple[list[str], str]] = [
        (["config", "Routing.Type", "none"], "Routing.Type"),
        (["config", "--json", "Bootstrap", "[]"], "Bootstrap"),
        (
            [
                "config", "--json", "Addresses.Swarm",
                json.dumps(["/ip4/127.0.0.1/tcp/4001", "/ip6/::1/tcp/4001"]),
            ],
            "Addresses.Swarm",
        ),
        (["config", "--json", "Gateway.NoFetch", "true"], "Gateway.NoFetch"),
    ]
    for argv, label in settings:
        try:
            subprocess.run(
                [str(binary), *argv],
                env=env, check=True, capture_output=True, text=True, timeout=15,
            )
        except subprocess.CalledProcessError as exc:
            raise IPFSError(
                f"Failed to set {label} during lockdown_mode: {exc.stderr.strip()}"
            ) from exc
    logger.info("lockdown_mode applied — node will not talk to public IPFS.")


# ---------------------------------------------------------------------------
# Long-name aliases — so code written against OpenMarket-Desktop's
# ipfs_manager.py keeps working after `pip install basic-ipfs`
# ---------------------------------------------------------------------------

add_to_ipfs = add
announce_to_ipfs = announce
get_from_ipfs = get
ipfs_pin = pin
ipfs_stop_pinning = unpin
get_pinned_cids = get_all_pins
start_ipfs_node = start
stop_ipfs_node = stop
get_ipfs_status = status

__all__ = [
    # short API
    "add", "announce", "add_folder", "compute_cid_locally",
    "get", "pin", "unpin", "get_all_pins", "is_pinned",
    "exists", "garbage_collection",
    "peers", "connect_to_node", "connect_to_nodes", "my_node_multiaddress",
    "create_private_network", "join_private_network",
    "get_private_network_key", "is_private_network",
    "rotate_identity", "lockdown_mode",
    "status", "start", "stop", "Node", "node",
    # long aliases
    "add_to_ipfs", "announce_to_ipfs", "get_from_ipfs", "ipfs_pin", "ipfs_stop_pinning",
    "get_pinned_cids", "start_ipfs_node", "stop_ipfs_node", "get_ipfs_status",
    # exceptions
    "IPFSError", "IPFSBinaryNotFound", "IPFSDaemonTimeout", "IPFSOperationError",
    "IPFSPortInUse", "IPFSRepoLocked", "IPFSRepoCorrupt",
    # types
    "StatusDict",
    # power-user internals
    "IPFSManager",
]

# Annotations are lazy (PEP 563), so these names exist only for type checkers
# and don't need to live in the module namespace at runtime. Hide them so
# `basic_ipfs.<TAB>` doesn't surface them. (Path / TypedDict / overload are
# kept — they're used at runtime.)
del Any, Iterable, Union
