"""
Tests for the auto-download path.

`requests` is mocked so we never hit the network. We exercise:
  - SHA-512 verification (success, mismatch, missing)
  - Atomic install (no half-written binary on failure)
  - Disk-space preflight
  - Baked-in vs network-fetched checksum preference
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from unittest import mock

import pytest
import requests

import basic_ipfs
from basic_ipfs import IPFSBinaryNotFound


def _make_tarball(binary_payload: bytes = b"#!/bin/sh\necho fake ipfs\n") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="kubo/ipfs")
        info.size = len(binary_payload)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(binary_payload))
    return buf.getvalue()


class _FakeResponse:
    def __init__(
        self,
        content: bytes,
        status: int = 200,
        text: str | None = None,
        url: str = "https://dist.ipfs.tech/fake",
    ):
        self._content = content
        self.status_code = status
        self.text = text if text is not None else ""
        self.headers = {"Content-Length": str(len(content))}
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i:i + chunk_size]


@pytest.fixture
def temp_install(tmp_path, monkeypatch):
    """Redirect _binary_path() to a writable temp dir."""
    bin_dir = tmp_path / "bin" / "linux-amd64"
    monkeypatch.setattr(basic_ipfs, "_binary_path", lambda: bin_dir / "ipfs")
    monkeypatch.setattr(basic_ipfs, "_platform_key", lambda: "linux-amd64")
    # Make disk-space check unconditionally pass.
    monkeypatch.setattr(basic_ipfs, "_check_disk_space", lambda _p: None)
    return bin_dir / "ipfs"


def _patch_session(monkeypatch, archive_bytes: bytes, sha_text: str | None = None):
    """Patch _download_session so the GET on the archive returns archive_bytes,
    and the GET on the .sha512 (if requested) returns sha_text.
    """

    class _FakeSession:
        def __init__(self):
            self.closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.close()

        def get(self, url, *_a, **_kw):
            if url.endswith(".sha512"):
                if sha_text is None:
                    raise requests.RequestException("sha512 not available")
                return _FakeResponse(b"", text=sha_text)
            return _FakeResponse(archive_bytes)

        def close(self):
            self.closed = True

        def mount(self, *_a, **_kw):
            pass

    monkeypatch.setattr(basic_ipfs, "_download_session", lambda: _FakeSession())


def test_install_uses_baked_in_checksum(temp_install, monkeypatch):
    archive = _make_tarball()
    correct_sha = hashlib.sha512(archive).hexdigest()
    monkeypatch.setattr(
        basic_ipfs.kubo_checksums, "known_checksum",
        lambda v, p: correct_sha,
    )
    _patch_session(monkeypatch, archive)

    basic_ipfs._auto_download_kubo(temp_install)
    assert temp_install.exists()
    assert temp_install.read_bytes().startswith(b"#!/bin/sh")
    # Provenance dropped alongside.
    assert (temp_install.parent / ".provenance.json").exists()


def test_install_refuses_without_baked_hash(temp_install, monkeypatch):
    """No baked-in SHA-512 = hard failure. We refuse to fetch the digest from
    the same origin as the archive (an attacker controlling dist.ipfs.tech
    could swap both files together)."""
    archive = _make_tarball()
    monkeypatch.setattr(
        basic_ipfs.kubo_checksums, "known_checksum", lambda v, p: None,
    )
    _patch_session(monkeypatch, archive)

    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._auto_download_kubo(temp_install)
    assert "kubo_checksums.py" in str(excinfo.value)
    assert not temp_install.exists()


def test_install_rejects_sha512_mismatch(temp_install, monkeypatch):
    archive = _make_tarball()
    wrong_sha = "0" * 128
    monkeypatch.setattr(
        basic_ipfs.kubo_checksums, "known_checksum", lambda v, p: wrong_sha,
    )
    _patch_session(monkeypatch, archive)

    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._auto_download_kubo(temp_install)
    assert "sha-512 mismatch" in str(excinfo.value).lower()
    # Critical: nothing was written to dest after a verification failure.
    assert not temp_install.exists()


def test_install_atomic_no_partial_left_behind(temp_install, monkeypatch):
    """If extraction itself fails, the .partial path is gone or doesn't pollute dest."""
    archive = _make_tarball()
    correct_sha = hashlib.sha512(archive).hexdigest()
    monkeypatch.setattr(
        basic_ipfs.kubo_checksums, "known_checksum", lambda v, p: correct_sha,
    )
    _patch_session(monkeypatch, archive)

    # Simulate extraction failure by patching _extract_binary to raise.
    def boom(*_a, **_kw):
        raise OSError("simulated extract failure")
    monkeypatch.setattr(basic_ipfs, "_extract_binary", boom)

    with pytest.raises(OSError):
        basic_ipfs._auto_download_kubo(temp_install)
    assert not temp_install.exists()
    # Streamed archive must be cleaned up even on extraction failure.
    assert not (temp_install.parent / (temp_install.name + ".archive.partial")).exists()
    assert not (temp_install.parent / (temp_install.name + ".partial")).exists()


def test_download_aborts_when_response_exceeds_cap(tmp_path, monkeypatch):
    """A hostile origin that streams past _MAX_DOWNLOAD_BYTES must be cut off
    before exhausting disk."""
    monkeypatch.setattr(basic_ipfs, "_MAX_DOWNLOAD_BYTES", 1024)

    huge_chunks = [b"x" * 256 for _ in range(20)]  # 5120 bytes — well over cap

    class _BigSession:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def get(self, url, *_a, **_kw):
            return _BigResponse(url)

        def close(self):
            pass

        def mount(self, *_a, **_kw):
            pass

    class _BigResponse:
        def __init__(self, url):
            self.url = url
            self.status_code = 200
            self.headers = {"Content-Length": "999999"}

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def raise_for_status(self):
            pass

        def iter_content(self, chunk_size=1):
            yield from huge_chunks

    monkeypatch.setattr(basic_ipfs, "_download_session", lambda: _BigSession())
    dest = tmp_path / "archive.bin"
    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._download("https://dist.ipfs.tech/fake", dest)
    assert "more than" in str(excinfo.value).lower()


def test_download_returns_sha512_hex(tmp_path, monkeypatch):
    payload = b"hello world"
    monkeypatch.setattr(
        basic_ipfs, "_download_session",
        lambda: _patch_session_factory(payload),
    )
    dest = tmp_path / "out.bin"
    digest = basic_ipfs._download("https://dist.ipfs.tech/fake", dest)
    assert digest == hashlib.sha512(payload).hexdigest()
    assert dest.read_bytes() == payload


def _patch_session_factory(payload: bytes):
    class _S:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def get(self, url, *_a, **_kw):
            return _FakeResponse(payload, url=url)

        def close(self):
            pass

        def mount(self, *_a, **_kw):
            pass

    return _S()




def test_disk_space_check_blocks_install(temp_install, monkeypatch):
    """End-to-end: low disk space stops the install before download."""
    monkeypatch.setattr(
        basic_ipfs, "_check_disk_space",
        mock.Mock(side_effect=IPFSBinaryNotFound("disk full")),
    )
    # Even if the network would succeed, the preflight blocks.
    archive = _make_tarball()
    _patch_session(monkeypatch, archive)
    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._auto_download_kubo(temp_install)
    assert "disk full" in str(excinfo.value)


def test_provenance_records_baked(temp_install, monkeypatch):
    archive = _make_tarball()
    correct_sha = hashlib.sha512(archive).hexdigest()

    monkeypatch.setattr(
        basic_ipfs.kubo_checksums, "known_checksum", lambda v, p: correct_sha,
    )
    _patch_session(monkeypatch, archive)
    basic_ipfs._auto_download_kubo(temp_install)
    import json
    prov = json.loads((temp_install.parent / ".provenance.json").read_text())
    assert prov["verification"] == "baked-in"
    assert prov["sha512"] == correct_sha


def test_download_session_has_retry_adapter():
    """Sanity check: the session is configured with retries."""
    session = basic_ipfs._download_session()
    adapter = session.get_adapter("https://dist.ipfs.tech")
    # urllib3 Retry config should be present.
    assert adapter.max_retries.total >= 1
    session.close()


@pytest.mark.parametrize("bad", [
    "v0.40.1/../../evil",
    "v0.40.1\nfoo",
    "0.40.1",       # missing leading 'v'
    "v0.40",        # only major.minor
    "v0.40.1 ",     # trailing whitespace
    "",
])
def test_archive_info_rejects_malformed_version(bad, monkeypatch):
    monkeypatch.setattr(basic_ipfs, "KUBO_VERSION", bad)
    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._archive_info()
    assert "kubo_version" in str(excinfo.value).lower()


@pytest.mark.parametrize("good", ["v0.40.1", "v1.2.3", "v0.41.0-rc1"])
def test_archive_info_accepts_well_formed_version(good, monkeypatch):
    monkeypatch.setattr(basic_ipfs, "KUBO_VERSION", good)
    url, ext = basic_ipfs._archive_info()
    assert good in url
    assert ext in ("tar.gz", "zip")


def test_download_rejects_offsite_redirect(temp_install, monkeypatch):
    """Even with TLS valid, a 30x to a non-pinned host must fail."""
    archive = _make_tarball()
    correct_sha = hashlib.sha512(archive).hexdigest()
    monkeypatch.setattr(
        basic_ipfs.kubo_checksums, "known_checksum", lambda v, p: correct_sha,
    )

    class _RedirectSession:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def get(self, url, *_a, **_kw):
            return _FakeResponse(archive, url="https://attacker.example/kubo")

        def close(self):
            pass

        def mount(self, *_a, **_kw):
            pass

    monkeypatch.setattr(basic_ipfs, "_download_session", lambda: _RedirectSession())

    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._auto_download_kubo(temp_install)
    assert "attacker.example" in str(excinfo.value)
    assert not temp_install.exists()
