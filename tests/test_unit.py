"""
Pure unit tests — no daemon, no network. Fast.

Cover everything that can be tested without spinning up Kubo:
platform detection, helpers, key validation, checksum lookup, etc.
"""

from __future__ import annotations

import json
import os
from unittest import mock

import pytest

import basic_ipfs
from basic_ipfs import (
    IPFSBinaryNotFound,
    StatusDict,
    _addr_score,
    _as_str_list,
    _chunked,
    _is_port_in_use,
    _safe_member_name,
    kubo_checksums,
)

# ---------------------------------------------------------------------------
# _as_str_list
# ---------------------------------------------------------------------------


def test_as_str_list_single_string():
    assert _as_str_list("Qm123") == ["Qm123"]


def test_as_str_list_iterable():
    assert _as_str_list(["a", "b", "c"]) == ["a", "b", "c"]
    assert _as_str_list(("a", "b")) == ["a", "b"]
    assert _as_str_list(iter(["a", "b"])) == ["a", "b"]


def test_as_str_list_empty():
    assert _as_str_list([]) == []


def test_as_str_list_rejects_bytes():
    with pytest.raises(TypeError):
        _as_str_list(b"abc")


def test_as_str_list_rejects_int():
    with pytest.raises(TypeError):
        _as_str_list(42)


def test_as_str_list_rejects_mixed_types():
    with pytest.raises(TypeError):
        _as_str_list(["abc", 42])


# ---------------------------------------------------------------------------
# _chunked
# ---------------------------------------------------------------------------


def test_chunked_exact_multiple():
    assert list(_chunked(["a", "b", "c", "d"], 2)) == [["a", "b"], ["c", "d"]]


def test_chunked_remainder():
    assert list(_chunked(["a", "b", "c"], 2)) == [["a", "b"], ["c"]]


def test_chunked_empty():
    assert list(_chunked([], 10)) == []


def test_chunked_single_chunk():
    assert list(_chunked(["a", "b"], 100)) == [["a", "b"]]


# ---------------------------------------------------------------------------
# _addr_score
# ---------------------------------------------------------------------------


def test_addr_score_loopback_excluded():
    assert _addr_score("/ip4/127.0.0.1/tcp/4001") == -1
    assert _addr_score("/ip6/::1/tcp/4001") == -1


def test_addr_score_link_local_excluded():
    assert _addr_score("/ip6/fe80::1/tcp/4001") == -1


def test_addr_score_public_ip_preferred():
    public = _addr_score("/ip4/8.8.8.8/tcp/4001")
    private = _addr_score("/ip4/192.168.1.5/tcp/4001")
    assert public > private
    assert private >= 0


def test_addr_score_malformed():
    assert _addr_score("garbage") == -1
    assert _addr_score("/ip4/not-an-ip/tcp/4001") == -1


# ---------------------------------------------------------------------------
# _is_port_in_use
# ---------------------------------------------------------------------------


def test_port_in_use_detects_bound_socket():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        assert _is_port_in_use("127.0.0.1", port) is True
    finally:
        s.close()


def test_port_in_use_false_for_unbound():
    # 1 is reserved and almost never has a listener.
    assert _is_port_in_use("127.0.0.1", 1) is False


# ---------------------------------------------------------------------------
# _safe_member_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "kubo/ipfs",
    "kubo/bin/ipfs",
    "ipfs.exe",
])
def test_safe_member_name_accepts_normal(name):
    assert _safe_member_name(name) is True


@pytest.mark.parametrize("name", [
    "",
    "/etc/passwd",
    "\\Windows\\System32\\evil.exe",
    "../../../etc/passwd",
    "kubo/../../etc/passwd",
    "a/b/c/d/e/f",  # exceeds depth cap
])
def test_safe_member_name_rejects_hostile(name):
    assert _safe_member_name(name) is False


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def test_platform_key_returns_known_triple():
    key = basic_ipfs._platform_key()
    assert key in (
        "linux-amd64", "linux-arm64", "linux-riscv64",
        "darwin-amd64", "darwin-arm64",
        "windows-amd64",
    )


def test_unsupported_platform_message_helpful(monkeypatch):
    monkeypatch.setattr(basic_ipfs.platform, "system", lambda: "Plan9")
    monkeypatch.setattr(basic_ipfs.platform, "machine", lambda: "weirdarch")
    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._platform_key()
    msg = str(excinfo.value)
    assert "plan9/weirdarch" in msg.lower()
    assert "supported" in msg.lower()
    # Includes a fallback path so users know where to drop a manual binary.
    assert "bin/" in msg or "bin\\" in msg


def test_armv7_explicit_unsupported_message(monkeypatch):
    monkeypatch.setattr(basic_ipfs.platform, "system", lambda: "Linux")
    monkeypatch.setattr(basic_ipfs.platform, "machine", lambda: "armv7l")
    monkeypatch.setattr(basic_ipfs, "_is_musl", lambda: False)
    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._platform_key()
    assert "32-bit ARM" in str(excinfo.value)
    assert "64-bit" in str(excinfo.value).lower() or "aarch64" in str(excinfo.value)


def test_musl_detection_blocks_install(monkeypatch):
    monkeypatch.setattr(basic_ipfs.platform, "system", lambda: "Linux")
    monkeypatch.setattr(basic_ipfs.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(basic_ipfs, "_is_musl", lambda: True)
    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._platform_key()
    assert "musl" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Checksum table
# ---------------------------------------------------------------------------


def test_known_checksum_returns_baked_in():
    sha = kubo_checksums.known_checksum("v0.40.1", "linux-amd64")
    assert sha is not None
    assert len(sha) == 128
    assert all(c in "0123456789abcdef" for c in sha)


def test_known_checksum_unknown_version():
    assert kubo_checksums.known_checksum("v999.999.999", "linux-amd64") is None


def test_known_checksum_unknown_platform():
    assert kubo_checksums.known_checksum("v0.40.1", "haiku-amd64") is None


def test_all_supported_triples_have_checksums():
    """Every supported triple must be in the table for the pinned version."""
    table = kubo_checksums.CHECKSUMS[basic_ipfs.KUBO_VERSION]
    expected = {
        "linux-amd64", "linux-arm64", "linux-riscv64",
        "darwin-amd64", "darwin-arm64",
        "windows-amd64",
    }
    assert expected.issubset(set(table.keys())), (
        f"kubo_checksums.py is missing entries for {expected - set(table.keys())} "
        f"in version {basic_ipfs.KUBO_VERSION}"
    )


def test_baked_checksums_are_well_formed():
    for version, plats in kubo_checksums.CHECKSUMS.items():
        for plat, sha in plats.items():
            assert len(sha) == 128, f"{version}/{plat}: not 128 hex chars"
            assert all(c in "0123456789abcdef" for c in sha), f"{version}/{plat}: not lowercase hex"


# ---------------------------------------------------------------------------
# Private network key validation (no daemon required)
# ---------------------------------------------------------------------------


def test_join_private_network_rejects_short_key(monkeypatch):
    monkeypatch.setattr(basic_ipfs, "_manager", None)
    with pytest.raises(ValueError):
        basic_ipfs.join_private_network("a" * 63)


def test_join_private_network_rejects_long_key(monkeypatch):
    monkeypatch.setattr(basic_ipfs, "_manager", None)
    with pytest.raises(ValueError):
        basic_ipfs.join_private_network("a" * 65)


def test_join_private_network_rejects_non_hex(monkeypatch):
    monkeypatch.setattr(basic_ipfs, "_manager", None)
    with pytest.raises(ValueError):
        basic_ipfs.join_private_network("z" * 64)


def test_join_private_network_accepts_uppercase(tmp_path, monkeypatch):
    monkeypatch.setattr(basic_ipfs, "REPO_PATH", tmp_path / "repo")
    monkeypatch.setattr(basic_ipfs, "_manager", None)
    upper = "A" * 64
    basic_ipfs.join_private_network(upper)
    # Function lowercases internally; round-trip must match.
    assert basic_ipfs.get_private_network_key() == upper.lower()


def test_swarm_key_chmod_0600_on_posix(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("POSIX-only")
    monkeypatch.setattr(basic_ipfs, "REPO_PATH", tmp_path / "repo")
    monkeypatch.setattr(basic_ipfs, "_manager", None)
    basic_ipfs.create_private_network()
    path = basic_ipfs._swarm_key_path()
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600, f"swarm.key mode should be 0o600, got 0o{mode:o}"


def test_get_private_network_key_returns_none_if_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(basic_ipfs, "REPO_PATH", tmp_path / "no_repo")
    assert basic_ipfs.get_private_network_key() is None


def test_is_private_network(tmp_path, monkeypatch):
    monkeypatch.setattr(basic_ipfs, "REPO_PATH", tmp_path / "repo")
    monkeypatch.setattr(basic_ipfs, "_manager", None)
    assert basic_ipfs.is_private_network() is False
    basic_ipfs.create_private_network()
    assert basic_ipfs.is_private_network() is True


# ---------------------------------------------------------------------------
# IPFSOperationError structured fields
# ---------------------------------------------------------------------------


def test_is_not_pinned_true_for_kubo_error():
    exc = basic_ipfs.IPFSOperationError(
        "IPFS API error [500] pin/rm: bafy... is not pinned",
        status_code=500,
        kubo_code=0,
        kubo_type="error",
        kubo_message="bafy... is not pinned",
    )
    assert exc.is_not_pinned() is True


def test_is_not_pinned_false_when_message_unrelated():
    exc = basic_ipfs.IPFSOperationError(
        "x",
        status_code=500,
        kubo_type="error",
        kubo_message="invalid CID",
    )
    assert exc.is_not_pinned() is False


def test_is_not_pinned_false_without_error_envelope():
    """An unstructured 502 (e.g. an HTML reverse-proxy page that happens to
    contain the words 'not pinned') must not be treated as a successful no-op."""
    exc = basic_ipfs.IPFSOperationError(
        "<html>not pinned</html>",
        status_code=502,
        kubo_type=None,
        kubo_message=None,
    )
    assert exc.is_not_pinned() is False


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


def test_all_exceptions_subclass_ipfs_error():
    for cls in (
        basic_ipfs.IPFSBinaryNotFound,
        basic_ipfs.IPFSDaemonTimeout,
        basic_ipfs.IPFSOperationError,
        basic_ipfs.IPFSPortInUse,
        basic_ipfs.IPFSRepoLocked,
        basic_ipfs.IPFSRepoCorrupt,
    ):
        assert issubclass(cls, basic_ipfs.IPFSError)


# ---------------------------------------------------------------------------
# StatusDict
# ---------------------------------------------------------------------------


def test_status_dict_keys():
    # Confirm StatusDict has the documented keys (TypedDict introspection).
    expected = {
        "peer_id", "agent_version", "repo_size_bytes",
        "num_objects", "pinned_cids", "addresses",
    }
    assert set(StatusDict.__annotations__.keys()) == expected


# ---------------------------------------------------------------------------
# Node context manager class
# ---------------------------------------------------------------------------


def test_node_class_and_alias_are_same():
    assert basic_ipfs.node is basic_ipfs.Node


# ---------------------------------------------------------------------------
# __version__ source
# ---------------------------------------------------------------------------


def test_version_matches_installed_metadata():
    """__version__ must match what pip resolved, not a hardcoded literal."""
    from importlib.metadata import PackageNotFoundError, version
    try:
        installed = version("basic-ipfs")
    except PackageNotFoundError:
        pytest.skip("basic-ipfs not installed (source checkout)")
    assert basic_ipfs.__version__ == installed


# ---------------------------------------------------------------------------
# Module-level long-name aliases
# ---------------------------------------------------------------------------


def test_aliases_identity():
    assert basic_ipfs.add_to_ipfs is basic_ipfs.add
    assert basic_ipfs.announce_to_ipfs is basic_ipfs.announce
    assert basic_ipfs.get_from_ipfs is basic_ipfs.get
    assert basic_ipfs.ipfs_pin is basic_ipfs.pin
    assert basic_ipfs.ipfs_stop_pinning is basic_ipfs.unpin
    assert basic_ipfs.get_pinned_cids is basic_ipfs.get_all_pins
    assert basic_ipfs.start_ipfs_node is basic_ipfs.start
    assert basic_ipfs.stop_ipfs_node is basic_ipfs.stop
    assert basic_ipfs.get_ipfs_status is basic_ipfs.status


# ---------------------------------------------------------------------------
# IPFSManager._is_api_up
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status: int = 200, body=None, raise_json: bool = False):
        self.status_code = status
        self._body = body
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("not json")
        return self._body


class _StubSession:
    def __init__(self, response):
        self._response = response

    def post(self, *_a, **_kw):
        return self._response


def _manager_with(response):
    m = basic_ipfs.IPFSManager()
    m._session = _StubSession(response)
    m._api_url = "http://127.0.0.1:5001/api/v0"
    return m


def test_is_api_up_true_for_real_kubo_response():
    m = _manager_with(_StubResponse(200, body={"Version": "0.40.1", "Commit": "abc"}))
    assert m._is_api_up() is True


def test_is_api_up_false_for_non_json_200():
    """Stray service returns 200 with HTML — must not be mistaken for Kubo."""
    m = _manager_with(_StubResponse(200, raise_json=True))
    assert m._is_api_up() is False


def test_is_api_up_false_when_version_field_missing():
    m = _manager_with(_StubResponse(200, body={"Hello": "world"}))
    assert m._is_api_up() is False


def test_is_api_up_false_for_non_200():
    m = _manager_with(_StubResponse(500, body={"Version": "0.40.1"}))
    assert m._is_api_up() is False


def test_is_api_up_false_when_session_missing():
    m = basic_ipfs.IPFSManager()
    assert m._is_api_up() is False


# ---------------------------------------------------------------------------
# Provenance file
# ---------------------------------------------------------------------------


def test_write_provenance(tmp_path):
    binary = tmp_path / "bin" / "linux-amd64" / "ipfs"
    binary.parent.mkdir(parents=True)
    binary.write_text("dummy")
    basic_ipfs._write_provenance(binary, "https://example/foo.tar.gz", "abc" * 40 + "x" * 8)
    prov = binary.parent / ".provenance.json"
    assert prov.exists()
    data = json.loads(prov.read_text())
    assert data["url"] == "https://example/foo.tar.gz"
    assert data["verification"] == "baked-in"
    assert data["version"] == basic_ipfs.KUBO_VERSION
    assert "installed_at_utc" in data


# ---------------------------------------------------------------------------
# Disk-space preflight
# ---------------------------------------------------------------------------


def test_disk_space_check_blocks_when_low(tmp_path, monkeypatch):
    fake_usage = mock.Mock(free=10 * 1024 * 1024)  # 10 MB
    monkeypatch.setattr(basic_ipfs.shutil, "disk_usage", lambda _p: fake_usage)
    with pytest.raises(IPFSBinaryNotFound) as excinfo:
        basic_ipfs._check_disk_space(tmp_path / "bin" / "ipfs")
    assert "disk space" in str(excinfo.value).lower()


def test_disk_space_check_passes_when_plenty(tmp_path, monkeypatch):
    fake_usage = mock.Mock(free=10 * 1024 * 1024 * 1024)  # 10 GB
    monkeypatch.setattr(basic_ipfs.shutil, "disk_usage", lambda _p: fake_usage)
    # Should not raise.
    basic_ipfs._check_disk_space(tmp_path / "bin" / "ipfs")
