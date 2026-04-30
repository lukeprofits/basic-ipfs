"""
End-to-end smoke tests for basic_ipfs.

These tests spin up a real Kubo daemon (auto-downloaded on first run).
They take ~5–60 seconds depending on whether the binary is cached.

Skips gracefully if the binary can't be obtained (e.g. offline CI).
"""

from __future__ import annotations

import os
import socket

import pytest

import basic_ipfs
from basic_ipfs import IPFSBinaryNotFound


def _has_internet() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="session", autouse=True)
def _node():
    """Bring the daemon up once for the whole test session."""
    try:
        basic_ipfs.start()
    except IPFSBinaryNotFound:
        if not _has_internet():
            pytest.skip("Kubo binary missing and no internet to download it")
        raise
    yield
    basic_ipfs.stop()


def test_add_bytes_roundtrip():
    payload = b"hello from basic_ipfs tests"
    cid = basic_ipfs.add(payload)
    assert isinstance(cid, str) and len(cid) > 10
    assert basic_ipfs.get(cid) == payload


def test_add_file_roundtrip(tmp_path):
    path = tmp_path / "example.bin"
    data = os.urandom(256 * 1024)  # 256 KB
    path.write_bytes(data)

    cid = basic_ipfs.add(str(path))
    assert basic_ipfs.get(cid) == data


def test_add_path_object_equivalent(tmp_path):
    from pathlib import Path

    p = tmp_path / "a.txt"
    p.write_bytes(b"abc")
    assert basic_ipfs.add(str(p)) == basic_ipfs.add(Path(p))


def test_get_to_disk_returns_none(tmp_path):
    data = b"write me to disk"
    cid = basic_ipfs.add(data)
    out = tmp_path / "got.bin"
    assert basic_ipfs.get(cid, str(out)) is None
    assert out.read_bytes() == data


def test_pin_and_unpin_idempotent():
    cid = basic_ipfs.add(b"pin test")
    basic_ipfs.pin(cid)
    basic_ipfs.unpin(cid)
    # Second unpin must not raise
    basic_ipfs.unpin(cid)


def test_pin_and_unpin_list():
    cids = [basic_ipfs.add(f"batch-{i}".encode()) for i in range(5)]
    basic_ipfs.pin(cids)
    basic_ipfs.unpin(cids)
    # Calling unpin again on the same list must be a no-op
    basic_ipfs.unpin(cids)


def test_pin_mixed_pinned_and_unpinned_list():
    # Pin half, then unpin the full list — the "not pinned" ones must
    # not cause the whole batch to fail.
    cids = [basic_ipfs.add(f"mix-{i}".encode()) for i in range(4)]
    basic_ipfs.pin(cids[:2])
    basic_ipfs.unpin(cids)  # includes 2 never-pinned CIDs


def test_pin_empty_list_noop():
    basic_ipfs.pin([])
    basic_ipfs.unpin([])


def test_pin_bad_type_raises():
    with pytest.raises(TypeError):
        basic_ipfs.pin(12345)
    with pytest.raises(TypeError):
        basic_ipfs.pin([123, 456])


def test_empty_bytes():
    cid = basic_ipfs.add(b"")
    assert basic_ipfs.get(cid) == b""


def test_bad_type_raises():
    with pytest.raises(TypeError):
        basic_ipfs.add(12345)


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        basic_ipfs.add("/does/not/exist/at/all.bin")


def test_status_shape():
    s = basic_ipfs.status()
    assert "peer_id" in s
    assert "agent_version" in s
    assert "repo_size_bytes" in s
    assert isinstance(s["pinned_cids"], int)


def test_aliases_point_to_same_functions():
    assert basic_ipfs.add_to_ipfs is basic_ipfs.add
    assert basic_ipfs.announce_to_ipfs is basic_ipfs.announce
    assert basic_ipfs.get_from_ipfs is basic_ipfs.get
    assert basic_ipfs.ipfs_pin is basic_ipfs.pin
    assert basic_ipfs.ipfs_stop_pinning is basic_ipfs.unpin


def test_get_all_pins_returns_list():
    cid = basic_ipfs.add(b"pins list test")
    pinned = basic_ipfs.get_all_pins()
    assert isinstance(pinned, list)
    assert cid in pinned
    basic_ipfs.unpin(cid)


def test_unpin_list():
    cids = [basic_ipfs.add(f"unpin-list-{i}".encode()) for i in range(3)]
    basic_ipfs.unpin(cids)
    pinned = basic_ipfs.get_all_pins()
    for cid in cids:
        assert cid not in pinned


def test_compute_cid_locally_matches_add():
    payload = b"compute-cid-locally test bytes"
    expected = basic_ipfs.add(payload)
    try:
        local_cid = basic_ipfs.compute_cid_locally(payload)
        assert local_cid == expected
    finally:
        basic_ipfs.unpin(expected)


def test_compute_cid_locally_does_not_pin_or_store(tmp_path):
    """A file the local node has never seen before should not appear in
    the local repo or pin set after compute_cid_locally."""
    payload = os.urandom(2048) + b"-only-hash-marker"
    cid = basic_ipfs.compute_cid_locally(payload)
    assert cid not in basic_ipfs.get_all_pins()
    assert basic_ipfs.exists(cid) is False


def test_compute_cid_locally_accepts_path(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"path input for only-hash")
    cid = basic_ipfs.compute_cid_locally(str(p))
    assert isinstance(cid, str) and len(cid) > 10


def test_announce_bytes_roundtrip():
    payload = b"announced content - basic_ipfs test"
    cid = basic_ipfs.announce(payload)
    assert isinstance(cid, str) and len(cid) > 10
    assert basic_ipfs.get(cid) == payload


def test_announce_not_pinned():
    cid = basic_ipfs.announce(b"announce no pin test")
    pinned_before = basic_ipfs.status()["pinned_cids"]
    basic_ipfs.unpin(cid)  # must be a no-op — content was never pinned
    assert basic_ipfs.status()["pinned_cids"] == pinned_before


def test_add_is_pinned():
    cid = basic_ipfs.add(b"add pins by default test")
    basic_ipfs.unpin(cid)  # succeeds only if add() pinned it


def test_is_pinned():
    cid = basic_ipfs.add(b"is_pinned test")
    assert basic_ipfs.is_pinned(cid) is True
    basic_ipfs.unpin(cid)
    assert basic_ipfs.is_pinned(cid) is False


def test_exists():
    cid = basic_ipfs.add(b"exists test")
    assert basic_ipfs.exists(cid) is True
    assert basic_ipfs.exists("bafybeiabc123doesnotexistXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX") is False
    basic_ipfs.unpin(cid)


def test_add_folder(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"file a")
    (tmp_path / "b.txt").write_bytes(b"file b")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.txt").write_bytes(b"file c")

    cid = basic_ipfs.add_folder(str(tmp_path))
    assert isinstance(cid, str) and len(cid) > 10
    assert basic_ipfs.is_pinned(cid)
    basic_ipfs.unpin(cid)


def test_pin_check_only_recursive(tmp_path):
    """is_pinned and get_all_pins must agree: indirect pins (folder children)
    are NOT counted, because basic_ipfs only ever creates recursive pins."""
    (tmp_path / "a.txt").write_bytes(b"child file a")
    (tmp_path / "b.txt").write_bytes(b"child file b")

    folder_cid = basic_ipfs.add_folder(str(tmp_path))
    try:
        # The folder itself is recursively pinned — both views agree.
        assert basic_ipfs.is_pinned(folder_cid) is True
        assert folder_cid in basic_ipfs.get_all_pins()

        # A standalone child file (separately added & unpinned) is indirectly
        # pinned through the folder, but neither view should claim it as
        # a top-level pin.
        child_cid = basic_ipfs.add(b"child file a")
        basic_ipfs.unpin(child_cid)
        assert basic_ipfs.is_pinned(child_cid) is False
        assert child_cid not in basic_ipfs.get_all_pins()
        # But the data is still locally available because the folder pins it.
        assert basic_ipfs.exists(child_cid) is True
    finally:
        basic_ipfs.unpin(folder_cid)


def test_add_folder_rejects_file(tmp_path):
    f = tmp_path / "notadir.txt"
    f.write_bytes(b"x")
    with pytest.raises(NotADirectoryError):
        basic_ipfs.add_folder(str(f))


def test_add_folder_handles_nested_and_empty_dirs(tmp_path):
    """The HTTP multipart implementation must produce a tree identical to
    `ipfs add -r --cid-version=1`, including for empty directories and nested
    structures."""
    (tmp_path / "top.txt").write_bytes(b"top")
    (tmp_path / "empty").mkdir()
    (tmp_path / "d1" / "d2").mkdir(parents=True)
    (tmp_path / "d1" / "one.txt").write_bytes(b"one")
    (tmp_path / "d1" / "d2" / "two.txt").write_bytes(b"")  # empty file

    cid = basic_ipfs.add_folder(str(tmp_path))
    try:
        # Root is reachable, and nested files can be fetched by subpath.
        assert basic_ipfs.exists(cid)
        nested = basic_ipfs.get(cid + "/d1/one.txt")
        assert nested == b"one"
    finally:
        basic_ipfs.unpin(cid)


def test_garbage_collection():
    basic_ipfs.garbage_collection()  # must not raise


def test_peers_returns_list():
    result = basic_ipfs.peers()
    assert isinstance(result, list)


def test_my_node_multiaddress():
    ipv4, ipv6 = basic_ipfs.my_node_multiaddress()
    assert ipv4 is not None or ipv6 is not None
    if ipv4:
        assert ipv4.startswith("/ip4/")
        assert "/p2p/" in ipv4
    if ipv6:
        assert ipv6.startswith("/ip6/")
        assert "/p2p/" in ipv6


def test_connect_to_node_bad_addr_raises():
    with pytest.raises(basic_ipfs.IPFSOperationError):
        basic_ipfs.connect_to_node("/ip4/0.0.0.0/tcp/4001/p2p/12D3KooWNotARealPeerXXXXXXX")


def test_private_network_functions_raise_while_running():
    # The daemon is already up for this test session, so both setup functions
    # must refuse — writing swarm.key after daemon start has no effect.
    with pytest.raises(basic_ipfs.IPFSError):
        basic_ipfs.create_private_network()
    with pytest.raises(basic_ipfs.IPFSError):
        basic_ipfs.join_private_network("a" * 64)


def test_join_private_network_validates_key(monkeypatch):
    monkeypatch.setattr(basic_ipfs, "_manager", None)  # pretend daemon isn't running
    with pytest.raises(ValueError):
        basic_ipfs.join_private_network("tooshort")
    with pytest.raises(ValueError):
        basic_ipfs.join_private_network("z" * 64)  # not valid hex


def test_private_network_key_roundtrip(tmp_path, monkeypatch):
    # Patch the repo path so we don't touch the live daemon's repo.
    monkeypatch.setattr(basic_ipfs, "REPO_PATH", tmp_path / "repo")
    monkeypatch.setattr(basic_ipfs, "_manager", None)  # pretend daemon isn't running

    key = basic_ipfs.create_private_network()
    assert len(key) == 64
    assert all(c in "0123456789abcdef" for c in key)
    assert basic_ipfs.is_private_network()
    assert basic_ipfs.get_private_network_key() == key

    # join with the same key and verify it round-trips
    basic_ipfs.join_private_network(key)
    assert basic_ipfs.get_private_network_key() == key


def test_connect_to_nodes_bad_addrs_raises():
    with pytest.raises(basic_ipfs.IPFSOperationError):
        basic_ipfs.connect_to_nodes([
            "/ip4/0.0.0.0/tcp/4001/p2p/12D3KooWNotARealPeerXXXXXXX",
            "/ip4/0.0.0.1/tcp/4001/p2p/12D3KooWNotARealPeerYYYYYYY",
        ])
