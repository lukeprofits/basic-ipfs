"""Adding a file in place: it stays where it is and is served from there.

Checked without a daemon by capturing what the call sends to Kubo's RPC, and
-- with ``IPFS_E2E=1`` -- for real, against a daemon on this machine.

Run the real one with:  IPFS_E2E=1 python -m pytest tests/test_in_place.py -v
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import basic_ipfs


class _Reply:
    text = '{"Hash": "bafyexample"}'


def _capturing(m: basic_ipfs.IPFSManager) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def post(endpoint: str, **kw: Any) -> _Reply:
        kw["body"] = b"".join(kw.pop("data"))
        calls.append({"endpoint": endpoint, **kw})
        return _Reply()

    m._post = post  # type: ignore[method-assign,assignment]
    return calls


def test_in_place_tells_kubo_where_the_file_is(tmp_path: Path) -> None:
    file = tmp_path / "a bé.bin"
    file.write_bytes(b"hello")
    m = basic_ipfs.IPFSManager()
    calls = _capturing(m)
    assert m.add(file, in_place=True) == "bafyexample"
    params = calls[0]["params"]
    assert ("nocopy", "true") in params
    assert ("raw-leaves", "true") in params
    encoded = str(tmp_path).encode() + b"/a%20b%C3%A9.bin"
    assert b"abspath-encoded: " + encoded + b"\r\n" in calls[0]["body"]


def test_an_ordinary_add_says_nothing_of_where_the_file_is(tmp_path: Path) -> None:
    file = tmp_path / "a.bin"
    file.write_bytes(b"hello")
    m = basic_ipfs.IPFSManager()
    calls = _capturing(m)
    m.add(file)
    assert ("nocopy", "true") not in calls[0]["params"]
    assert b"abspath" not in calls[0]["body"]


def test_a_link_is_given_to_kubo_as_the_link(tmp_path: Path) -> None:
    (tmp_path / "drive").mkdir()
    (tmp_path / "drive" / "a.bin").write_bytes(b"hello")
    os.symlink(tmp_path / "drive", tmp_path / "link")
    m = basic_ipfs.IPFSManager()
    calls = _capturing(m)
    m.add(tmp_path / "link" / "a.bin", in_place=True)
    assert b"/link/a.bin\r\n" in calls[0]["body"]


def test_in_place_needs_a_path_and_raw_leaves(tmp_path: Path) -> None:
    file = tmp_path / "a.bin"
    file.write_bytes(b"hello")
    m = basic_ipfs.IPFSManager()
    _capturing(m)
    with pytest.raises(TypeError, match="file path"):
        m.add(b"hello", in_place=True)
    with pytest.raises(ValueError, match="raw leaves"):
        m.add(file, in_place=True, raw_leaves=False)


def test_a_refusal_says_what_to_do(tmp_path: Path) -> None:
    file = tmp_path / "a.bin"
    file.write_bytes(b"hello")
    m = basic_ipfs.IPFSManager()

    def refuse(endpoint: str, **kwargs: Any) -> Any:
        raise basic_ipfs.IPFSOperationError(
            "IPFS API error [500] add: cannot add filestore references "
            "outside ipfs root (/somewhere)"
        )

    m._post = refuse  # type: ignore[method-assign]
    with pytest.raises(basic_ipfs.IPFSError, match="in_place=True"):
        m.add(file, in_place=True)


def test_in_place_is_switched_on_only_when_asked() -> None:
    seen: list[tuple[str, ...]] = []
    plain = basic_ipfs.IPFSManager()
    plain._run_cli = lambda *args, **kw: seen.append(args)  # type: ignore[method-assign,assignment]
    plain._configure_in_place()
    assert seen == []
    m = basic_ipfs.IPFSManager(in_place=True)
    m._run_cli = lambda *args, **kw: seen.append(args)  # type: ignore[method-assign,assignment]
    m._configure_in_place()
    assert seen == [("config", "--json", "Experimental.FilestoreEnabled", "true")]


@pytest.mark.skipif(not os.environ.get("IPFS_E2E"), reason="set IPFS_E2E=1")
def test_a_file_on_another_drive_is_served_from_where_it_is(tmp_path: Path) -> None:
    home = tmp_path / "home"
    drive = tmp_path / "drive"
    home.mkdir()
    drive.mkdir()
    m = basic_ipfs.IPFSManager(
        port=5627,
        repo=home / "ipfs",
        gateway_port=8627,
        swarm_port=4627,
        in_place=True,
    )
    data = os.urandom(3_000_000)
    (drive / "blob").write_bytes(data)
    try:
        m.start()
        # outside the folder that holds the repository: refused
        with pytest.raises(basic_ipfs.IPFSError, match="in_place=True"):
            m.add(drive / "blob", in_place=True, provide=False)
        # through a link beside the repository: taken, and nothing copied
        os.symlink(drive, home / "drive")
        cid = m.add(home / "drive" / "blob", in_place=True, provide=False)
        assert m.cat(cid) == data
        copied = sum(f.stat().st_size for f in (home / "ipfs" / "blocks").rglob("*") if f.is_file())
        assert copied < 100_000
        # the drive leaves: the read fails and the daemon lives
        os.rename(drive / "blob", drive / "away")
        with pytest.raises(basic_ipfs.IPFSError):
            m.cat(cid, timeout=5)
        os.rename(drive / "away", drive / "blob")
        assert m.cat(cid) == data
        # letting go of it never deletes the file: that is the caller's to do
        m.pin_rm(cid)
        m.repo_gc()
        assert (drive / "blob").read_bytes() == data
    finally:
        m.stop()
